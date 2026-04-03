import { Bus } from "@/bus"
import { Session } from "@/session"
import { MessageV2 } from "@/session/message-v2"
import { Log } from "@/util/log"
import { Memory } from "."
import { Provider } from "@/provider/provider"
import { LLM } from "@/session/llm"
import { Agent } from "@/agent/agent"

const log = Log.create({ service: "memory.session-save" })
const LIMIT = 20

const SAVE_PROMPT = [
  "You are a memory-extraction assistant. Analyze the conversation below from a completed session and extract information worth preserving for future sessions.",
  "",
  "Focus ONLY on durable, reusable knowledge:",
  "- User identity, preferences, or conventions discovered",
  "- Key decisions made and their rationale",
  "- Important technical findings, architecture choices, or patterns",
  "- Task outcomes and what remains to be done",
  "- File paths, code patterns, or project structure insights",
  "",
  "IGNORE and skip:",
  "- Routine greetings and small talk",
  "- Debugging trial-and-error that led nowhere",
  "- Raw command output, error logs, or status messages",
  "- Repetitive back-and-forth that adds no lasting value",
  "",
  "Format: concise markdown bullet points grouped by category.",
  "If nothing is worth remembering, output ONLY: [nothing to save]",
  "",
  "IMPORTANT: Output ONLY the memory content. No preamble, explanation, or code fences.",
].join("\n")

function extract(msgs: MessageV2.WithParts[]): string[] {
  const lines: string[] = []
  for (const msg of msgs) {
    if (msg.info.role !== "user" && msg.info.role !== "assistant") continue
    for (const part of msg.parts) {
      if (part.type !== "text") continue
      if (part.synthetic) continue
      const text = part.text.trim()
      if (!text) continue
      if (text.startsWith("/")) continue
      lines.push(`${msg.info.role}: ${text}`)
    }
  }
  return lines.slice(-LIMIT)
}

async function summarize(lines: string[], session: Session.Info): Promise<string | null> {
  try {
    const defaults = await Provider.defaultModel().catch(() => null)
    if (!defaults) return null

    const model = await Provider.getSmallModel(defaults.providerID)
    if (!model) return null

    const agent = await Agent.get("compaction")
    if (!agent) return null

    const user: MessageV2.User = {
      id: "session-save" as any,
      sessionID: session.id,
      role: "user",
      time: { created: Date.now() },
      agent: "compaction",
      model: { providerID: model.providerID, modelID: model.id },
    }

    const content = lines.join("\n")
    const ctrl = new AbortController()
    const timer = setTimeout(() => ctrl.abort(), 10_000)

    try {
      const result = await LLM.stream({
        agent,
        user,
        system: [SAVE_PROMPT],
        small: true,
        tools: {},
        model,
        abort: ctrl.signal,
        sessionID: session.id,
        retries: 1,
        messages: [
          {
            role: "user",
            content: `Here is the conversation from the completed session to extract memories from:\n\n${content}`,
          },
        ],
      })
      const text = (await result.text)
        .replace(/<think>[\s\S]*?<\/think>\s*/g, "")
        .trim()
      if (!text || text.includes("[nothing to save]")) return null
      return text
    } finally {
      clearTimeout(timer)
    }
  } catch (err) {
    log.warn("LLM summarization failed, falling back to raw extraction", { error: String(err) })
    return null
  }
}

export namespace SessionSave {
  export function init() {
    Bus.subscribe(Session.Event.Created, async (evt) => {
      try {
        const info = evt.properties.info
        // skip sub-sessions (tasks)
        if (info.parentID) return

        // find the previous session
        const sessions = [...Session.list({ roots: true, limit: 2 })]
        const prev = sessions.find((s) => s.id !== info.id)
        if (!prev) return

        // get messages from previous session
        const msgs = await Session.messages({ sessionID: prev.id })
        if (!msgs || msgs.length === 0) return

        const lines = extract(msgs)
        if (lines.length === 0) return

        const date = new Date(prev.time.created).toISOString().slice(0, 10)
        const time = new Date(prev.time.created).toISOString().slice(11, 19)

        // try LLM-driven summarization first, fall back to raw extraction
        const summary = await summarize(lines, prev)
        const body = summary ?? lines.join("\n")

        const content = [
          `## Session: ${time} UTC`,
          "",
          `- **Title**: ${prev.title}`,
          `- **Session ID**: ${prev.id}`,
          "",
          summary ? "### Extracted Memories" : "### Conversation Summary",
          "",
          body,
          "",
        ].join("\n")

        // append to daily file (memory/YYYY-MM-DD.md)
        await Memory.appendDaily(content, date)
        log.info("saved previous session to daily memory", { session: prev.id, date, llm: !!summary })
      } catch (err) {
        log.warn("failed to save session to memory", { error: String(err) })
      }
    })
  }
}
