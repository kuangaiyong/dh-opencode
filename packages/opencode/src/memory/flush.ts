import crypto from "node:crypto"
import { Bus } from "@/bus"
import { Session } from "@/session"
import { SessionCompaction } from "@/session/compaction"
import { MessageV2 } from "@/session/message-v2"
import { Log } from "@/util/log"
import { Memory } from "."
import { Provider } from "@/provider/provider"
import { LLM } from "@/session/llm"
import { Agent } from "@/agent/agent"

const log = Log.create({ service: "memory.flush" })
const LIMIT = 30

// ── Flush deduplication ──
// SHA-256 hash of last 3 user/assistant messages + message count.
// If the hash matches the previous flush, skip to avoid duplicate entries.
let lastHash: string | null = null

// Sessions that already ran pre-compaction flush — skip post-compaction event
const preflushed = new Set<string>()

function contextHash(msgs: MessageV2.WithParts[]): string {
  const tail = msgs
    .filter((m) => m.info.role === "user" || m.info.role === "assistant")
    .slice(-3)
  const payload = `${msgs.length}:${tail.map((m, i) => {
    const text = m.parts
      .filter((p): p is MessageV2.TextPart => p.type === "text")
      .map((p) => p.text)
      .join("")
    return `[${i}:${m.info.role}]${text}`
  }).join("\x00")}`
  return crypto.createHash("sha256").update(payload).digest("hex").slice(0, 16)
}

const FLUSH_PROMPT = [
  "You are a memory-extraction assistant. Analyze the conversation below and extract durable memories worth preserving for future sessions.",
  "",
  "Focus ONLY on lasting, reusable knowledge:",
  "- Key decisions made and their rationale",
  "- User preferences and conventions discovered",
  "- Important technical findings or architecture decisions",
  "- Task progress and what remains to be done",
  "- File paths and code patterns important for future work",
  "",
  "IGNORE and skip:",
  "- Routine greetings, small talk, or casual exchanges",
  "- Debugging trial-and-error that led nowhere",
  "- Raw command output, error logs, stack traces, or status dumps",
  "- Repetitive back-and-forth that adds no lasting value",
  "- Information already obvious from the codebase itself",
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
    // include compaction summaries — they contain condensed knowledge
    if (msg.info.role === "assistant" && msg.info.summary) {
      for (const part of msg.parts) {
        if (part.type !== "text") continue
        const text = part.text.trim()
        if (!text) continue
        lines.push(`[summary]: ${text}`)
      }
      continue
    }
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
      id: "flush" as any,
      sessionID: session.id,
      role: "user",
      time: { created: Date.now() },
      agent: "compaction",
      model: { providerID: model.providerID, modelID: model.id },
    }

    const content = lines.join("\n")
    const ctrl = new AbortController()
    // 10 second timeout for flush summarization
    const timer = setTimeout(() => ctrl.abort(), 10_000)

    try {
      const result = await LLM.stream({
        agent,
        user,
        system: [FLUSH_PROMPT],
        small: true,
        tools: {},
        model,
        abort: ctrl.signal,
        sessionID: session.id,
        retries: 1,
        messages: [
          {
            role: "user",
            content: `Here is the conversation to extract memories from:\n\n${content}`,
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

export namespace MemoryFlush {
  /** Reset dedup state (e.g. on new session). */
  export function reset() {
    lastHash = null
    preflushed.clear()
  }

  /** Run flush for a given session. Can be called directly (pre-compaction) or via event. */
  export async function run(sid: string) {
    const msgs = await Session.messages({ sessionID: sid as any })
    if (!msgs || msgs.length === 0) return

    // ── dedup check ──
    const hash = contextHash(msgs)
    if (hash === lastHash) {
      log.info("flush skipped — context unchanged (dedup)", { session: sid })
      return
    }

    const lines = extract(msgs)
    if (lines.length === 0) return

    const session = await Session.get(sid as any)
    const date = new Date().toISOString().slice(0, 10)
    const time = new Date().toISOString().slice(11, 19)

    // try LLM-driven summarization first, fall back to raw extraction
    const summary = await summarize(lines, session)
    const body = summary ?? lines.join("\n")

    const content = [
      `## Compaction: ${time} UTC`,
      "",
      `- **Title**: ${session.title}`,
      `- **Session ID**: ${sid}`,
      "",
      summary ? "### Extracted Memories" : "### Key Context",
      "",
      body,
      "",
    ].join("\n")

    // append to daily file (memory/YYYY-MM-DD.md) instead of creating per-event files
    await Memory.appendDaily(content, date)
    lastHash = hash
    log.info("flushed session context to daily memory", {
      session: sid,
      date,
      llm: !!summary,
    })
  }

  /**
   * Pre-compaction flush: save memory while full context is still available.
   * Marks the session so the post-compaction event handler skips the redundant flush.
   */
  export async function preflush(sid: string) {
    try {
      await run(sid)
      preflushed.add(sid)
      log.info("pre-compaction flush completed", { session: sid })
    } catch (err) {
      log.warn("pre-compaction flush failed", { error: String(err) })
    }
  }

  export function init() {
    Bus.subscribe(SessionCompaction.Event.Compacted, async (evt) => {
      try {
        const sid = evt.properties.sessionID
        // skip if pre-compaction flush already ran for this session
        if (preflushed.has(sid)) {
          preflushed.delete(sid)
          log.info("post-compaction flush skipped — pre-flush already ran", { session: sid })
          return
        }
        // fallback: run post-compaction flush (e.g. manual compaction without pre-flush)
        await run(sid)
      } catch (err) {
        log.warn("failed to flush memory on compaction", { error: String(err) })
      }
    })
  }
}
