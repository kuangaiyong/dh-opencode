import fs from "fs/promises"
import path from "path"
import { Log } from "@/util/log"
import { Memory } from "."
import { Provider } from "@/provider/provider"
import { LLM } from "@/session/llm"
import { Agent } from "@/agent/agent"
import { MessageV2 } from "@/session/message-v2"

const log = Log.create({ service: "memory.consolidate" })

// Track last consolidation date so we run at most once per day
let lastDate: string | null = null

const CONSOLIDATE_PROMPT = [
  "You are a memory consolidation assistant. Your job is to merge new information from daily session logs into the permanent MEMORY.md file.",
  "",
  "Rules:",
  "1. Preserve ALL existing content in MEMORY.md — never remove or overwrite existing information",
  "2. Add new facts, preferences, decisions, and context from the daily logs that are NOT already in MEMORY.md",
  "3. Organize information into clear categories (e.g. ## User Info, ## Preferences, ## Project Context, ## Key Decisions)",
  "4. Deduplicate — if the same fact appears in both MEMORY.md and daily logs, keep the MEMORY.md version",
  "5. Be concise — use bullet points, avoid verbose descriptions",
  "6. Keep the # Memory header at the top",
  "7. If the daily logs contain nothing new worth adding, output the existing MEMORY.md content unchanged",
  "",
  "IMPORTANT: Output ONLY the complete updated MEMORY.md content. No preamble, explanation, or code fences.",
].join("\n")

// Maximum chars of daily content to send to LLM
const MAX_DAILY = 8000
const MAX_PERMANENT = 6000
const DAILY_DAYS = 7

async function recent(dir: string): Promise<string> {
  try {
    const files = await fs.readdir(dir)
    const daily = files
      .filter((f) => /^\d{4}-\d{2}-\d{2}\.md$/.test(f))
      .sort()
      .reverse()
      .slice(0, DAILY_DAYS)
    if (daily.length === 0) return ""
    const parts: string[] = []
    let total = 0
    for (const file of daily) {
      const content = await fs.readFile(path.join(dir, file), "utf-8")
      if (total + content.length > MAX_DAILY) {
        const remaining = MAX_DAILY - total
        if (remaining > 100) parts.push(content.slice(0, remaining) + "\n...[truncated]...")
        break
      }
      parts.push(content)
      total += content.length
    }
    return parts.join("\n\n---\n\n")
  } catch {
    return ""
  }
}

async function merge(permanent: string, daily: string): Promise<string | null> {
  try {
    const defaults = await Provider.defaultModel().catch(() => null)
    if (!defaults) return null

    const model = await Provider.getSmallModel(defaults.providerID)
    if (!model) return null

    const agent = await Agent.get("compaction")
    if (!agent) return null

    const user: MessageV2.User = {
      id: "consolidate" as any,
      sessionID: "consolidate" as any,
      role: "user",
      time: { created: Date.now() },
      agent: "compaction",
      model: { providerID: model.providerID, modelID: model.id },
    }

    const ctrl = new AbortController()
    const timer = setTimeout(() => ctrl.abort(), 15_000)

    try {
      const result = await LLM.stream({
        agent,
        user,
        system: [CONSOLIDATE_PROMPT],
        small: true,
        tools: {},
        model,
        abort: ctrl.signal,
        sessionID: "consolidate" as any,
        retries: 1,
        messages: [
          {
            role: "user",
            content: [
              "Here is the current MEMORY.md content:",
              "```",
              permanent || "(empty)",
              "```",
              "",
              "Here are the recent daily session logs to merge:",
              "```",
              daily,
              "```",
              "",
              "Output the updated MEMORY.md content with any new information merged in.",
            ].join("\n"),
          },
        ],
      })
      const text = (await result.text)
        .replace(/<think>[\s\S]*?<\/think>\s*/g, "")
        .trim()
      if (!text || text.length < 10) return null
      return text
    } finally {
      clearTimeout(timer)
    }
  } catch (err) {
    log.warn("LLM consolidation failed", { error: String(err) })
    return null
  }
}

export namespace Consolidate {
  /**
   * Run daily memory consolidation: merge recent daily files into MEMORY.md.
   * Safe to call multiple times — runs at most once per calendar day.
   * Called during bootstrap after Memory.init().
   */
  export async function run() {
    const filepath = Memory.permanentPath()
    if (!filepath) return

    const today = new Date().toISOString().slice(0, 10)
    if (lastDate === today) {
      log.info("consolidation already ran today, skipping")
      return
    }

    const dir = path.dirname(filepath)
    const memdir = path.join(dir, "memory")

    // read current MEMORY.md
    let permanent = ""
    try {
      permanent = await fs.readFile(filepath, "utf-8")
    } catch {}

    // read recent daily files
    const daily = await recent(memdir)
    if (!daily) {
      log.info("no daily memory files to consolidate")
      lastDate = today
      return
    }

    // truncate permanent for LLM context
    const trimmed = permanent.length > MAX_PERMANENT
      ? permanent.slice(0, MAX_PERMANENT) + "\n...[truncated]..."
      : permanent

    // run LLM merge
    const merged = await merge(trimmed, daily)
    if (!merged) {
      log.info("consolidation produced no changes")
      lastDate = today
      return
    }

    // sanity check: merged should be at least as long as original non-template content
    const template = "# Memory\n\nThis file stores cross-session memory for the AI assistant."
    const orig = permanent.trim() === template ? "" : permanent
    if (merged.length < orig.length * 0.5 && orig.length > 100) {
      log.warn("consolidation result suspiciously shorter than original, skipping write", {
        original: orig.length,
        merged: merged.length,
      })
      lastDate = today
      return
    }

    // write back
    await fs.writeFile(filepath, merged, "utf-8")
    lastDate = today
    log.info("consolidated daily memory into MEMORY.md", {
      date: today,
      before: permanent.length,
      after: merged.length,
    })
  }
}
