/**
 * Post-compaction context refresh.
 *
 * After session compaction, the LLM loses the full conversation history.
 * This module extracts critical sections from AGENTS.md (e.g. "Session Startup",
 * "Red Lines") and formats them for re-injection into the conversation context.
 *
 * Ported from openclaw's post-compaction-context.ts.
 */

import fs from "fs/promises"
import path from "path"
import { Instance } from "@/project/instance"
import { Log } from "@/util/log"

const log = Log.create({ service: "memory.post-compaction" })

const MAX_CONTEXT_CHARS = 3000
const DEFAULT_SECTIONS = ["Session Startup", "Red Lines"]

/**
 * Extract named sections from markdown content.
 * Matches H2 (##) or H3 (###) headings case-insensitively.
 * Skips content inside fenced code blocks.
 */
function extractSections(content: string, names: string[]): string[] {
  const results: string[] = []
  const lines = content.split("\n")

  for (const name of names) {
    const buf: string[] = []
    let active = false
    let level = 0
    let fence = false

    for (const line of lines) {
      if (line.trimStart().startsWith("```")) {
        fence = !fence
        if (active) buf.push(line)
        continue
      }

      if (fence) {
        if (active) buf.push(line)
        continue
      }

      const heading = line.match(/^(#{2,3})\s+(.+?)\s*$/)
      if (heading) {
        const lvl = heading[1].length
        const text = heading[2]

        if (!active) {
          if (text.toLowerCase() === name.toLowerCase()) {
            active = true
            level = lvl
            buf.push(line)
          }
        } else {
          if (lvl <= level) break
          buf.push(line)
        }
        continue
      }

      if (active) buf.push(line)
    }

    if (buf.length > 0) results.push(buf.join("\n").trim())
  }

  return results
}

export namespace PostCompaction {
  /**
   * Read critical sections from workspace AGENTS.md for post-compaction injection.
   * Returns formatted context string, or empty string if nothing to inject.
   */
  export async function context(): Promise<string> {
    const dir = Instance.worktree
    const candidates = ["AGENTS.md", "CLAUDE.md"]

    let content = ""
    for (const file of candidates) {
      const filepath = path.join(dir, file)
      try {
        content = await fs.readFile(filepath, "utf-8")
        break
      } catch {
        continue
      }
    }

    if (!content) return ""

    const sections = extractSections(content, DEFAULT_SECTIONS)
    if (sections.length === 0) return ""

    const combined = sections.join("\n\n")
    const safe =
      combined.length > MAX_CONTEXT_CHARS ? combined.slice(0, MAX_CONTEXT_CHARS) + "\n...[truncated]..." : combined

    return [
      "[Post-compaction context refresh]",
      "",
      "Session was just compacted. The conversation summary above is a hint, NOT a substitute for your full context.",
      "Review the critical rules below and check the <permanent-memory> and <recent-memory> content in your system prompt before responding.",
      "",
      "Critical rules from AGENTS.md:",
      "",
      safe,
    ].join("\n")
  }
}
