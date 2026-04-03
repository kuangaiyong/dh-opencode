/**
 * Automatic memory capture from user messages.
 *
 * Subscribes to user message events and detects patterns that indicate
 * the user is expressing something worth remembering (preferences, facts,
 * decisions, etc.). When a trigger fires, the message content is
 * automatically saved as a memory file.
 *
 * Safety:
 * - Only captures from user messages (never assistant output — avoids self-poisoning)
 * - Rejects content that looks like prompt injection
 * - Max 3 captures per session to avoid noise
 *
 * Ported from openclaw's memory-lancedb auto-capture triggers.
 */

import { Bus } from "@/bus"
import { MessageV2 } from "@/session/message-v2"
import { Session } from "@/session"
import { Log } from "@/util/log"
import { Memory } from "."
import { looksLikeInjection } from "./sanitize"
import { classify } from "./classify"

const log = Log.create({ service: "memory.capture" })

// ---------------------------------------------------------------------------
// Trigger patterns — multi-language (EN/ES/PT/DE/FR/ZH/JA/KO)
// ---------------------------------------------------------------------------

const TRIGGERS = [
  /\b(remember|don'?t forget|keep in mind|note that|take note)\b/i,
  /\b(my (name|preference|style|setup|config) is)\b/i,
  /\b(i (always|usually|never|prefer|like|hate|dislike|use|want))\b/i,
  /\b(from now on|going forward|in the future)\b/i,
  /\b(recuerda|no olvides|mi nombre es|prefiero)\b/i,
  /\b(lembre|não esqueça|meu nome é|eu prefiro)\b/i,
  /\b(merk dir|vergiss nicht|mein name ist|ich bevorzuge)\b/i,
  /\b(rappelle-toi|n'?oublie pas|mon nom est|je préfère)\b/i,
  /(记住|别忘了|我的名字是|我喜欢|我偏好|以后都|从现在开始)/,
  /(覚えて|忘れないで|名前は|好きな|嫌いな)/,
  /(기억해|잊지 마|내 이름은|나는 좋아|나는 싫어)/,
]

// ---------------------------------------------------------------------------
// Guards — skip system-generated content and structured output
// ---------------------------------------------------------------------------

function shouldSkip(text: string): boolean {
  // already wrapped memory context
  if (text.includes("<relevant-memories>")) return true
  // system-generated XML/HTML content
  if (text.startsWith("<") && text.includes("</")) return true
  // agent summary (markdown with bullet lists)
  if (text.includes("**") && text.includes("\n-")) return true
  // too short to be meaningful
  if (text.length < 10) return true
  // too long — likely a code dump, not a personal statement
  if (text.length > 2000) return true
  return false
}

/** Exported for testing — determines if a user message should be auto-captured */
export function shouldCapture(text: string): boolean {
  if (shouldSkip(text)) return false
  if (looksLikeInjection(text)) return false
  return TRIGGERS.some((r) => r.test(text))
}

// ---------------------------------------------------------------------------
// Per-session capture counter
// ---------------------------------------------------------------------------

const MAX_PER_SESSION = 3
const counts = new Map<string, number>()

// Clean up old sessions periodically
function prune() {
  if (counts.size > 100) {
    const keys = [...counts.keys()].slice(0, 50)
    for (const k of keys) counts.delete(k)
  }
}

// ---------------------------------------------------------------------------
// Init — subscribe to message events
// ---------------------------------------------------------------------------

export namespace AutoCapture {
  export function init() {
    Bus.subscribe(MessageV2.Event.Updated, async (evt) => {
      try {
        const info = evt.properties.info
        // only user messages
        if (info.role !== "user") return
        // skip sub-sessions
        const session = await Session.get(info.sessionID)
        if (session.parentID) return

        // rate limit per session
        const n = counts.get(info.sessionID) ?? 0
        if (n >= MAX_PER_SESSION) return

        // get text parts from the message
        const msgs = await Session.messages({ sessionID: info.sessionID })
        const msg = msgs?.find((m) => m.info.id === info.id)
        if (!msg) return

        const texts: string[] = []
        for (const part of msg.parts) {
          if (part.type !== "text") continue
          if (part.synthetic) continue
          const text = part.text.trim()
          if (text) texts.push(text)
        }

        for (const text of texts) {
          if (!shouldCapture(text)) continue

          const category = classify(text)
          const date = new Date().toISOString().slice(0, 10)
          const time = new Date().toISOString().slice(11, 19).replace(/:/g, "")
          const slug = `auto-${category}-${time}`

          const content = [
            `# Auto-captured: ${category}`,
            "",
            `- **Category**: ${category}`,
            `- **Session**: ${info.sessionID}`,
            `- **Date**: ${date}`,
            "",
            text,
            "",
          ].join("\n")

          await Memory.save(slug, content)
          counts.set(info.sessionID, (counts.get(info.sessionID) ?? 0) + 1)
          log.info("auto-captured memory", { category, session: info.sessionID })
          prune()
          break // one capture per message event
        }
      } catch (err) {
        log.warn("auto-capture failed", { error: String(err) })
      }
    })
  }
}
