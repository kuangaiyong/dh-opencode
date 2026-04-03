import { createHash } from "crypto"

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const CHARS_PER_TOKEN = 4
const DEFAULT_TOKENS = 400
const DEFAULT_OVERLAP = 80

// ---------------------------------------------------------------------------
// CJK-aware character estimation
// ---------------------------------------------------------------------------

function isCJK(code: number): boolean {
  return (
    (code >= 0x4e00 && code <= 0x9fff) ||
    (code >= 0x3400 && code <= 0x4dbf) ||
    (code >= 0x20000 && code <= 0x2a6df) ||
    (code >= 0x2a700 && code <= 0x2b73f) ||
    (code >= 0xf900 && code <= 0xfaff) ||
    (code >= 0x3000 && code <= 0x303f) ||
    (code >= 0xff00 && code <= 0xffef) ||
    (code >= 0xac00 && code <= 0xd7af) ||
    (code >= 0x3040 && code <= 0x309f) ||
    (code >= 0x30a0 && code <= 0x30ff)
  )
}

function estimate(str: string): number {
  let n = 0
  for (let i = 0; i < str.length; i++) {
    const code = str.codePointAt(i)!
    if (code > 0xffff) {
      n += CHARS_PER_TOKEN
      i++ // skip surrogate pair
    } else if (isCJK(code)) {
      n += CHARS_PER_TOKEN
    } else {
      n += 1
    }
  }
  return n
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface Chunk {
  start_line: number
  end_line: number
  text: string
  hash: string
}

export interface ChunkOptions {
  tokens?: number
  overlap?: number
}

// ---------------------------------------------------------------------------
// Hash helper
// ---------------------------------------------------------------------------

function hash(text: string): string {
  return createHash("sha256").update(text).digest("hex").slice(0, 16)
}

// ---------------------------------------------------------------------------
// chunkMarkdown — line-budget sliding window with CJK awareness
// ---------------------------------------------------------------------------

export function chunkMarkdown(content: string, opts?: ChunkOptions): Chunk[] {
  const tokens = opts?.tokens ?? DEFAULT_TOKENS
  const overlap = opts?.overlap ?? DEFAULT_OVERLAP
  const max = Math.max(32, tokens * CHARS_PER_TOKEN)
  const lap = Math.max(0, overlap * CHARS_PER_TOKEN)

  const lines = content.split("\n")
  if (lines.length === 0) return []

  const chunks: Chunk[] = []
  let buf: { line: string; no: number }[] = []
  let size = 0

  function flush() {
    if (buf.length === 0) return
    const text = buf.map((e) => e.line).join("\n")
    chunks.push({
      start_line: buf[0]!.no,
      end_line: buf[buf.length - 1]!.no,
      text,
      hash: hash(text),
    })
  }

  function carry() {
    if (lap <= 0 || buf.length === 0) {
      buf = []
      size = 0
      return
    }
    let acc = 0
    const kept: typeof buf = []
    for (let i = buf.length - 1; i >= 0; i--) {
      const entry = buf[i]!
      acc += estimate(entry.line) + 1
      kept.unshift(entry)
      if (acc >= lap) break
    }
    buf = kept
    size = kept.reduce((s, e) => s + estimate(e.line) + 1, 0)
  }

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? ""
    const no = i + 1

    // split ultra-long lines into segments that fit the budget
    const segments: string[] = []
    if (line.length === 0) {
      segments.push("")
    } else {
      for (let start = 0; start < line.length; start += max) {
        const coarse = line.slice(start, start + max)
        if (estimate(coarse) > max) {
          const step = Math.max(1, tokens)
          for (let j = 0; j < coarse.length; ) {
            let end = Math.min(j + step, coarse.length)
            // avoid splitting surrogate pairs
            if (end < coarse.length) {
              const code = coarse.charCodeAt(end - 1)
              if (code >= 0xd800 && code <= 0xdbff) end += 1
            }
            segments.push(coarse.slice(j, end))
            j = end
          }
        } else {
          segments.push(coarse)
        }
      }
    }

    for (const seg of segments) {
      const w = estimate(seg) + 1
      if (size + w > max && buf.length > 0) {
        flush()
        carry()
      }
      buf.push({ line: seg, no })
      size += w
    }
  }

  flush()
  return chunks
}
