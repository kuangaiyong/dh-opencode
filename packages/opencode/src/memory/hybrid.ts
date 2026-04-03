import type { SearchResult } from "./search"

// ---------------------------------------------------------------------------
// Hybrid merge — weighted combination of vector and keyword results
// ---------------------------------------------------------------------------

const VECTOR_WEIGHT = 0.7
const KEYWORD_WEIGHT = 0.3

export function mergeHybrid(vector: SearchResult[], keyword: SearchResult[]): SearchResult[] {
  const map = new Map<string, SearchResult & { vs: number; ks: number }>()

  for (const r of vector) {
    map.set(r.id, { ...r, vs: r.score, ks: 0 })
  }

  for (const r of keyword) {
    const existing = map.get(r.id)
    if (existing) {
      existing.ks = r.score
    } else {
      map.set(r.id, { ...r, vs: 0, ks: r.score })
    }
  }

  const merged = [...map.values()].map((r) => ({
    id: r.id,
    path: r.path,
    text: r.text,
    start_line: r.start_line,
    end_line: r.end_line,
    score: r.vs * VECTOR_WEIGHT + r.ks * KEYWORD_WEIGHT,
    source: (r.vs >= r.ks ? "vector" : "keyword") as SearchResult["source"],
  }))

  merged.sort((a, b) => b.score - a.score)
  return merged
}

// ---------------------------------------------------------------------------
// Temporal decay — exponential decay based on file modification time
// ---------------------------------------------------------------------------

const HALF_LIFE_DAYS = 30
const DECAY_LAMBDA = Math.LN2 / (HALF_LIFE_DAYS * 86400_000)

/**
 * Extract a date from the memory file path.
 * Expects filenames like `YYYY-MM-DD-slug.md` or `MEMORY.md`.
 */
function extractDate(filepath: string): number | null {
  const match = /(\d{4}-\d{2}-\d{2})/.exec(filepath)
  if (!match) return null
  const ts = new Date(match[1]!).getTime()
  return Number.isNaN(ts) ? null : ts
}

export function applyTemporalDecay(results: SearchResult[], now?: number): SearchResult[] {
  const t = now ?? Date.now()

  return results.map((r) => {
    const date = extractDate(r.path)
    if (!date) return r // no date in path — no decay
    const age = Math.max(0, t - date)
    const factor = Math.exp(-DECAY_LAMBDA * age)
    return { ...r, score: r.score * factor }
  })
}

// ---------------------------------------------------------------------------
// MMR (Maximal Marginal Relevance) reranking
// Uses Jaccard similarity on token sets as the diversity metric.
// ---------------------------------------------------------------------------

const MMR_LAMBDA = 0.7

function tokenize(text: string): Set<string> {
  return new Set(
    text
      .toLowerCase()
      .split(/\W+/)
      .filter((t) => t.length > 1),
  )
}

function jaccard(a: Set<string>, b: Set<string>): number {
  if (a.size === 0 && b.size === 0) return 0
  let inter = 0
  for (const t of a) {
    if (b.has(t)) inter++
  }
  const union = a.size + b.size - inter
  return union === 0 ? 0 : inter / union
}

export function applyMMR(results: SearchResult[], limit: number): SearchResult[] {
  if (results.length <= 1) return results.slice(0, limit)

  const tokens = results.map((r) => tokenize(r.text))
  const selected: number[] = []
  const remaining = new Set(results.map((_, i) => i))

  // always pick the highest-scored result first
  selected.push(0)
  remaining.delete(0)

  while (selected.length < limit && remaining.size > 0) {
    let best = -1
    let bestScore = -Infinity

    for (const idx of remaining) {
      const relevance = results[idx]!.score

      // max similarity to any already-selected result
      let maxSim = 0
      for (const sel of selected) {
        const sim = jaccard(tokens[idx]!, tokens[sel]!)
        if (sim > maxSim) maxSim = sim
      }

      const mmr = MMR_LAMBDA * relevance - (1 - MMR_LAMBDA) * maxSim
      if (mmr > bestScore) {
        bestScore = mmr
        best = idx
      }
    }

    if (best < 0) break
    selected.push(best)
    remaining.delete(best)
  }

  return selected.map((i) => results[i]!)
}

// ---------------------------------------------------------------------------
// Full search pipeline
// ---------------------------------------------------------------------------

export interface PipelineOptions {
  decay?: boolean
  mmr?: boolean
  limit?: number
  minScore?: number
}

export function pipeline(
  vector: SearchResult[],
  keyword: SearchResult[],
  opts?: PipelineOptions,
): SearchResult[] {
  const limit = opts?.limit ?? 10
  const minScore = opts?.minScore ?? 0

  // 1. hybrid merge
  let results = mergeHybrid(vector, keyword)

  // 2. temporal decay
  if (opts?.decay !== false) {
    results = applyTemporalDecay(results)
    results.sort((a, b) => b.score - a.score)
  }

  // 3. score filter
  if (minScore > 0) {
    results = results.filter((r) => r.score >= minScore)
  }

  // 4. MMR diversity reranking
  if (opts?.mmr !== false) {
    results = applyMMR(results, limit)
  } else {
    results = results.slice(0, limit)
  }

  return results
}
