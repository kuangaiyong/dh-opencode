import { MemoryDatabase } from "./memory-db"
import { type EmbeddingProvider } from "./embedding"
import { extractKeywords } from "./query-expansion"
import { Log } from "../util/log"

const log = Log.create({ service: "memory-search" })

// ---------------------------------------------------------------------------
// Result type shared across all search methods
// ---------------------------------------------------------------------------

export interface SearchResult {
  id: string
  path: string
  text: string
  start_line: number
  end_line: number
  score: number
  source: "vector" | "keyword"
  category?: string
}

// ---------------------------------------------------------------------------
// Vector search — cosine similarity via sqlite-vec (chunks_vec)
// Falls back to in-process cosine when extension is unavailable.
// ---------------------------------------------------------------------------

export async function searchVector(
  query: string,
  provider: EmbeddingProvider,
  limit: number,
): Promise<SearchResult[]> {
  const vecs = await provider.embed([query])
  const qvec = vecs[0]
  if (!qvec) return []

  const hasVec = MemoryDatabase.hasVecExtension()

  if (hasVec) {
    return vecSearch(qvec, limit)
  }
  return fallbackCosine(qvec, limit)
}

function vecSearch(qvec: number[], limit: number): SearchResult[] {
  const json = JSON.stringify(qvec)
  try {
    const rows = MemoryDatabase.query<{
      id: string
      distance: number
    }>(`SELECT id, distance FROM chunks_vec WHERE embedding MATCH '${json}' ORDER BY distance LIMIT ${limit}`)

    return rows
      .map((row) => {
        const chunk = chunkById(row.id)
        if (!chunk) return null
        // sqlite-vec returns L2 distance; convert to similarity 0..1
        const score = 1 / (1 + row.distance)
        return { ...chunk, score, source: "vector" as const }
      })
      .filter(Boolean) as SearchResult[]
  } catch (err) {
    log.warn("vec search failed, falling back to in-process cosine", { error: String(err) })
    return fallbackCosine(qvec, limit)
  }
}

function fallbackCosine(qvec: number[], limit: number): SearchResult[] {
  // load all embeddings from chunks table
  const rows = MemoryDatabase.query<{
    id: string
    path: string
    text: string
    start_line: number
    end_line: number
    embedding: string
    category: string
  }>(`SELECT id, path, text, start_line, end_line, embedding, category FROM chunks WHERE embedding != '[]'`)

  const scored: SearchResult[] = []

  for (const row of rows) {
    let vec: number[]
    try {
      vec = JSON.parse(row.embedding)
    } catch {
      continue
    }
    if (vec.length !== qvec.length) continue

    const score = cosine(qvec, vec)
    scored.push({
      id: row.id,
      path: row.path,
      text: row.text,
      start_line: row.start_line,
      end_line: row.end_line,
      score,
      source: "vector",
      category: row.category,
    })
  }

  scored.sort((a, b) => b.score - a.score)
  return scored.slice(0, limit)
}

function cosine(a: number[], b: number[]): number {
  let dot = 0
  let na = 0
  let nb = 0
  for (let i = 0; i < a.length; i++) {
    dot += a[i]! * b[i]!
    na += a[i]! * a[i]!
    nb += b[i]! * b[i]!
  }
  const denom = Math.sqrt(na) * Math.sqrt(nb)
  return denom < 1e-10 ? 0 : dot / denom
}

// ---------------------------------------------------------------------------
// Keyword search — FTS5 with BM25 scoring
// ---------------------------------------------------------------------------

export function searchKeyword(query: string, limit: number): SearchResult[] {
  // Use multi-language keyword extraction (stop word filtering + CJK tokenization)
  const keywords = extractKeywords(query)

  // Fall back to naive split when extraction yields nothing (e.g. pure stop-word query)
  const raw =
    keywords.length > 0
      ? keywords
      : query
          .replace(/['"*(){}[\]^~\\:]/g, " ")
          .split(/\s+/)
          .filter(Boolean)

  const terms = raw.map((t) => `"${t}"`).join(" OR ")

  if (!terms) return []

  try {
    const rows = MemoryDatabase.query<{
      id: string
      path: string
      text: string
      start_line: number
      end_line: number
      rank: number
      category: string
    }>(
      `SELECT chunks_fts.id, chunks_fts.path, COALESCE(chunks.text, chunks_fts.text) as text, chunks_fts.start_line, chunks_fts.end_line, rank, COALESCE(chunks.category, 'other') as category FROM chunks_fts LEFT JOIN chunks ON chunks_fts.id = chunks.id WHERE chunks_fts MATCH '${terms.replace(/'/g, "''")}' ORDER BY rank LIMIT ${limit}`,
    )

    // FTS5 rank is negative BM25 — lower (more negative) is better
    // normalise to 0..1 range
    if (rows.length === 0) return []
    const worst = rows[rows.length - 1]!.rank
    const best = rows[0]!.rank
    const range = worst - best || 1

    return rows.map((row) => ({
      id: row.id,
      path: row.path,
      text: row.text,
      start_line: row.start_line,
      end_line: row.end_line,
      score: 1 - (row.rank - best) / range,
      source: "keyword" as const,
      category: row.category,
    }))
  } catch (err) {
    log.warn("FTS search failed", { error: String(err) })
    return []
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function chunkById(id: string) {
  const rows = MemoryDatabase.query<{
    id: string
    path: string
    text: string
    start_line: number
    end_line: number
    category: string
  }>(`SELECT id, path, text, start_line, end_line, category FROM chunks WHERE id = '${id.replace(/'/g, "''")}'`)
  return rows[0] ?? null
}
