import { createHash } from "crypto"
import { Log } from "../util/log"
import { MemoryDatabase, EmbeddingCacheTable } from "./memory-db"
import { eq, and, inArray, sql } from "drizzle-orm"

const log = Log.create({ service: "memory-embedding" })

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const BATCH_MAX_BYTES = 8000
const RETRY_MAX = 3
const RETRY_BASE_MS = 500
const RETRY_CAP_MS = 8000
const TIMEOUT_REMOTE_MS = 60_000
const TIMEOUT_LOCAL_MS = 5 * 60_000
const CACHE_MAX = 50_000

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface EmbeddingProvider {
  id: string
  model: string
  dims: number
  embed(texts: string[]): Promise<number[][]>
}

interface ProviderSpec {
  id: string
  priority: number // lower = try first in auto mode
  model: string
  dims: number
  url: string
  keyEnv: string[]
  body(texts: string[], model: string): unknown
  parse(json: any): number[][]
}

// ---------------------------------------------------------------------------
// Vector normalisation
// ---------------------------------------------------------------------------

function normalize(vec: number[]): number[] {
  const mag = Math.sqrt(vec.reduce((s, v) => s + v * v, 0))
  if (mag < 1e-10) return vec
  return vec.map((v) => v / mag)
}

// ---------------------------------------------------------------------------
// Provider specifications
// ---------------------------------------------------------------------------

const SPECS: ProviderSpec[] = [
  {
    id: "openai",
    priority: 20,
    model: "text-embedding-3-small",
    dims: 1536,
    url: "https://api.openai.com/v1/embeddings",
    keyEnv: ["OPENAI_API_KEY"],
    body: (texts, model) => ({ input: texts, model }),
    parse: (json) => json.data.map((d: any) => d.embedding as number[]),
  },
  {
    id: "gemini",
    priority: 30,
    model: "text-embedding-004",
    dims: 768,
    url: "https://generativelanguage.googleapis.com/v1beta/models/{model}:batchEmbedContents",
    keyEnv: ["GOOGLE_API_KEY", "GEMINI_API_KEY"],
    body: (texts, model) => ({
      requests: texts.map((text) => ({
        model: `models/${model}`,
        content: { parts: [{ text }] },
      })),
    }),
    parse: (json) => json.embeddings.map((e: any) => normalize(e.values as number[])),
  },
  {
    id: "voyage",
    priority: 40,
    model: "voyage-3-lite",
    dims: 512,
    url: "https://api.voyageai.com/v1/embeddings",
    keyEnv: ["VOYAGE_API_KEY"],
    body: (texts, model) => ({ input: texts, model, input_type: "document" }),
    parse: (json) => json.data.map((d: any) => d.embedding as number[]),
  },
  {
    id: "mistral",
    priority: 50,
    model: "mistral-embed",
    dims: 1024,
    url: "https://api.mistral.ai/v1/embeddings",
    keyEnv: ["MISTRAL_API_KEY"],
    body: (texts, model) => ({ input: texts, model }),
    parse: (json) => json.data.map((d: any) => d.embedding as number[]),
  },
  {
    id: "ollama",
    priority: Infinity, // never auto-selected
    model: "nomic-embed-text",
    dims: 768,
    url: "http://127.0.0.1:11434/api/embed",
    keyEnv: [],
    body: (texts, model) => ({ model, input: texts }),
    parse: (json) => (json.embeddings as number[][]).map(normalize),
  },
]

// ---------------------------------------------------------------------------
// Key resolution — reuses opencode's provider system
// ---------------------------------------------------------------------------

async function resolveKey(spec: ProviderSpec, overrides?: Record<string, string>): Promise<string | undefined> {
  // explicit override from memory config
  if (overrides?.[spec.id]) return overrides[spec.id]

  // environment variables
  for (const name of spec.keyEnv) {
    const val = process.env[name]
    if (val) return val
  }

  // try opencode's provider registry (lazy import to avoid circular deps)
  try {
    const { Provider } = await import("../provider/provider")
    const map = await Provider.list()
    // map provider IDs: gemini -> google
    const pid = spec.id === "gemini" ? "google" : spec.id
    const info = map[pid as keyof typeof map]
    if (info?.key) return info.key
  } catch {}

  return undefined
}

// ---------------------------------------------------------------------------
// HTTP fetch with timeout
// ---------------------------------------------------------------------------

async function post(url: string, key: string | undefined, body: unknown, timeout: number): Promise<any> {
  const headers: Record<string, string> = { "Content-Type": "application/json" }
  if (key) {
    // gemini uses query param, others use bearer
    if (url.includes("googleapis.com")) {
      url += (url.includes("?") ? "&" : "?") + `key=${key}`
    } else if (url.includes("127.0.0.1:11434")) {
      // ollama — key is optional, add only if present
      if (key) headers["Authorization"] = `Bearer ${key}`
    } else {
      headers["Authorization"] = `Bearer ${key}`
    }
  }

  const ctrl = new AbortController()
  const timer = setTimeout(() => ctrl.abort(), timeout)
  try {
    const res = await fetch(url, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
      signal: ctrl.signal,
    })
    if (!res.ok) {
      const text = await res.text().catch(() => "")
      throw new Error(`embedding ${res.status}: ${text.slice(0, 300)}`)
    }
    return res.json()
  } finally {
    clearTimeout(timer)
  }
}

// ---------------------------------------------------------------------------
// Retry helper
// ---------------------------------------------------------------------------

const RETRYABLE = /(rate[_ ]limit|too many requests|429|resource has been exhausted|5\d\d|cloudflare|tokens per day)/i

async function withRetry<T>(fn: () => Promise<T>): Promise<T> {
  let delay = RETRY_BASE_MS
  for (let i = 0; ; i++) {
    try {
      return await fn()
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err)
      if (i >= RETRY_MAX || !RETRYABLE.test(msg)) throw err
      const wait = Math.min(RETRY_CAP_MS, Math.round(delay * (1 + Math.random() * 0.2)))
      log.warn("embedding rate limited, retrying", { wait, attempt: i + 1 })
      await new Promise((r) => setTimeout(r, wait))
      delay *= 2
    }
  }
}

// ---------------------------------------------------------------------------
// Batching — group texts so each batch stays under BATCH_MAX_BYTES
// ---------------------------------------------------------------------------

function batch(texts: string[]): string[][] {
  const result: string[][] = []
  let buf: string[] = []
  let size = 0

  for (const t of texts) {
    const bytes = Buffer.byteLength(t, "utf8")
    if (buf.length > 0 && size + bytes > BATCH_MAX_BYTES) {
      result.push(buf)
      buf = []
      size = 0
    }
    // single text exceeds limit — push alone
    if (buf.length === 0 && bytes > BATCH_MAX_BYTES) {
      result.push([t])
      continue
    }
    buf.push(t)
    size += bytes
  }
  if (buf.length > 0) result.push(buf)
  return result
}

// ---------------------------------------------------------------------------
// Embedding cache (SQLite)
// ---------------------------------------------------------------------------

function hashText(text: string): string {
  return createHash("sha256").update(text).digest("hex").slice(0, 16)
}

export namespace EmbeddingCache {
  export function providerKey(provider: EmbeddingProvider): string {
    return hashText(JSON.stringify({ provider: provider.id, model: provider.model }))
  }

  export function load(provider: EmbeddingProvider, hashes: string[]): Map<string, number[]> {
    const key = providerKey(provider)
    const map = new Map<string, number[]>()
    if (hashes.length === 0) return map

    const db = MemoryDatabase.client()
    const step = 400
    for (let i = 0; i < hashes.length; i += step) {
      const slice = hashes.slice(i, i + step)
      const rows = db
        .select({ hash: EmbeddingCacheTable.hash, embedding: EmbeddingCacheTable.embedding })
        .from(EmbeddingCacheTable)
        .where(
          and(
            eq(EmbeddingCacheTable.provider, provider.id),
            eq(EmbeddingCacheTable.model, provider.model),
            eq(EmbeddingCacheTable.provider_key, key),
            inArray(EmbeddingCacheTable.hash, slice),
          ),
        )
        .all()
      for (const row of rows) {
        try {
          map.set(row.hash, JSON.parse(row.embedding))
        } catch {}
      }
    }
    return map
  }

  export function store(provider: EmbeddingProvider, entries: { hash: string; vec: number[] }[]) {
    if (entries.length === 0) return
    const key = providerKey(provider)
    const now = Date.now()
    const db = MemoryDatabase.client()

    for (const e of entries) {
      db.insert(EmbeddingCacheTable)
        .values({
          provider: provider.id,
          model: provider.model,
          provider_key: key,
          hash: e.hash,
          embedding: JSON.stringify(e.vec),
          dims: e.vec.length,
          updated_at: now,
        })
        .onConflictDoUpdate({
          target: [
            EmbeddingCacheTable.provider,
            EmbeddingCacheTable.model,
            EmbeddingCacheTable.provider_key,
            EmbeddingCacheTable.hash,
          ],
          set: {
            embedding: JSON.stringify(e.vec),
            dims: e.vec.length,
            updated_at: now,
          },
        })
        .run()
    }
  }

  export function prune() {
    const db = MemoryDatabase.client()
    const rows = db.select({ count: sql<number>`count(*)` }).from(EmbeddingCacheTable).all()
    const count = rows[0]?.count ?? 0
    if (count <= CACHE_MAX) return
    const excess = count - CACHE_MAX
    MemoryDatabase.sql(
      `DELETE FROM embedding_cache WHERE rowid IN (SELECT rowid FROM embedding_cache ORDER BY updated_at ASC LIMIT ${excess})`,
    )
    log.info("pruned embedding cache", { removed: excess })
  }
}

// ---------------------------------------------------------------------------
// Create a concrete EmbeddingProvider from a spec + resolved key
// ---------------------------------------------------------------------------

function create(spec: ProviderSpec, key: string | undefined, overrides?: { model?: string; url?: string; dims?: number }): EmbeddingProvider {
  const model = overrides?.model ?? spec.model
  const dims = overrides?.dims ?? spec.dims
  const timeout = spec.id === "ollama" ? TIMEOUT_LOCAL_MS : TIMEOUT_REMOTE_MS
  let base = overrides?.url ?? spec.url

  // substitute model placeholder
  base = base.replace("{model}", model)

  return {
    id: spec.id,
    model,
    dims,
    async embed(texts) {
      const batches = batch(texts)
      const all: number[][] = []
      for (const b of batches) {
        const json = await withRetry(() => post(base, key, spec.body(b, model), timeout))
        const vecs = spec.parse(json)
        all.push(...vecs)
      }
      return all
    },
  }
}

// ---------------------------------------------------------------------------
// Auto-select: try providers by priority until one works
// ---------------------------------------------------------------------------

export interface EmbeddingConfig {
  provider?: string
  model?: string
  url?: string
  dims?: number
  keys?: Record<string, string>
}

export async function createEmbeddingProvider(cfg?: EmbeddingConfig): Promise<EmbeddingProvider | null> {
  const explicit = cfg?.provider

  // explicit provider
  if (explicit && explicit !== "auto") {
    const spec = SPECS.find((s) => s.id === explicit)
    if (!spec) {
      log.warn("unknown embedding provider", { provider: explicit })
      return null
    }
    const key = await resolveKey(spec, cfg?.keys)
    if (!key && spec.keyEnv.length > 0) {
      log.warn("no API key for embedding provider", { provider: explicit })
      return null
    }
    return create(spec, key, cfg)
  }

  // auto mode — try in priority order
  const sorted = SPECS.filter((s) => s.priority < Infinity).sort((a, b) => a.priority - b.priority)

  for (const spec of sorted) {
    const key = await resolveKey(spec, cfg?.keys)
    if (!key && spec.keyEnv.length > 0) continue
    try {
      const provider = create(spec, key, cfg)
      // validate with a tiny test call
      log.info("selected embedding provider", { provider: spec.id, model: spec.model })
      return provider
    } catch (err) {
      log.info("skipping embedding provider", { provider: spec.id, error: String(err) })
    }
  }

  log.warn("no embedding provider available — memory search will use keyword-only mode")
  return null
}
