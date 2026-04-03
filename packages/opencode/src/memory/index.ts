import fs from "fs/promises"
import path from "path"
import { Effect, Layer, ServiceMap } from "effect"
import { makeRuntime } from "@/effect/run-service"
import { Log } from "../util/log"
import { MemoryDatabase } from "./memory-db"
import { Indexer } from "./indexer"
import { searchVector, searchKeyword, type SearchResult } from "./search"
import { pipeline, type PipelineOptions } from "./hybrid"
import { createEmbeddingProvider, EmbeddingCache, type EmbeddingProvider, type EmbeddingConfig } from "./embedding"

const log = Log.create({ service: "memory" })

// ---------------------------------------------------------------------------
// Memory file paths — MEMORY.md + memory/ directory live in the user config dir
// (e.g. ~/.config/opencode/ on Linux, %APPDATA%/opencode/ on Windows)
// ---------------------------------------------------------------------------

function memoryDir(dir: string): string {
  return path.join(dir, "memory")
}

function memoryFile(dir: string): string {
  return path.join(dir, "MEMORY.md")
}

// ---------------------------------------------------------------------------
// Memory namespace — Effect Service + static wrappers
// ---------------------------------------------------------------------------

export namespace Memory {
  // ── State ──
  let provider: EmbeddingProvider | null = null
  let rootDir: string | undefined
  let _enabled = false

  /** Whether the memory system has been initialised */
  export function enabled() {
    return _enabled
  }

  // ── Interface ──
  export interface Interface {
    readonly init: (dir: string, cfg?: EmbeddingConfig) => Effect.Effect<void>
    readonly sync: () => Effect.Effect<number>
    readonly search: (query: string, opts?: PipelineOptions) => Effect.Effect<SearchResult[]>
    readonly get: (filepath: string, from?: number, lines?: number) => Effect.Effect<string>
    readonly save: (slug: string, content: string) => Effect.Effect<string>
    readonly forget: (filepath: string) => Effect.Effect<boolean>
    readonly reindex: () => Effect.Effect<void>
    readonly close: () => Effect.Effect<void>
  }

  // ── Service tag ──
  export class Service extends ServiceMap.Service<Service, Interface>()("@opencode/Memory") {}

  // ── Layer ──
  export const layer = Layer.effect(
    Service,
    Effect.gen(function* () {
      const init = Effect.fn("Memory.init")(function* (dir: string, cfg?: EmbeddingConfig) {
        rootDir = dir
        // ensure memory directory exists
        yield* Effect.promise(() => fs.mkdir(memoryDir(dir), { recursive: true }))
        // ensure MEMORY.md exists
        const main = memoryFile(dir)
        yield* Effect.promise(async () => {
          try {
            await fs.access(main)
          } catch {
            await fs.writeFile(main, "# Memory\n\nThis file stores cross-session memory for the AI assistant.\n")
          }
        })
        // initialise embedding provider
        provider = yield* Effect.promise(() => createEmbeddingProvider(cfg))
        if (provider) {
          log.info("memory embedding provider ready", { provider: provider.id, model: provider.model })
        }
        // initial index sync — memory/ subdirectory then project root (MEMORY.md)
        yield* Effect.promise(() => Indexer.sync({ dir: memoryDir(dir), provider }))
        yield* Effect.promise(() => Indexer.sync({ dir, provider }))
        log.info("memory system initialised", { dir })
        _enabled = true
      })

      const sync = Effect.fn("Memory.sync")(function* () {
        if (!rootDir) return 0
        try {
          const a = yield* Effect.promise(() => Indexer.sync({ dir: memoryDir(rootDir!), provider }))
          const b = yield* Effect.promise(() => Indexer.sync({ dir: rootDir!, provider }))
          return a + b
        } catch (err) {
          if (!MemoryDatabase.isReadonly(err)) throw err
          log.warn("readonly database detected during sync, reopening")
          MemoryDatabase.reopen()
          const a = yield* Effect.promise(() => Indexer.sync({ dir: memoryDir(rootDir!), provider }))
          const b = yield* Effect.promise(() => Indexer.sync({ dir: rootDir!, provider }))
          return a + b
        }
      })

      const search = Effect.fn("Memory.search")(function* (query: string, opts?: PipelineOptions) {
        const limit = opts?.limit ?? 10
        const fetch = limit * 3 // overfetch for post-processing

        let vector: SearchResult[] = []
        if (provider) {
          vector = yield* Effect.promise(() => searchVector(query, provider!, fetch))
        }
        const keyword = searchKeyword(query, fetch)

        return pipeline(vector, keyword, opts)
      })

      const get = Effect.fn("Memory.get")(function* (filepath: string, from?: number, lines?: number) {
        const content = yield* Effect.promise(() => fs.readFile(filepath, "utf-8"))
        if (from === undefined) return content
        const all = content.split("\n")
        const start = Math.max(0, (from ?? 1) - 1)
        const end = lines ? start + lines : all.length
        return all.slice(start, end).join("\n")
      })

      const save = Effect.fn("Memory.save")(function* (slug: string, content: string) {
        if (!rootDir) {
          yield* Effect.fail(new Error("memory not initialised"))
          return ""
        }

        // ── Duplicate detection via embedding similarity ──
        if (provider) {
          const dupeResult = yield* Effect.promise(async () => {
            try {
              const results = await searchVector(content, provider!, 5)
              if (results.length === 0) return "new"
              const best = results[0]!
              if (best.score >= 0.95) return "skip" as const
              if (best.score >= 0.85) return best.path
              return "new" as const
            } catch {
              return "new" as const
            }
          })

          if (dupeResult === "skip") {
            log.info("memory skipped — near-duplicate detected", { slug })
            return ""
          }

          // similarity 0.85-0.95: update the existing file
          if (dupeResult !== "new") {
            const existing = dupeResult
            // only update files inside the memory directory
            if (existing.startsWith(memoryDir(rootDir))) {
              yield* Effect.promise(() => fs.writeFile(existing, content, "utf-8"))
              yield* Effect.promise(() => Indexer.sync({ dir: memoryDir(rootDir!), provider }))
              log.info("memory updated — similar content merged", { file: path.basename(existing) })
              return existing
            }
          }
        }

        const date = new Date().toISOString().slice(0, 10)
        const filename = `${date}-${slug}.md`
        const filepath = path.join(memoryDir(rootDir), filename)
        yield* Effect.promise(() => fs.writeFile(filepath, content, "utf-8"))
        // re-index this file
        yield* Effect.promise(() => Indexer.sync({ dir: memoryDir(rootDir!), provider }))
        log.info("memory saved", { file: filename })
        return filepath
      })

      const forget = Effect.fn("Memory.forget")(function* (filepath: string) {
        if (!rootDir) return false
        // only allow deleting files inside the memory directory
        const dir = memoryDir(rootDir)
        if (!filepath.startsWith(dir)) return false
        yield* Effect.promise(async () => {
          try {
            await fs.rm(filepath, { force: true })
          } catch {}
        })
        // remove from index
        MemoryDatabase.deleteFile(filepath)
        log.info("memory forgotten", { file: path.basename(filepath) })
        return true
      })

      const close = Effect.fn("Memory.close")(function* () {
        EmbeddingCache.prune()
        MemoryDatabase.close()
        provider = null
        rootDir = undefined
        _enabled = false
        log.info("memory system closed")
      })

      const reindex = Effect.fn("Memory.reindex")(function* () {
        if (!rootDir) return
        yield* Effect.promise(() =>
          MemoryDatabase.atomicReindex(async (_tempDb) => {
            // Full rebuild: re-sync all memory files into the temp database
            // The temp DB is already set up with schema. We need to temporarily
            // point MemoryDatabase at it, run sync, then it gets swapped back.
            // Since atomicReindex handles the swap, we just need to populate
            // the temp DB by running indexer against the memory directories.
            await Indexer.sync({ dir: memoryDir(rootDir!), provider })
            await Indexer.sync({ dir: rootDir!, provider })
          }),
        )
        log.info("memory reindex completed")
      })

      return Service.of({ init, sync, search, get, save, forget, reindex, close })
    }),
  )

  // ── defaultLayer ──
  export const defaultLayer = layer

  // ── Runtime ──
  const { runPromise } = makeRuntime(Service, defaultLayer)

  // ── Static wrappers ──
  export async function init(dir: string, cfg?: EmbeddingConfig) {
    return runPromise((svc) => svc.init(dir, cfg))
  }

  export async function sync() {
    return runPromise((svc) => svc.sync())
  }

  export async function search(query: string, opts?: PipelineOptions): Promise<SearchResult[]> {
    return runPromise((svc) => svc.search(query, opts))
  }

  export async function get(filepath: string, from?: number, lines?: number): Promise<string> {
    return runPromise((svc) => svc.get(filepath, from, lines))
  }

  export async function save(slug: string, content: string): Promise<string> {
    return runPromise((svc) => svc.save(slug, content))
  }

  export async function forget(filepath: string): Promise<boolean> {
    return runPromise((svc) => svc.forget(filepath))
  }

  /**
   * Append content to the daily memory file (memory/YYYY-MM-DD.md).
   * Creates the file if it doesn't exist. Appends with separator if it does.
   * Bypasses duplicate detection — used by flush and session-save.
   */
  export async function appendDaily(content: string, date?: string): Promise<string> {
    if (!rootDir) return ""
    const d = date ?? new Date().toISOString().slice(0, 10)
    const filename = `${d}.md`
    const filepath = path.join(memoryDir(rootDir), filename)
    try {
      await fs.access(filepath)
      // file exists — append with separator
      await fs.appendFile(filepath, "\n\n---\n\n" + content, "utf-8")
    } catch {
      // file doesn't exist — create with header
      const header = `# Daily Memory: ${d}\n\n`
      await fs.writeFile(filepath, header + content, "utf-8")
    }
    // re-index
    await Indexer.sync({ dir: memoryDir(rootDir), provider })
    log.info("daily memory appended", { file: filename })
    return filepath
  }

  export async function reindex() {
    return runPromise((svc) => svc.reindex())
  }

  export async function close() {
    return runPromise((svc) => svc.close())
  }

  // ── Convenience: memory directory path ──
  export function dir(root: string) {
    return memoryDir(root)
  }

  export function mainFile(root: string) {
    return memoryFile(root)
  }

  /** Return the resolved path to MEMORY.md, or empty string if not initialised. */
  export function permanentPath(): string {
    if (!rootDir) return ""
    return memoryFile(rootDir)
  }

  // ── Bootstrap helpers: read MEMORY.md + recent daily memory for system prompt ──

  const MAX_MEMORY_CHARS = 20_000
  const MAX_DAILY_CHARS = 10_000
  const DEFAULT_DAILY_DAYS = 3

  /**
   * Read MEMORY.md content for injection into system prompt.
   * Returns empty string if file doesn't exist or is only the default template.
   * Truncates to MAX_MEMORY_CHARS.
   */
  export async function readPermanent(): Promise<string> {
    if (!rootDir) return ""
    const filepath = memoryFile(rootDir)
    try {
      const content = await fs.readFile(filepath, "utf-8")
      // skip if only default template
      if (content.trim() === "# Memory\n\nThis file stores cross-session memory for the AI assistant.") return ""
      if (content.trim().length < 20) return ""
      return content.length > MAX_MEMORY_CHARS ? content.slice(0, MAX_MEMORY_CHARS) + "\n...[truncated]..." : content
    } catch {
      return ""
    }
  }

  /**
   * Read recent N days of daily memory files (memory/YYYY-MM-DD.md) for injection.
   * Returns combined content, most recent first. Truncates to MAX_DAILY_CHARS.
   */
  export async function readRecent(days?: number): Promise<string> {
    if (!rootDir) return ""
    const dir = memoryDir(rootDir)
    const n = days ?? DEFAULT_DAILY_DAYS
    try {
      const files = await fs.readdir(dir)
      // match YYYY-MM-DD.md pattern (daily aggregated files)
      const daily = files
        .filter((f) => /^\d{4}-\d{2}-\d{2}\.md$/.test(f))
        .sort()
        .reverse()
        .slice(0, n)
      if (daily.length === 0) return ""
      const parts: string[] = []
      let total = 0
      for (const file of daily) {
        const content = await fs.readFile(path.join(dir, file), "utf-8")
        if (total + content.length > MAX_DAILY_CHARS) {
          const remaining = MAX_DAILY_CHARS - total
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
}
