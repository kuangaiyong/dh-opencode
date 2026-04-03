import { sqliteTable, text, integer, index, primaryKey } from "drizzle-orm/sqlite-core"
import { Global } from "../global"
import { Log } from "../util/log"
import { lazy } from "../util/lazy"
import { open, wrap, run, exec, close as rawClose, type RawDatabase, type DrizzleClient } from "#memory-db-raw"
import path from "path"
import { randomUUID } from "crypto"

const log = Log.create({ service: "memory-db" })

// ---------------------------------------------------------------------------
// Drizzle table definitions (used for typed queries, NOT for drizzle-kit migration)
// ---------------------------------------------------------------------------

export const MemoryFileTable = sqliteTable("files", {
  path: text().primaryKey(),
  source: text().notNull().default("memory"),
  hash: text().notNull(),
  mtime: integer().notNull(),
  size: integer().notNull(),
})

export const MemoryChunkTable = sqliteTable(
  "chunks",
  {
    id: text().primaryKey(),
    path: text().notNull(),
    source: text().notNull().default("memory"),
    start_line: integer().notNull(),
    end_line: integer().notNull(),
    hash: text().notNull(),
    model: text().notNull(),
    text: text().notNull(),
    embedding: text().notNull(),
    updated_at: integer().notNull(),
    category: text().notNull().default("other"),
  },
  (table) => [
    index("chunks_path_idx").on(table.path),
    index("chunks_source_idx").on(table.source),
  ],
)

export const EmbeddingCacheTable = sqliteTable(
  "embedding_cache",
  {
    provider: text().notNull(),
    model: text().notNull(),
    provider_key: text().notNull(),
    hash: text().notNull(),
    embedding: text().notNull(),
    dims: integer(),
    updated_at: integer().notNull(),
  },
  (table) => [
    primaryKey({ columns: [table.provider, table.model, table.provider_key, table.hash] }),
    index("embedding_cache_updated_at_idx").on(table.updated_at),
  ],
)

export const MemoryMetaTable = sqliteTable("meta", {
  key: text().primaryKey(),
  value: text().notNull(),
})

// ---------------------------------------------------------------------------
// Raw DDL for tables that must live in the independent memory DB
// Includes FTS5 / vec0 virtual tables that Drizzle cannot express
// ---------------------------------------------------------------------------

const DDL = [
  `CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS files (
    path   TEXT PRIMARY KEY,
    source TEXT NOT NULL DEFAULT 'memory',
    hash   TEXT NOT NULL,
    mtime  INTEGER NOT NULL,
    size   INTEGER NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS chunks (
    id         TEXT PRIMARY KEY,
    path       TEXT NOT NULL,
    source     TEXT NOT NULL DEFAULT 'memory',
    start_line INTEGER NOT NULL,
    end_line   INTEGER NOT NULL,
    hash       TEXT NOT NULL,
    model      TEXT NOT NULL,
    text       TEXT NOT NULL,
    embedding  TEXT NOT NULL,
    updated_at INTEGER NOT NULL,
    category   TEXT NOT NULL DEFAULT 'other'
  )`,
  `CREATE INDEX IF NOT EXISTS chunks_path_idx   ON chunks(path)`,
  `CREATE INDEX IF NOT EXISTS chunks_source_idx ON chunks(source)`,
  `CREATE TABLE IF NOT EXISTS embedding_cache (
    provider      TEXT NOT NULL,
    model         TEXT NOT NULL,
    provider_key  TEXT NOT NULL,
    hash          TEXT NOT NULL,
    embedding     TEXT NOT NULL,
    dims          INTEGER,
    updated_at    INTEGER NOT NULL,
    PRIMARY KEY (provider, model, provider_key, hash)
  )`,
  `CREATE INDEX IF NOT EXISTS embedding_cache_updated_at_idx ON embedding_cache(updated_at)`,
  // FTS5 virtual table for keyword search
  `CREATE VIRTUAL TABLE IF NOT EXISTS chunks_fts USING fts5(
    text,
    id         UNINDEXED,
    path       UNINDEXED,
    source     UNINDEXED,
    model      UNINDEXED,
    start_line UNINDEXED,
    end_line   UNINDEXED
  )`,
]

// vec0 virtual table is created lazily after we know the embedding dimensions
function vecDDL(dims: number) {
  return `CREATE VIRTUAL TABLE IF NOT EXISTS chunks_vec USING vec0(
    id        TEXT PRIMARY KEY,
    embedding FLOAT[${dims}]
  )`
}

// ---------------------------------------------------------------------------
// MemoryDatabase — independent SQLite connection for cross-session memory
// ---------------------------------------------------------------------------

export namespace MemoryDatabase {
  export type { RawDatabase, DrizzleClient }

  export const VECTOR_TABLE = "chunks_vec"
  export const FTS_TABLE = "chunks_fts"
  export const CACHE_TABLE = "embedding_cache"

  export function dbPath() {
    return path.join(Global.Path.data, "memory.db")
  }

  // -- internal lazy handles + override for atomic reindex --
  let _override: { raw: RawDatabase; client: DrizzleClient } | null = null

  const _raw = lazy(() => {
    const p = dbPath()
    log.info("opening memory database", { path: p })
    const db = open(p)
    run(db, "PRAGMA journal_mode = WAL")
    run(db, "PRAGMA synchronous = NORMAL")
    run(db, "PRAGMA busy_timeout = 5000")
    run(db, "PRAGMA cache_size = -32000")
    run(db, "PRAGMA foreign_keys = OFF")

    for (const stmt of DDL) {
      run(db, stmt)
    }

    // schema migration: add category column if missing (existing databases)
    try {
      run(db, `ALTER TABLE chunks ADD COLUMN category TEXT NOT NULL DEFAULT 'other'`)
    } catch {}

    return db
  })

  const _client = lazy(() => wrap(_raw()))

  /** Raw sqlite handle — exposed for vec0 / FTS5 operations that need raw sql */
  export function raw(): RawDatabase {
    return _override ? _override.raw : _raw()
  }

  /** Drizzle-wrapped client for typed queries on regular tables */
  export function client(): DrizzleClient {
    return _override ? _override.client : _client()
  }

  /** Execute a raw SQL statement */
  export function sql(stmt: string) {
    run(raw(), stmt)
  }

  /** Execute a raw SQL query and return rows */
  export function query<T = unknown>(stmt: string): T[] {
    return exec<T>(raw(), stmt)
  }

  /** Create the vec0 virtual table once embedding dimensions are known */
  export function ensureVectorTable(dims: number) {
    run(raw(), vecDDL(dims))
  }

  /** Check whether sqlite-vec extension is available */
  export function hasVecExtension(): boolean {
    try {
      exec(raw(), "SELECT vec_version()")
      return true
    } catch {
      return false
    }
  }

  /** Delete chunks by their IDs from all tables (chunks, FTS, vec0) */
  export function deleteChunks(ids: string[]) {
    if (ids.length === 0) return
    for (const id of ids) {
      const escaped = `'${id.replace(/'/g, "''")}'`
      try {
        run(raw(), `DELETE FROM chunks_fts WHERE id = ${escaped}`)
      } catch {}
      try {
        run(raw(), `DELETE FROM chunks_vec WHERE id = ${escaped}`)
      } catch {}
      run(raw(), `DELETE FROM chunks WHERE id = ${escaped}`)
    }
  }

  /** Delete a file record and all its chunks */
  export function deleteFile(filepath: string) {
    const escaped = `'${filepath.replace(/'/g, "''")}'`
    const rows = exec<{ id: string }>(raw(), `SELECT id FROM chunks WHERE path = ${escaped}`)
    deleteChunks(rows.map((r) => r.id))
    run(raw(), `DELETE FROM files WHERE path = ${escaped}`)
  }

  export function close() {
    _override = null
    try {
      rawClose(_raw())
    } catch {}
    _raw.reset()
    _client.reset()
  }

  /** Delete the database file and reset lazy handles — used for full rebuild */
  export async function destroy() {
    close()
    const fs = await import("fs/promises")
    const p = dbPath()
    for (const suffix of ["", "-wal", "-shm"]) {
      await fs.rm(p + suffix, { force: true }).catch(() => {})
    }
  }

  // -------------------------------------------------------------------------
  // Readonly DB recovery
  // -------------------------------------------------------------------------

  const READONLY_PATTERN = /attempt to write a readonly database|database is read-only|SQLITE_READONLY/i

  /** Check whether an error indicates a readonly database handle */
  export function isReadonly(err: unknown): boolean {
    if (!err) return false
    const msg = err instanceof Error ? err.message : String(err)
    if (READONLY_PATTERN.test(msg)) return true
    if (err && typeof err === "object") {
      const rec = err as Record<string, unknown>
      for (const key of ["code", "name"]) {
        if (typeof rec[key] === "string" && READONLY_PATTERN.test(rec[key] as string)) return true
      }
      if (rec.cause && typeof rec.cause === "object") {
        const cause = rec.cause as Record<string, unknown>
        for (const key of ["message", "code", "name"]) {
          if (typeof cause[key] === "string" && READONLY_PATTERN.test(cause[key] as string)) return true
        }
      }
    }
    return false
  }

  /** Reopen the database connection — used to recover from readonly file handles */
  export function reopen() {
    log.warn("reopening memory database after readonly error")
    close()
    // accessing raw() triggers the lazy initialiser which re-opens & runs DDL
    raw()
    client()
  }

  /**
   * Execute a write operation with automatic readonly recovery.
   * If the operation fails with SQLITE_READONLY, reopen the connection and retry once.
   */
  export function withRecovery<T>(fn: () => T): T {
    try {
      return fn()
    } catch (err) {
      if (!isReadonly(err)) throw err
      reopen()
      return fn()
    }
  }

  // -------------------------------------------------------------------------
  // Atomic reindex — temp DB → full rebuild → 3-step file swap
  // -------------------------------------------------------------------------

  function esc(val: string | number | null): string {
    if (val === null) return "NULL"
    if (typeof val === "number") return String(val)
    return `'${String(val).replace(/'/g, "''")}'`
  }

  /**
   * Open a fresh database at `p`, run DDL, and return the raw handle.
   * This is used to create a temporary database for atomic reindex.
   */
  function openAt(p: string): RawDatabase {
    const db = open(p)
    run(db, "PRAGMA journal_mode = WAL")
    run(db, "PRAGMA synchronous = NORMAL")
    run(db, "PRAGMA busy_timeout = 5000")
    run(db, "PRAGMA cache_size = -32000")
    run(db, "PRAGMA foreign_keys = OFF")
    for (const stmt of DDL) {
      run(db, stmt)
    }
    return db
  }

  /**
   * Move SQLite files (db + WAL + SHM) from source to target.
   * Ignores ENOENT for WAL/SHM files (they may not exist).
   */
  async function moveFiles(source: string, target: string) {
    const fs = await import("fs/promises")
    for (const suffix of ["", "-wal", "-shm"]) {
      try {
        await fs.rename(source + suffix, target + suffix)
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err
      }
    }
  }

  /** Remove SQLite files (db + WAL + SHM) at basePath */
  async function removeFiles(base: string) {
    const fs = await import("fs/promises")
    for (const suffix of ["", "-wal", "-shm"]) {
      await fs.rm(base + suffix, { force: true }).catch(() => {})
    }
  }

  /**
   * Copy the embedding_cache table from the current DB into a temp DB.
   * This preserves expensive embedding computations across reindex.
   */
  function seedCache(source: RawDatabase, target: RawDatabase) {
    try {
      const rows = exec<{
        provider: string
        model: string
        provider_key: string
        hash: string
        embedding: string
        dims: number | null
        updated_at: number
      }>(source, "SELECT * FROM embedding_cache")

      for (const row of rows) {
        const vals = [
          esc(row.provider), esc(row.model), esc(row.provider_key), esc(row.hash),
          esc(row.embedding), row.dims !== null ? row.dims : "NULL", row.updated_at,
        ].join(", ")
        run(target, `INSERT OR IGNORE INTO embedding_cache (provider, model, provider_key, hash, embedding, dims, updated_at) VALUES (${vals})`)
      }
    } catch {
      // cache seeding is best-effort
    }
  }

  /**
   * Perform an atomic reindex:
   * 1. Create a temp database
   * 2. Seed embedding cache from current DB
   * 3. Run the provided `rebuild` callback against the temp DB
   * 4. Close both DBs
   * 5. Swap files: current → backup, temp → current, delete backup
   * 6. Reopen at the original path
   *
   * On failure the original database is preserved.
   */
  export async function atomicReindex(rebuild: (db: RawDatabase) => Promise<void>) {
    const p = dbPath()
    const temp = `${p}.tmp-${randomUUID()}`
    const backup = `${p}.backup-${randomUUID()}`
    const original = raw()

    let tempDb: RawDatabase | null = null

    try {
      tempDb = openAt(temp)
      seedCache(original, tempDb)

      // Redirect all MemoryDatabase.raw() / client() calls to the temp DB
      // so that Indexer.sync and other callers write into the temp database.
      _override = { raw: tempDb, client: wrap(tempDb) }
      try {
        await rebuild(tempDb)
      } finally {
        _override = null
      }

      // close both handles
      rawClose(tempDb)
      tempDb = null
      close() // closes original + resets lazy handles

      // 3-step file swap with backup rollback
      await moveFiles(p, backup)
      try {
        await moveFiles(temp, p)
      } catch (err) {
        // rollback: restore backup
        await moveFiles(backup, p)
        throw err
      }
      await removeFiles(backup)

      // reopen at original path
      raw()
      client()
      log.info("atomic reindex completed successfully")
    } catch (err) {
      _override = null
      // cleanup temp DB if still open
      if (tempDb) {
        try { rawClose(tempDb) } catch {}
      }
      await removeFiles(temp)
      // ensure original DB is accessible — reopen if close() was called
      try { raw(); client() } catch {}
      log.warn("atomic reindex failed, original database preserved", { error: String(err) })
      throw err
    }
  }
}
