import { createHash } from "crypto"
import fs from "fs/promises"
import path from "path"
import { eq } from "drizzle-orm"
import { Log } from "../util/log"
import { MemoryDatabase, MemoryFileTable, MemoryChunkTable, MemoryMetaTable } from "./memory-db"
import { chunkMarkdown, type ChunkOptions } from "./chunker"
import { type EmbeddingProvider, EmbeddingCache } from "./embedding"
import { classify } from "./classify"
import { extractKeywords } from "./query-expansion"

const log = Log.create({ service: "memory-indexer" })

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function hash(content: string): string {
  return createHash("sha256").update(content).digest("hex")
}

function chunkId(filepath: string, idx: number): string {
  return createHash("sha256")
    .update(`${filepath}:${idx}`)
    .digest("hex")
    .slice(0, 24)
}

// ---------------------------------------------------------------------------
// Indexer
// ---------------------------------------------------------------------------

export interface IndexerOptions {
  dir: string
  provider: EmbeddingProvider | null
  chunking?: ChunkOptions
}

export namespace Indexer {
  const FTS_VERSION = "2"

  /**
   * One-time migration: rebuild chunks_fts with CJK-augmented text.
   * Runs when fts_version in meta table does not match FTS_VERSION.
   */
  function migrateFts() {
    const ver = getMeta("fts_version")
    if (ver === FTS_VERSION) return

    log.info("rebuilding FTS index for CJK support", { from: ver ?? "none", to: FTS_VERSION })

    MemoryDatabase.sql("DROP TABLE IF EXISTS chunks_fts")
    MemoryDatabase.sql(
      `CREATE VIRTUAL TABLE IF NOT EXISTS chunks_fts USING fts5(
        text,
        id         UNINDEXED,
        path       UNINDEXED,
        source     UNINDEXED,
        model      UNINDEXED,
        start_line UNINDEXED,
        end_line   UNINDEXED
      )`,
    )

    const rows = MemoryDatabase.query<{
      id: string
      path: string
      source: string
      model: string
      start_line: number
      end_line: number
      text: string
    }>("SELECT id, path, source, model, start_line, end_line, text FROM chunks")

    for (const row of rows) {
      MemoryDatabase.sql(
        `INSERT INTO chunks_fts (text, id, path, source, model, start_line, end_line) VALUES (${esc(augment(row.text))}, ${esc(row.id)}, ${esc(row.path)}, ${esc(row.source)}, ${esc(row.model)}, ${row.start_line}, ${row.end_line})`,
      )
    }

    setMeta("fts_version", FTS_VERSION)
    log.info("FTS migration complete", { rows: rows.length })
  }

  /**
   * Full or incremental sync of all markdown files under `dir`.
   * Returns the number of files that were re-indexed.
   */
  export async function sync(opts: IndexerOptions): Promise<number> {
    migrateFts()

    const files = await discover(opts.dir)
    const db = MemoryDatabase.client()

    // load current file index
    const existing = new Map<string, { hash: string; mtime: number }>()
    for (const row of db.select().from(MemoryFileTable).all()) {
      existing.set(row.path, { hash: row.hash, mtime: row.mtime })
    }

    // determine which files changed or are new
    const changed: { filepath: string; content: string; stat: { mtime: number; size: number } }[] = []
    const seen = new Set<string>()

    for (const filepath of files) {
      seen.add(filepath)
      const stat = await fs.stat(filepath)
      const prev = existing.get(filepath)
      if (prev && prev.mtime === Math.floor(stat.mtimeMs)) continue

      const content = await fs.readFile(filepath, "utf-8")
      const h = hash(content)
      if (prev && prev.hash === h) {
        // content same, update mtime only
        db.update(MemoryFileTable)
          .set({ mtime: Math.floor(stat.mtimeMs) })
          .where(eq(MemoryFileTable.path, filepath))
          .run()
        continue
      }

      changed.push({ filepath, content, stat: { mtime: Math.floor(stat.mtimeMs), size: stat.size } })
    }

    // remove deleted files
    const deleted = [...existing.keys()].filter((p) => !seen.has(p))
    if (deleted.length > 0) {
      removeFiles(deleted)
    }

    // index changed files
    for (const file of changed) {
      await indexFile(file.filepath, file.content, file.stat, opts)
    }

    if (changed.length > 0 || deleted.length > 0) {
      log.info("memory index sync complete", {
        indexed: changed.length,
        deleted: deleted.length,
        total: files.length,
      })
    }

    return changed.length
  }

  /**
   * Index a single file: chunk, embed, store.
   */
  async function indexFile(
    filepath: string,
    content: string,
    stat: { mtime: number; size: number },
    opts: IndexerOptions,
  ) {
    const db = MemoryDatabase.client()
    const h = hash(content)
    const chunks = chunkMarkdown(content, opts.chunking)

    if (chunks.length === 0) {
      // empty file — just track it
      upsertFile(filepath, h, stat)
      return
    }

    // remove old chunks for this file
    removeChunksForFile(filepath)

    const now = Date.now()
    const provider = opts.provider
    let embeddings: (number[] | null)[] = chunks.map(() => null)

    if (provider) {
      // check cache
      const hashes = chunks.map((c) => c.hash)
      const cached = EmbeddingCache.load(provider, hashes)
      const missing: { idx: number; text: string; hash: string }[] = []

      for (let i = 0; i < chunks.length; i++) {
        const hit = cached.get(chunks[i]!.hash)
        if (hit) {
          embeddings[i] = hit
        } else {
          missing.push({ idx: i, text: chunks[i]!.text, hash: chunks[i]!.hash })
        }
      }

      // embed missing chunks
      if (missing.length > 0) {
        try {
          const vecs = await provider.embed(missing.map((m) => m.text))
          const entries: { hash: string; vec: number[] }[] = []
          for (let j = 0; j < missing.length; j++) {
            embeddings[missing[j]!.idx] = vecs[j]!
            entries.push({ hash: missing[j]!.hash, vec: vecs[j]! })
          }
          EmbeddingCache.store(provider, entries)
        } catch (err) {
          log.warn("embedding failed for file, using FTS only", {
            path: filepath,
            error: String(err),
          })
        }
      }

      // ensure vec table exists
      MemoryDatabase.ensureVectorTable(provider.dims)
    }

    // insert chunks into DB
    for (let i = 0; i < chunks.length; i++) {
      const chunk = chunks[i]!
      const id = chunkId(filepath, i)
      const vec = embeddings[i]
      const model = provider?.model ?? "none"

      db.insert(MemoryChunkTable)
        .values({
          id,
          path: filepath,
          source: "memory",
          start_line: chunk.start_line,
          end_line: chunk.end_line,
          hash: chunk.hash,
          model,
          text: chunk.text,
          embedding: vec ? JSON.stringify(vec) : "[]",
          updated_at: now,
          category: classify(chunk.text),
        })
        .run()

      // FTS — augment CJK text so unicode61 tokenizer can match char/bigram queries
      MemoryDatabase.sql(
        `INSERT INTO chunks_fts (text, id, path, source, model, start_line, end_line) VALUES (${esc(augment(chunk.text))}, ${esc(id)}, ${esc(filepath)}, 'memory', ${esc(model)}, ${chunk.start_line}, ${chunk.end_line})`,
      )

      // vec0
      if (vec && vec.length > 0) {
        try {
          MemoryDatabase.sql(
            `INSERT INTO chunks_vec (id, embedding) VALUES (${esc(id)}, '${JSON.stringify(vec)}')`,
          )
        } catch {
          // vec0 extension may not be available
        }
      }
    }

    // update file record
    upsertFile(filepath, h, stat)
  }

  /**
   * Remove file records and their chunks from the index.
   */
  function removeFiles(paths: string[]) {
    const db = MemoryDatabase.client()
    for (const p of paths) {
      removeChunksForFile(p)
      db.delete(MemoryFileTable).where(eq(MemoryFileTable.path, p)).run()
    }
  }

  function removeChunksForFile(filepath: string) {
    const db = MemoryDatabase.client()
    // get chunk ids
    const ids = db
      .select({ id: MemoryChunkTable.id })
      .from(MemoryChunkTable)
      .where(eq(MemoryChunkTable.path, filepath))
      .all()
      .map((r) => r.id)

    if (ids.length === 0) return

    // remove from FTS
    for (const id of ids) {
      try {
        MemoryDatabase.sql(`DELETE FROM chunks_fts WHERE id = ${esc(id)}`)
      } catch {}
    }

    // remove from vec0
    for (const id of ids) {
      try {
        MemoryDatabase.sql(`DELETE FROM chunks_vec WHERE id = ${esc(id)}`)
      } catch {}
    }

    // remove from chunks table
    db.delete(MemoryChunkTable).where(eq(MemoryChunkTable.path, filepath)).run()
  }

  function upsertFile(filepath: string, h: string, stat: { mtime: number; size: number }) {
    const db = MemoryDatabase.client()
    db.insert(MemoryFileTable)
      .values({
        path: filepath,
        source: "memory",
        hash: h,
        mtime: stat.mtime,
        size: stat.size,
      })
      .onConflictDoUpdate({
        target: MemoryFileTable.path,
        set: { hash: h, mtime: stat.mtime, size: stat.size },
      })
      .run()
  }

  /**
   * Discover all .md files in the memory directory.
   */
  async function discover(dir: string): Promise<string[]> {
    const result: string[] = []
    try {
      const entries = await fs.readdir(dir, { withFileTypes: true, recursive: true })
      for (const entry of entries) {
        if (!entry.isFile()) continue
        if (!entry.name.endsWith(".md")) continue
        result.push(path.join(entry.parentPath ?? dir, entry.name))
      }
    } catch {
      // directory may not exist yet
    }
    return result.sort()
  }

  /**
   * Store metadata about the index configuration.
   */
  export function setMeta(key: string, value: string) {
    const db = MemoryDatabase.client()
    db.insert(MemoryMetaTable)
      .values({ key, value })
      .onConflictDoUpdate({ target: MemoryMetaTable.key, set: { value } })
      .run()
  }

  export function getMeta(key: string): string | undefined {
    const db = MemoryDatabase.client()
    const row = db
      .select({ value: MemoryMetaTable.value })
      .from(MemoryMetaTable)
      .where(eq(MemoryMetaTable.key, key))
      .get()
    return row?.value
  }
}

// ---------------------------------------------------------------------------
// CJK FTS augmentation
// ---------------------------------------------------------------------------

const CJK = /[\u4e00-\u9fff\u3040-\u30ff\uac00-\ud7af]/

/**
 * Augment text with pre-tokenized CJK keywords for FTS5 indexing.
 *
 * FTS5's default unicode61 tokenizer treats CJK runs as single tokens,
 * but query-expansion splits them into chars + bigrams. Appending the
 * extracted keywords ensures FTS MATCH can find them.
 */
export function augment(text: string): string {
  if (!CJK.test(text)) return text
  const keywords = extractKeywords(text)
  if (keywords.length === 0) return text
  return text + "\n" + keywords.join(" ")
}

// ---------------------------------------------------------------------------
// SQL escape helper for raw queries (FTS / vec0)
// ---------------------------------------------------------------------------

function esc(val: string): string {
  return `'${val.replace(/'/g, "''")}'`
}
