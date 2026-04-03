import { Database } from "bun:sqlite"
import { drizzle } from "drizzle-orm/bun-sqlite"

export type RawDatabase = Database
export type DrizzleClient = ReturnType<typeof drizzle>

export function open(path: string): RawDatabase {
  return new Database(path, { create: true })
}

export function wrap(db: RawDatabase): DrizzleClient {
  return drizzle({ client: db })
}

export function run(db: RawDatabase, sql: string) {
  db.run(sql)
}

export function exec<T = unknown>(db: RawDatabase, sql: string): T[] {
  return db.prepare(sql).all() as T[]
}

export function close(db: RawDatabase) {
  db.close()
}
