import { DatabaseSync } from "node:sqlite"
import { drizzle } from "drizzle-orm/node-sqlite"

export type RawDatabase = DatabaseSync
export type DrizzleClient = ReturnType<typeof drizzle>

export function open(path: string): RawDatabase {
  return new DatabaseSync(path)
}

export function wrap(db: RawDatabase): DrizzleClient {
  return drizzle({ client: db })
}

export function run(db: RawDatabase, sql: string) {
  db.exec(sql)
}

export function exec<T = unknown>(db: RawDatabase, sql: string): T[] {
  const stmt = db.prepare(sql)
  return stmt.all() as T[]
}

export function close(db: RawDatabase) {
  db.close()
}
