import { describe, test, expect } from "bun:test"
import { MemoryDatabase } from "../../src/memory/memory-db"

describe("memory-db: isReadonly", () => {
  test("detects readonly error message", () => {
    expect(MemoryDatabase.isReadonly(new Error("attempt to write a readonly database"))).toBeTrue()
    expect(MemoryDatabase.isReadonly(new Error("SQLITE_READONLY: cannot modify"))).toBeTrue()
    expect(MemoryDatabase.isReadonly(new Error("database is read-only"))).toBeTrue()
  })

  test("detects readonly in code property", () => {
    const err = Object.assign(new Error("write failed"), { code: "SQLITE_READONLY" })
    expect(MemoryDatabase.isReadonly(err)).toBeTrue()
  })

  test("detects readonly in name property", () => {
    const err = Object.assign(new Error("operation failed"), { name: "SQLITE_READONLY" })
    expect(MemoryDatabase.isReadonly(err)).toBeTrue()
  })

  test("detects readonly in cause chain", () => {
    const cause = { message: "attempt to write a readonly database", code: "SQLITE_READONLY" }
    const err = Object.assign(new Error("outer error"), { cause })
    expect(MemoryDatabase.isReadonly(err)).toBeTrue()
  })

  test("detects readonly in cause code", () => {
    const cause = { message: "failed", code: "SQLITE_READONLY" }
    const err = Object.assign(new Error("outer"), { cause })
    expect(MemoryDatabase.isReadonly(err)).toBeTrue()
  })

  test("returns false for null/undefined", () => {
    expect(MemoryDatabase.isReadonly(null)).toBeFalse()
    expect(MemoryDatabase.isReadonly(undefined)).toBeFalse()
  })

  test("returns false for unrelated errors", () => {
    expect(MemoryDatabase.isReadonly(new Error("SQLITE_BUSY"))).toBeFalse()
    expect(MemoryDatabase.isReadonly(new Error("disk full"))).toBeFalse()
    expect(MemoryDatabase.isReadonly(new Error("connection refused"))).toBeFalse()
  })

  test("returns false for non-error values", () => {
    expect(MemoryDatabase.isReadonly("some string")).toBeFalse()
    expect(MemoryDatabase.isReadonly(42)).toBeFalse()
    expect(MemoryDatabase.isReadonly({})).toBeFalse()
  })

  test("case insensitive matching", () => {
    expect(MemoryDatabase.isReadonly(new Error("ATTEMPT TO WRITE A READONLY DATABASE"))).toBeTrue()
    expect(MemoryDatabase.isReadonly(new Error("Database Is Read-Only"))).toBeTrue()
  })
})
