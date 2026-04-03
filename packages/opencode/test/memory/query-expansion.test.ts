import { describe, test, expect } from "bun:test"
import { extractKeywords, expandQuery } from "../../src/memory/query-expansion"
import { augment } from "../../src/memory/indexer"

describe("query-expansion", () => {
  describe("extractKeywords", () => {
    test("filters English stop words", () => {
      const result = extractKeywords("that thing we discussed about the API")
      expect(result).toContain("discussed")
      expect(result).toContain("api")
      expect(result).not.toContain("that")
      expect(result).not.toContain("the")
      expect(result).not.toContain("we")
      expect(result).not.toContain("thing")
    })

    test("returns empty for all-stop-word query", () => {
      const result = extractKeywords("what was the thing")
      expect(result).toEqual([])
    })

    test("handles Chinese text with bigrams", () => {
      const result = extractKeywords("之前讨论的那个方案")
      // Stop words "之前" "的" "那个" filtered; CJK produces unigrams + bigrams
      expect(result.some((k) => k.includes("讨"))).toBeTrue()
      expect(result.some((k) => k.includes("方案"))).toBeTrue()
    })

    test("handles Korean with particle stripping", () => {
      const result = extractKeywords("프로젝트에서 사용한 도구")
      // "프로젝트" should survive after stripping "에서"
      expect(result.some((k) => k.includes("프로젝트"))).toBeTrue()
    })

    test("handles Japanese text", () => {
      const result = extractKeywords("昨日のミーティングで話した内容")
      // "昨日" is a stop word; "ミーティング" should survive
      expect(result.some((k) => k.includes("ミーティング"))).toBeTrue()
    })

    test("deduplicates tokens", () => {
      const result = extractKeywords("api api api endpoint endpoint")
      expect(result.filter((k) => k === "api")).toHaveLength(1)
      expect(result.filter((k) => k === "endpoint")).toHaveLength(1)
    })

    test("filters pure numbers", () => {
      const result = extractKeywords("123 456 config")
      expect(result).not.toContain("123")
      expect(result).not.toContain("456")
      expect(result).toContain("config")
    })

    test("filters short English words", () => {
      const result = extractKeywords("go to db config")
      expect(result).not.toContain("go")
      expect(result).not.toContain("to")
      expect(result).not.toContain("db")
      expect(result).toContain("config")
    })

    test("handles empty string", () => {
      expect(extractKeywords("")).toEqual([])
    })

    test("handles mixed-language input", () => {
      const result = extractKeywords("the API 配置 and 설정")
      expect(result).toContain("api")
      // Chinese characters for 配置
      expect(result.some((k) => k.includes("配"))).toBeTrue()
    })
  })

  describe("expandQuery", () => {
    test("returns original and expanded with OR", () => {
      const result = expandQuery("what was the API solution")
      expect(result.original).toBe("what was the API solution")
      expect(result.keywords).toContain("api")
      expect(result.keywords).toContain("solution")
      expect(result.expanded).toContain("OR")
    })

    test("returns original only when no keywords extracted", () => {
      const result = expandQuery("what was the thing")
      expect(result.keywords).toEqual([])
      expect(result.expanded).toBe("what was the thing")
    })

    test("trims whitespace", () => {
      const result = expandQuery("  hello world  ")
      expect(result.original).toBe("hello world")
    })
  })

  describe("augment", () => {
    test("returns text unchanged for pure English", () => {
      const text = "This is a plain English memory about API design"
      expect(augment(text)).toBe(text)
    })

    test("appends CJK keywords for Chinese text", () => {
      const text = "用户身份是测试架构师"
      const result = augment(text)
      // Original text preserved at the start
      expect(result.startsWith(text)).toBeTrue()
      // Keywords appended after newline
      expect(result).toContain("\n")
      const appended = result.slice(text.length + 1)
      // Should contain bigrams like "用户" "身份" "测试" "架构"
      expect(appended).toContain("用户")
      expect(appended).toContain("测试")
    })

    test("appends keywords for Japanese text", () => {
      const text = "プロジェクトの設定について"
      const result = augment(text)
      expect(result.startsWith(text)).toBeTrue()
      expect(result.length).toBeGreaterThan(text.length)
    })

    test("appends keywords for Korean text", () => {
      const text = "프로젝트 설정 가이드"
      const result = augment(text)
      expect(result.startsWith(text)).toBeTrue()
      expect(result.length).toBeGreaterThan(text.length)
    })

    test("handles mixed CJK and English", () => {
      const text = "API 配置指南 for deployment"
      const result = augment(text)
      expect(result.startsWith(text)).toBeTrue()
      expect(result).toContain("配置")
    })

    test("returns text unchanged when CJK produces no keywords", () => {
      // Single CJK stop word only — extractKeywords returns []
      const text = "的"
      const result = augment(text)
      expect(result).toBe(text)
    })
  })
})
