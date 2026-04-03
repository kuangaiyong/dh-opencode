import { describe, test, expect } from "bun:test"
import { classify, type Category } from "../../src/memory/classify"

describe("classify", () => {
  test("classifies preferences", () => {
    expect(classify("I prefer TypeScript over JavaScript")).toBe("preference")
    expect(classify("I like using Vim keybindings")).toBe("preference")
    expect(classify("I dislike long functions")).toBe("preference")
    expect(classify("My favorite framework is React")).toBe("preference")
    expect(classify("I would rather use Bun than Node")).toBe("preference")
  })

  test("classifies decisions", () => {
    expect(classify("We decided to use PostgreSQL for the database")).toBe("decision")
    expect(classify("The team chose microservices architecture")).toBe("decision")
    expect(classify("We concluded that caching is needed")).toBe("decision")
    expect(classify("The agreed approach is to use REST")).toBe("decision")
    expect(classify("We settled on a monorepo strategy")).toBe("decision")
  })

  test("classifies entities", () => {
    expect(classify("My name is Alice")).toBe("entity")
    expect(classify("The service is called AuthProxy")).toBe("entity")
    expect(classify("She is known as the DevOps lead")).toBe("entity")
    expect(classify("The project is named Phoenix")).toBe("entity")
    expect(classify("Our team maintains the billing repo")).toBe("entity")
  })

  test("classifies facts", () => {
    expect(classify("The server is located in us-east-1")).toBe("fact")
    expect(classify("She works at Google")).toBe("fact")
    expect(classify("The API runs on port 3000")).toBe("fact")
    expect(classify("The project is built with Rust")).toBe("fact")
    expect(classify("Production uses version 2.1.0")).toBe("fact")
  })

  test("returns other for unmatched text", () => {
    expect(classify("The weather is nice today")).toBe("other")
    expect(classify("Random notes about the meeting")).toBe("other")
    expect(classify("")).toBe("other")
  })

  test("first matching pattern wins (preference before decision)", () => {
    // "prefer" matches preference; "decided" would match decision
    expect(classify("I prefer the approach we decided on")).toBe("preference")
  })

  test("classification is case-insensitive", () => {
    expect(classify("I PREFER tabs")).toBe("preference")
    expect(classify("we DECIDED on REST")).toBe("decision")
    expect(classify("NAME IS Bob")).toBe("entity")
    expect(classify("IS LOCATED in AWS")).toBe("fact")
  })

  test("returns correct Category type", () => {
    const result: Category = classify("test")
    expect(["preference", "decision", "entity", "fact", "other"]).toContain(result)
  })
})
