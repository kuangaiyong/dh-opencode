import { describe, expect, test } from "bun:test"
import {
  isDangerousBashPattern,
  isDangerousPowerShellPattern,
  isDangerousRule,
  stripDangerousRules,
  findDangerousRules,
} from "../../src/permission/dangerous-rules"

describe("dangerous-rules", () => {
  // ─── isDangerousBashPattern ────────────────────────────────────────

  describe("isDangerousBashPattern", () => {
    test("flags wildcard *", () => {
      expect(isDangerousBashPattern("*")).toBe(true)
    })

    test("flags python", () => {
      expect(isDangerousBashPattern("python")).toBe(true)
    })

    test("flags python:*", () => {
      expect(isDangerousBashPattern("python:*")).toBe(true)
    })

    test("flags python*", () => {
      expect(isDangerousBashPattern("python*")).toBe(true)
    })

    test("flags python *", () => {
      expect(isDangerousBashPattern("python *")).toBe(true)
    })

    test("flags python -c*", () => {
      expect(isDangerousBashPattern("python -c*")).toBe(true)
    })

    test("flags node", () => {
      expect(isDangerousBashPattern("node")).toBe(true)
    })

    test("flags bash", () => {
      expect(isDangerousBashPattern("bash")).toBe(true)
    })

    test("flags ssh", () => {
      expect(isDangerousBashPattern("ssh")).toBe(true)
    })

    test("flags eval", () => {
      expect(isDangerousBashPattern("eval")).toBe(true)
    })

    test("flags xargs", () => {
      expect(isDangerousBashPattern("xargs")).toBe(true)
    })

    test("flags sudo", () => {
      expect(isDangerousBashPattern("sudo")).toBe(true)
    })

    test("is case-insensitive", () => {
      expect(isDangerousBashPattern("PYTHON")).toBe(true)
      expect(isDangerousBashPattern("Python")).toBe(true)
    })

    test("allows safe patterns", () => {
      expect(isDangerousBashPattern("git status")).toBe(false)
      expect(isDangerousBashPattern("ls -la")).toBe(false)
      expect(isDangerousBashPattern("grep pattern")).toBe(false)
      expect(isDangerousBashPattern("cat file.txt")).toBe(false)
    })

    test("allows specific git patterns", () => {
      expect(isDangerousBashPattern("git *")).toBe(false)
      expect(isDangerousBashPattern("git:*")).toBe(false)
    })

    test("handles whitespace in pattern", () => {
      expect(isDangerousBashPattern("  python  ")).toBe(true)
    })
  })

  // ─── isDangerousPowerShellPattern ──────────────────────────────────

  describe("isDangerousPowerShellPattern", () => {
    test("flags wildcard *", () => {
      expect(isDangerousPowerShellPattern("*")).toBe(true)
    })

    test("flags powershell", () => {
      expect(isDangerousPowerShellPattern("powershell")).toBe(true)
    })

    test("flags pwsh", () => {
      expect(isDangerousPowerShellPattern("pwsh")).toBe(true)
    })

    test("flags cmd", () => {
      expect(isDangerousPowerShellPattern("cmd")).toBe(true)
    })

    test("flags cmd.exe", () => {
      expect(isDangerousPowerShellPattern("cmd.exe")).toBe(true)
    })

    test("flags Invoke-Expression", () => {
      expect(isDangerousPowerShellPattern("Invoke-Expression")).toBe(true)
    })

    test("flags iex", () => {
      expect(isDangerousPowerShellPattern("iex")).toBe(true)
    })

    test("flags Start-Process", () => {
      expect(isDangerousPowerShellPattern("Start-Process")).toBe(true)
    })

    test("flags python.exe variants", () => {
      expect(isDangerousPowerShellPattern("python.exe")).toBe(true)
      expect(isDangerousPowerShellPattern("python.exe *")).toBe(true)
      expect(isDangerousPowerShellPattern("python.exe:*")).toBe(true)
    })

    test("flags node.exe", () => {
      expect(isDangerousPowerShellPattern("node.exe")).toBe(true)
    })

    test("is case-insensitive", () => {
      expect(isDangerousPowerShellPattern("POWERSHELL")).toBe(true)
      expect(isDangerousPowerShellPattern("IEX")).toBe(true)
    })

    test("allows safe patterns", () => {
      expect(isDangerousPowerShellPattern("Get-ChildItem")).toBe(false)
      expect(isDangerousPowerShellPattern("Get-Content")).toBe(false)
    })
  })

  // ─── isDangerousRule ───────────────────────────────────────────────

  describe("isDangerousRule", () => {
    test("flags bash allow * rule", () => {
      expect(
        isDangerousRule({ permission: "bash", pattern: "*", action: "allow" }),
      ).toBe(true)
    })

    test("flags bash allow python:* rule", () => {
      expect(
        isDangerousRule({ permission: "bash", pattern: "python:*", action: "allow" }),
      ).toBe(true)
    })

    test("does not flag deny rules", () => {
      expect(
        isDangerousRule({ permission: "bash", pattern: "*", action: "deny" }),
      ).toBe(false)
    })

    test("does not flag ask rules", () => {
      expect(
        isDangerousRule({ permission: "bash", pattern: "*", action: "ask" }),
      ).toBe(false)
    })

    test("does not flag non-bash permissions", () => {
      expect(
        isDangerousRule({ permission: "edit", pattern: "*", action: "allow" }),
      ).toBe(false)
    })

    test("flags powershell allow * rule", () => {
      expect(
        isDangerousRule({ permission: "powershell", pattern: "*", action: "allow" }),
      ).toBe(true)
    })

    test("flags powershell allow iex rule", () => {
      expect(
        isDangerousRule({ permission: "powershell", pattern: "iex", action: "allow" }),
      ).toBe(true)
    })

    test("allows safe bash allow rule", () => {
      expect(
        isDangerousRule({ permission: "bash", pattern: "git status", action: "allow" }),
      ).toBe(false)
    })
  })

  // ─── stripDangerousRules ───────────────────────────────────────────

  describe("stripDangerousRules", () => {
    test("removes dangerous rules", () => {
      const rules = [
        { permission: "bash", pattern: "*", action: "allow" },
        { permission: "bash", pattern: "git status", action: "allow" },
        { permission: "bash", pattern: "python *", action: "allow" },
        { permission: "edit", pattern: "*", action: "allow" },
      ]
      const result = stripDangerousRules(rules)
      expect(result).toHaveLength(2)
      expect(result).toEqual([
        { permission: "bash", pattern: "git status", action: "allow" },
        { permission: "edit", pattern: "*", action: "allow" },
      ])
    })

    test("returns same reference when no changes", () => {
      const rules = [
        { permission: "bash", pattern: "git status", action: "allow" },
        { permission: "edit", pattern: "*", action: "allow" },
      ]
      const result = stripDangerousRules(rules)
      expect(result).toBe(rules) // Same reference
    })

    test("handles empty array", () => {
      const result = stripDangerousRules([])
      expect(result).toEqual([])
    })

    test("preserves deny rules", () => {
      const rules = [
        { permission: "bash", pattern: "*", action: "deny" },
        { permission: "bash", pattern: "python *", action: "deny" },
      ]
      const result = stripDangerousRules(rules)
      expect(result).toHaveLength(2)
    })
  })

  // ─── findDangerousRules ────────────────────────────────────────────

  describe("findDangerousRules", () => {
    test("finds all dangerous rules", () => {
      const rules = [
        { permission: "bash", pattern: "*", action: "allow" },
        { permission: "bash", pattern: "git status", action: "allow" },
        { permission: "bash", pattern: "python *", action: "allow" },
        { permission: "edit", pattern: "*", action: "allow" },
      ]
      const dangerous = findDangerousRules(rules)
      expect(dangerous).toHaveLength(2)
      expect(dangerous[0]!.pattern).toBe("*")
      expect(dangerous[1]!.pattern).toBe("python *")
    })

    test("returns empty for safe ruleset", () => {
      const rules = [
        { permission: "bash", pattern: "git *", action: "allow" },
        { permission: "edit", pattern: "*", action: "allow" },
      ]
      const dangerous = findDangerousRules(rules)
      expect(dangerous).toHaveLength(0)
    })
  })
})
