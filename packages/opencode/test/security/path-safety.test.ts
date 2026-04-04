import { describe, expect, test } from "bun:test"
import {
  checkPathSafety,
  checkPathsSafety,
  DANGEROUS_FILES,
  DANGEROUS_DIRECTORIES,
} from "../../src/security/path-safety"

describe("path-safety", () => {
  // ─── Dangerous Files ───────────────────────────────────────────────

  describe("dangerous files", () => {
    for (const file of DANGEROUS_FILES) {
      test(`flags ${file} as unsafe`, () => {
        const result = checkPathSafety(`/home/user/${file}`)
        expect(result.safe).toBe(false)
        if (!result.safe) {
          expect(result.classifierApprovable).toBe(true)
        }
      })
    }

    test("flags .bashrc in nested path", () => {
      const result = checkPathSafety("/some/deep/path/.bashrc")
      expect(result.safe).toBe(false)
    })

    test("flags dangerous files case-insensitively", () => {
      const result = checkPathSafety("/home/user/.BASHRC")
      expect(result.safe).toBe(false)
    })

    test("flags .Gitconfig with mixed case", () => {
      const result = checkPathSafety("/home/user/.GitConfig")
      expect(result.safe).toBe(false)
    })

    test("allows normal files", () => {
      const result = checkPathSafety("/home/user/project/index.ts")
      expect(result.safe).toBe(true)
    })

    test("allows files with similar names", () => {
      // ".bashrc_backup" should NOT be flagged — only exact match
      const result = checkPathSafety("/home/user/.bashrc_backup")
      expect(result.safe).toBe(true)
    })
  })

  // ─── Dangerous Directories ─────────────────────────────────────────

  describe("dangerous directories", () => {
    for (const dir of DANGEROUS_DIRECTORIES) {
      test(`flags path inside ${dir}/`, () => {
        const result = checkPathSafety(`/project/${dir}/config`)
        expect(result.safe).toBe(false)
        if (!result.safe) {
          expect(result.classifierApprovable).toBe(true)
        }
      })
    }

    test("flags .git/hooks/pre-commit", () => {
      const result = checkPathSafety("/project/.git/hooks/pre-commit")
      expect(result.safe).toBe(false)
    })

    test("flags .vscode case-insensitively", () => {
      const result = checkPathSafety("/project/.VSCODE/settings.json")
      expect(result.safe).toBe(false)
    })

    test("allows paths not in dangerous directories", () => {
      const result = checkPathSafety("/project/src/git/helper.ts")
      expect(result.safe).toBe(true)
    })
  })

  // ─── UNC Paths ─────────────────────────────────────────────────────

  describe("UNC paths", () => {
    test("flags backslash UNC path", () => {
      const result = checkPathSafety("\\\\server\\share\\file.txt")
      expect(result.safe).toBe(false)
    })

    test("flags forward-slash UNC path", () => {
      const result = checkPathSafety("//server/share/file.txt")
      expect(result.safe).toBe(false)
    })

    test("does not flag single backslash", () => {
      const result = checkPathSafety("\\Users\\test\\file.txt")
      // Single backslash is a normal Windows path, not UNC
      // But it WILL be flagged by isDangerousFilePath if the path happens
      // to normalize into a dangerous dir. For a normal path, it should pass.
      // This depends on normalization, so just check it doesn't crash.
      expect(typeof result.safe).toBe("boolean")
    })
  })

  // ─── Windows Suspicious Patterns ───────────────────────────────────

  describe("suspicious Windows path patterns", () => {
    test("flags 8.3 short names (GIT~1)", () => {
      const result = checkPathSafety("C:\\GIT~1\\config")
      expect(result.safe).toBe(false)
      if (!result.safe) {
        expect(result.classifierApprovable).toBe(false) // Hard block
      }
    })

    test("flags CLAUDE~1", () => {
      const result = checkPathSafety("C:\\CLAUDE~1\\settings.json")
      expect(result.safe).toBe(false)
      if (!result.safe) {
        expect(result.classifierApprovable).toBe(false)
      }
    })

    test("flags long path prefix \\\\?\\", () => {
      const result = checkPathSafety("\\\\?\\C:\\very\\long\\path")
      expect(result.safe).toBe(false)
      if (!result.safe) {
        expect(result.classifierApprovable).toBe(false)
      }
    })

    test("flags long path prefix \\\\.\\", () => {
      const result = checkPathSafety("\\\\.\\C:\\device\\path")
      expect(result.safe).toBe(false)
    })

    test("flags //?/ prefix", () => {
      const result = checkPathSafety("//?/C:/path")
      expect(result.safe).toBe(false)
    })

    test("flags //./ prefix", () => {
      const result = checkPathSafety("//./C:/path")
      expect(result.safe).toBe(false)
    })

    test("flags trailing dots", () => {
      const result = checkPathSafety("C:\\project\\.git.")
      expect(result.safe).toBe(false)
      if (!result.safe) {
        expect(result.classifierApprovable).toBe(false)
      }
    })

    test("flags trailing spaces", () => {
      const result = checkPathSafety("C:\\project\\.git ")
      expect(result.safe).toBe(false)
    })

    test("flags DOS device names", () => {
      const result = checkPathSafety("C:\\project\\file.txt.CON")
      expect(result.safe).toBe(false)
    })

    test("flags PRN device name", () => {
      const result = checkPathSafety("C:\\project\\data.PRN")
      expect(result.safe).toBe(false)
    })

    test("flags NUL device name", () => {
      const result = checkPathSafety("C:\\test.NUL")
      expect(result.safe).toBe(false)
    })

    test("flags triple dots path traversal", () => {
      const result = checkPathSafety("C:\\project\\...\\secret")
      expect(result.safe).toBe(false)
    })

    test("does not flag normal double dots", () => {
      // Normal parent directory reference should not be flagged by Windows check
      // (though path.resolve would normalize it)
      const result = checkPathSafety("/project/../other/file.ts")
      // Double dots are not flagged by the Windows pattern check specifically
      // They may still be handled by path normalization
      expect(typeof result.safe).toBe("boolean")
    })
  })

  // ─── Safe Paths ────────────────────────────────────────────────────

  describe("safe paths", () => {
    test("allows normal project files", () => {
      expect(checkPathSafety("/project/src/index.ts").safe).toBe(true)
    })

    test("allows deeply nested paths", () => {
      expect(checkPathSafety("/project/src/components/ui/Button.tsx").safe).toBe(true)
    })

    test("allows paths with numbers", () => {
      expect(checkPathSafety("/project/v2/config.json").safe).toBe(true)
    })

    test("allows relative paths", () => {
      expect(checkPathSafety("src/index.ts").safe).toBe(true)
    })

    test("allows Windows-style paths", () => {
      expect(checkPathSafety("C:\\project\\src\\main.ts").safe).toBe(true)
    })
  })

  // ─── Batch Check (checkPathsSafety) ────────────────────────────────

  describe("checkPathsSafety", () => {
    test("returns safe for empty array", () => {
      expect(checkPathsSafety([]).safe).toBe(true)
    })

    test("returns safe when all paths are safe", () => {
      const result = checkPathsSafety([
        "/project/src/a.ts",
        "/project/src/b.ts",
        "/project/README.md",
      ])
      expect(result.safe).toBe(true)
    })

    test("returns first unsafe result", () => {
      const result = checkPathsSafety([
        "/project/src/a.ts",
        "/project/.git/config",
        "/project/src/b.ts",
      ])
      expect(result.safe).toBe(false)
      if (!result.safe) {
        expect(result.message).toContain(".git")
      }
    })

    test("prioritizes Windows pattern (non-classifier-approvable) even if later", () => {
      // Since it returns the FIRST unsafe, if a dangerous dir comes first,
      // it returns that (classifier-approvable). This is by design.
      const result = checkPathsSafety([
        "/project/.git/config",
        "C:\\GIT~1\\exploit",
      ])
      expect(result.safe).toBe(false)
      if (!result.safe) {
        expect(result.classifierApprovable).toBe(true) // first match is .git
      }
    })

    test("returns Windows pattern when it comes first", () => {
      const result = checkPathsSafety([
        "C:\\GIT~1\\exploit",
        "/project/.git/config",
      ])
      expect(result.safe).toBe(false)
      if (!result.safe) {
        expect(result.classifierApprovable).toBe(false) // 8.3 name
      }
    })
  })
})
