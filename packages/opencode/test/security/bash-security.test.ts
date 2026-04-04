import { describe, expect, test } from "bun:test"
import { validateBashCommand } from "../../src/security/bash-security"

describe("bash-security", () => {
  // ─── Safe Commands ─────────────────────────────────────────────────

  describe("safe commands", () => {
    test("allows simple ls", () => {
      expect(validateBashCommand("ls").safe).toBe(true)
    })

    test("allows git status", () => {
      expect(validateBashCommand("git status").safe).toBe(true)
    })

    test("allows echo with simple args", () => {
      expect(validateBashCommand("echo hello world").safe).toBe(true)
    })

    test("allows cat with file path", () => {
      expect(validateBashCommand("cat /tmp/file.txt").safe).toBe(true)
    })

    test("allows empty command", () => {
      expect(validateBashCommand("").safe).toBe(true)
    })

    test("allows whitespace-only command", () => {
      expect(validateBashCommand("   ").safe).toBe(true)
    })

    test("allows grep with quoted pattern", () => {
      expect(validateBashCommand("grep 'pattern' file.txt").safe).toBe(true)
    })

    test("allows command with safe 2>&1 redirection", () => {
      // Note: 2>&1 is stripped by stripSafeRedirections, but > in unquoted
      // content is still flagged by validateRedirections. However, the order
      // of stripping means 2>&1 is removed first.
      // Actually, the validators check fullyUnquotedContent which has safe
      // redirections stripped. So `command 2>&1` should pass.
      const result = validateBashCommand("ls 2>&1")
      // This should be safe because 2>&1 is stripped
      expect(result.safe).toBe(true)
    })
  })

  // ─── Control Characters ────────────────────────────────────────────

  describe("control characters", () => {
    test("blocks null byte", () => {
      const result = validateBashCommand("ls\x00hidden")
      expect(result.safe).toBe(false)
      if (!result.safe) expect(result.isMisparsing).toBe(true)
    })

    test("blocks bell character", () => {
      const result = validateBashCommand("echo\x07test")
      expect(result.safe).toBe(false)
    })

    test("blocks backspace", () => {
      const result = validateBashCommand("ls\x08hidden")
      expect(result.safe).toBe(false)
    })

    test("blocks escape character", () => {
      const result = validateBashCommand("echo\x1Btest")
      expect(result.safe).toBe(false)
    })

    test("blocks DEL character", () => {
      const result = validateBashCommand("echo\x7Ftest")
      expect(result.safe).toBe(false)
    })

    test("allows tab character", () => {
      // Tab is excluded from the control char check
      const result = validateBashCommand("echo\thello")
      expect(result.safe).toBe(true)
    })
  })

  // ─── Command Substitution ──────────────────────────────────────────

  describe("command substitution", () => {
    test("blocks unquoted backticks", () => {
      const result = validateBashCommand("echo `whoami`")
      expect(result.safe).toBe(false)
      if (!result.safe) expect(result.isMisparsing).toBe(true)
    })

    test("blocks $() substitution", () => {
      const result = validateBashCommand("echo $(whoami)")
      expect(result.safe).toBe(false)
    })

    test("blocks ${} parameter substitution", () => {
      const result = validateBashCommand("echo ${PATH}")
      expect(result.safe).toBe(false)
    })

    test("blocks process substitution <()", () => {
      const result = validateBashCommand("diff <(ls) file.txt")
      expect(result.safe).toBe(false)
    })

    test("blocks process substitution >()", () => {
      const result = validateBashCommand("tee >(cat)")
      expect(result.safe).toBe(false)
    })

    test("blocks $[] arithmetic", () => {
      const result = validateBashCommand("echo $[1+1]")
      expect(result.safe).toBe(false)
    })

    test("allows backticks inside single quotes (protected)", () => {
      // Single-quoted backticks are stripped from unquotedContent
      const result = validateBashCommand("echo 'hello `world`'")
      expect(result.safe).toBe(true)
    })
  })

  // ─── Redirections ──────────────────────────────────────────────────

  describe("redirections", () => {
    test("blocks output redirection >", () => {
      const result = validateBashCommand("echo hello > /tmp/file")
      expect(result.safe).toBe(false)
      if (!result.safe) expect(result.isMisparsing).toBe(false) // Real concern, not misparsing
    })

    test("blocks input redirection <", () => {
      const result = validateBashCommand("cat < /etc/passwd")
      expect(result.safe).toBe(false)
    })

    test("allows > inside single quotes", () => {
      const result = validateBashCommand("echo 'a > b'")
      expect(result.safe).toBe(true)
    })

    test("allows > inside double quotes", () => {
      const result = validateBashCommand('echo "a > b"')
      expect(result.safe).toBe(true)
    })

    test("allows safe /dev/null redirection", () => {
      const result = validateBashCommand("ls > /dev/null")
      // Note: > /dev/null is stripped by stripSafeRedirections
      expect(result.safe).toBe(true)
    })

    test("allows 2>/dev/null", () => {
      const result = validateBashCommand("ls 2>/dev/null")
      expect(result.safe).toBe(true)
    })
  })

  // ─── Newlines ──────────────────────────────────────────────────────

  describe("newlines", () => {
    test("blocks newline followed by command", () => {
      const result = validateBashCommand("ls\nrm -rf /")
      expect(result.safe).toBe(false)
    })

    test("allows safe backslash-newline continuation", () => {
      // Backslash-newline at word boundary is a safe continuation
      const result = validateBashCommand("ls \\\n-la")
      // This depends on the regex — backslash-newline preceded by whitespace
      // The regex checks for (?<![\s]\\)[\n\r]\s*\S
      // "ls \\\n-la" → fullyUnquotedPreStrip would have the newline
      // The negative lookbehind checks for whitespace+backslash before newline
      // Actually " \\" has space then backslash, so the lookbehind matches
      // and the newline is NOT flagged → safe
      expect(result.safe).toBe(true)
    })
  })

  // ─── Carriage Return ──────────────────────────────────────────────

  describe("carriage return", () => {
    test("blocks CR outside quotes", () => {
      const result = validateBashCommand("ls\rmalicious")
      expect(result.safe).toBe(false)
      if (!result.safe) expect(result.isMisparsing).toBe(true)
    })

    test("allows CR inside double quotes", () => {
      const result = validateBashCommand('echo "hello\rworld"')
      expect(result.safe).toBe(true)
    })

    test("blocks CR inside single quotes (still outside double quotes)", () => {
      // CR inside single quotes is still flagged because the check
      // specifically looks for CR outside double quotes (not single quotes)
      const result = validateBashCommand("echo 'hello\rworld'")
      expect(result.safe).toBe(false)
    })
  })

  // ─── Unicode Whitespace ────────────────────────────────────────────

  describe("unicode whitespace", () => {
    test("blocks non-breaking space", () => {
      const result = validateBashCommand("echo\u00A0hello")
      expect(result.safe).toBe(false)
      if (!result.safe) expect(result.isMisparsing).toBe(true)
    })

    test("blocks em space", () => {
      const result = validateBashCommand("echo\u2003hello")
      expect(result.safe).toBe(false)
    })

    test("blocks zero-width no-break space (BOM)", () => {
      const result = validateBashCommand("echo\uFEFFhello")
      expect(result.safe).toBe(false)
    })

    test("blocks ideographic space", () => {
      const result = validateBashCommand("echo\u3000hello")
      expect(result.safe).toBe(false)
    })
  })

  // ─── IFS Injection ────────────────────────────────────────────────

  describe("IFS injection", () => {
    test("blocks $IFS usage", () => {
      const result = validateBashCommand("cat$IFS/etc/passwd")
      expect(result.safe).toBe(false)
      if (!result.safe) expect(result.isMisparsing).toBe(true)
    })

    test("blocks ${IFS} usage", () => {
      const result = validateBashCommand("cat${IFS}/etc/passwd")
      expect(result.safe).toBe(false)
    })
  })

  // ─── Brace Expansion ──────────────────────────────────────────────

  describe("brace expansion", () => {
    test("blocks {a,b} pattern", () => {
      const result = validateBashCommand("echo {a,b}")
      expect(result.safe).toBe(false)
    })

    test("blocks {1..5} range", () => {
      const result = validateBashCommand("echo {1..5}")
      expect(result.safe).toBe(false)
    })

    test("allows braces inside quotes", () => {
      const result = validateBashCommand("echo '{a,b}'")
      expect(result.safe).toBe(true)
    })
  })

  // ─── Zsh Dangerous Commands ────────────────────────────────────────

  describe("zsh dangerous commands", () => {
    test("blocks zmodload", () => {
      const result = validateBashCommand("zmodload zsh/net/tcp")
      expect(result.safe).toBe(false)
    })

    test("blocks zpty", () => {
      const result = validateBashCommand("zpty test command")
      expect(result.safe).toBe(false)
    })

    test("blocks ztcp", () => {
      const result = validateBashCommand("ztcp host 80")
      expect(result.safe).toBe(false)
    })

    test("blocks fc -e", () => {
      const result = validateBashCommand("fc -e vi")
      expect(result.safe).toBe(false)
    })
  })

  // ─── Obfuscated Flags ─────────────────────────────────────────────

  describe("obfuscated flags", () => {
    test("blocks ANSI-C quoting with hex escape", () => {
      const result = validateBashCommand("grep $'\\x2d'e pattern file")
      expect(result.safe).toBe(false)
      if (!result.safe) expect(result.isMisparsing).toBe(true)
    })

    test("blocks locale-dependent quoting $\"...\"", () => {
      const result = validateBashCommand('echo $"hello"')
      expect(result.safe).toBe(false)
    })

    test("blocks empty quote pairs for flag obfuscation", () => {
      const result = validateBashCommand("grep --''exec pattern")
      expect(result.safe).toBe(false)
    })
  })

  // ─── Shell Metacharacters ──────────────────────────────────────────

  describe("shell metacharacters", () => {
    test("blocks unquoted semicolons in arguments", () => {
      const result = validateBashCommand("echo hello; rm -rf /")
      expect(result.safe).toBe(false)
      if (!result.safe) expect(result.isMisparsing).toBe(false)
    })

    test("blocks unquoted pipe in arguments", () => {
      const result = validateBashCommand("cat file | sh")
      expect(result.safe).toBe(false)
    })

    test("blocks unquoted ampersand in arguments", () => {
      const result = validateBashCommand("echo test & malicious")
      expect(result.safe).toBe(false)
    })
  })

  // ─── Dangerous Variables ───────────────────────────────────────────

  describe("dangerous variables", () => {
    test("blocks variable in redirection target", () => {
      const result = validateBashCommand("echo data > $OUTPUT")
      expect(result.safe).toBe(false)
    })

    test("blocks variable piped to command", () => {
      const result = validateBashCommand("$cmd | sh")
      expect(result.safe).toBe(false)
    })
  })

  // ─── Comment-Quote Desync ──────────────────────────────────────────

  describe("comment-quote desync", () => {
    test("blocks # comment with quote characters", () => {
      const result = validateBashCommand("echo hello # that's a comment")
      expect(result.safe).toBe(false)
      if (!result.safe) expect(result.isMisparsing).toBe(true)
    })

    test("allows # inside quotes", () => {
      const result = validateBashCommand("echo 'hello # world'")
      expect(result.safe).toBe(true)
    })
  })

  // ─── Backslash-Escaped Whitespace ──────────────────────────────────

  describe("backslash-escaped whitespace", () => {
    test("blocks backslash-space outside quotes", () => {
      const result = validateBashCommand("ls /path\\ to/file")
      expect(result.safe).toBe(false)
      if (!result.safe) expect(result.isMisparsing).toBe(true)
    })

    test("blocks backslash-tab outside quotes", () => {
      const result = validateBashCommand("ls /path\\\tto/file")
      expect(result.safe).toBe(false)
    })
  })

  // ─── Backslash-Escaped Operators ───────────────────────────────────

  describe("backslash-escaped operators", () => {
    test("blocks backslash-semicolon", () => {
      const result = validateBashCommand("echo hello\\; rm -rf /")
      expect(result.safe).toBe(false)
    })

    test("blocks backslash-pipe", () => {
      const result = validateBashCommand("echo hello\\| sh")
      expect(result.safe).toBe(false)
    })

    test("blocks backslash-ampersand", () => {
      const result = validateBashCommand("echo hello\\& bg")
      expect(result.safe).toBe(false)
    })
  })

  // ─── Mid-Word Hash ─────────────────────────────────────────────────

  describe("mid-word hash", () => {
    test("blocks mid-word # outside quotes", () => {
      const result = validateBashCommand("echo hello#world")
      expect(result.safe).toBe(false)
      if (!result.safe) expect(result.isMisparsing).toBe(true)
    })

    test("allows # preceded by space (comment)", () => {
      // A real comment with no quotes should be allowed
      const result = validateBashCommand("echo hello #safe")
      // Actually, this is "# followed by s" — the check looks for quote chars in the rest
      // Since "safe" has no quotes, this should pass the comment-quote check
      // But the mid-word hash check is \S(?<!\$\{)# — "#safe" preceded by space " " → \s
      // So this is NOT mid-word hash
      expect(result.safe).toBe(true)
    })
  })

  // ─── /proc/*/environ ───────────────────────────────────────────────

  describe("/proc/*/environ access", () => {
    test("blocks /proc/self/environ", () => {
      const result = validateBashCommand("cat /proc/self/environ")
      expect(result.safe).toBe(false)
      if (!result.safe) expect(result.isMisparsing).toBe(false) // Real concern
    })

    test("blocks /proc/1/environ", () => {
      const result = validateBashCommand("cat /proc/1/environ")
      expect(result.safe).toBe(false)
    })

    test("allows /proc/self/status", () => {
      const result = validateBashCommand("cat /proc/self/status")
      expect(result.safe).toBe(true)
    })
  })

  // ─── Priority: Misparsing vs Non-Misparsing ───────────────────────

  describe("priority handling", () => {
    test("misparsing result takes priority over non-misparsing", () => {
      // Command with both redirections (non-misparsing) and IFS (misparsing)
      const result = validateBashCommand("cat$IFS/etc > /tmp/out")
      expect(result.safe).toBe(false)
      if (!result.safe) {
        // IFS injection (misparsing) should take priority
        expect(result.isMisparsing).toBe(true)
      }
    })
  })
})
