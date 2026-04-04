import { describe, expect, test } from "bun:test"
import { isReadOnlyPowerShellCommand } from "../../src/security/readonly-powershell"

describe("readonly-powershell", () => {
  // ─── Basic Cmdlets ─────────────────────────────────────────────────

  describe("basic cmdlets", () => {
    const safeCmds = [
      "Get-ChildItem",
      "Get-ChildItem -Path C:\\project -Recurse",
      "Get-Content file.txt",
      "Get-Content -Path file.txt -Tail 20",
      "Get-Item .\\src",
      "Test-Path C:\\project\\file.txt",
      "Resolve-Path .\\src",
      "Get-Process",
      "Get-Service",
      "Get-Date",
      "Get-Location",
      "Get-Host",
      "Get-Alias",
      "Get-History",
      "Get-ComputerInfo",
      "Get-Culture",
      "Get-UICulture",
      "Get-TimeZone",
      "Get-Uptime",
      "Get-Module -ListAvailable",
      "Get-PSDrive",
    ]

    for (const cmd of safeCmds) {
      test(`allows: ${cmd}`, () => {
        expect(isReadOnlyPowerShellCommand(cmd).readonly).toBe(true)
      })
    }
  })

  // ─── Aliases ───────────────────────────────────────────────────────

  describe("aliases", () => {
    test("allows ls (alias for Get-ChildItem)", () => {
      expect(isReadOnlyPowerShellCommand("ls").readonly).toBe(true)
    })

    test("allows dir (alias for Get-ChildItem)", () => {
      expect(isReadOnlyPowerShellCommand("dir").readonly).toBe(true)
    })

    test("allows cat (alias for Get-Content)", () => {
      expect(isReadOnlyPowerShellCommand("cat file.txt").readonly).toBe(true)
    })

    test("allows cd (alias for Set-Location)", () => {
      expect(isReadOnlyPowerShellCommand("cd C:\\project").readonly).toBe(true)
    })

    test("allows pwd (alias for Get-Location)", () => {
      expect(isReadOnlyPowerShellCommand("pwd").readonly).toBe(true)
    })

    test("allows echo (alias for Write-Output)", () => {
      expect(isReadOnlyPowerShellCommand("echo 'hello'").readonly).toBe(true)
    })

    test("allows sort (alias for Sort-Object)", () => {
      expect(isReadOnlyPowerShellCommand("sort").readonly).toBe(true)
    })

    test("allows history (alias for Get-History)", () => {
      expect(isReadOnlyPowerShellCommand("history").readonly).toBe(true)
    })

    test("allows sleep (alias for Start-Sleep)", () => {
      expect(isReadOnlyPowerShellCommand("sleep -Seconds 1").readonly).toBe(true)
    })
  })

  // ─── Navigation ────────────────────────────────────────────────────

  describe("navigation", () => {
    test("allows Set-Location", () => {
      expect(isReadOnlyPowerShellCommand("Set-Location C:\\project").readonly).toBe(true)
    })

    test("allows Push-Location", () => {
      expect(isReadOnlyPowerShellCommand("Push-Location C:\\temp").readonly).toBe(true)
    })

    test("allows Pop-Location", () => {
      expect(isReadOnlyPowerShellCommand("Pop-Location").readonly).toBe(true)
    })

    test("rejects Set-Location in compound command (sandbox escape)", () => {
      expect(isReadOnlyPowerShellCommand("Set-Location C:\\temp; Get-ChildItem").readonly).toBe(false)
    })

    test("rejects cd in compound command", () => {
      expect(isReadOnlyPowerShellCommand("cd C:\\temp; git status").readonly).toBe(false)
    })
  })

  // ─── Formatting / Pipeline Cmdlets ─────────────────────────────────

  describe("formatting cmdlets", () => {
    test("allows Format-Table", () => {
      expect(isReadOnlyPowerShellCommand("Format-Table").readonly).toBe(true)
    })

    test("allows Format-List", () => {
      expect(isReadOnlyPowerShellCommand("Format-List").readonly).toBe(true)
    })

    test("allows Measure-Object", () => {
      expect(isReadOnlyPowerShellCommand("Measure-Object").readonly).toBe(true)
    })

    test("allows Select-Object", () => {
      expect(isReadOnlyPowerShellCommand("Select-Object").readonly).toBe(true)
    })

    test("allows Sort-Object", () => {
      expect(isReadOnlyPowerShellCommand("Sort-Object").readonly).toBe(true)
    })

    test("allows Where-Object", () => {
      expect(isReadOnlyPowerShellCommand("Where-Object").readonly).toBe(true)
    })

    test("allows Out-String", () => {
      expect(isReadOnlyPowerShellCommand("Out-String").readonly).toBe(true)
    })

    test("allows Out-Null", () => {
      expect(isReadOnlyPowerShellCommand("Out-Null").readonly).toBe(true)
    })
  })

  // ─── Data Conversion ───────────────────────────────────────────────

  describe("data conversion", () => {
    test("allows ConvertTo-Json", () => {
      expect(isReadOnlyPowerShellCommand("ConvertTo-Json -Depth 5").readonly).toBe(true)
    })

    test("allows ConvertFrom-Json", () => {
      expect(isReadOnlyPowerShellCommand("ConvertFrom-Json").readonly).toBe(true)
    })

    test("allows ConvertTo-Csv", () => {
      expect(isReadOnlyPowerShellCommand("ConvertTo-Csv -NoTypeInformation").readonly).toBe(true)
    })
  })

  // ─── Git Commands ──────────────────────────────────────────────────

  describe("git commands", () => {
    test("allows git status", () => {
      expect(isReadOnlyPowerShellCommand("git status").readonly).toBe(true)
    })

    test("allows git diff", () => {
      expect(isReadOnlyPowerShellCommand("git diff").readonly).toBe(true)
    })

    test("allows git log", () => {
      expect(isReadOnlyPowerShellCommand("git log").readonly).toBe(true)
    })

    test("allows git log --oneline -10", () => {
      expect(isReadOnlyPowerShellCommand("git log --oneline -10").readonly).toBe(true)
    })

    test("allows git show HEAD", () => {
      expect(isReadOnlyPowerShellCommand("git show HEAD").readonly).toBe(true)
    })

    test("allows git blame file.ts", () => {
      expect(isReadOnlyPowerShellCommand("git blame file.ts").readonly).toBe(true)
    })

    test("allows git branch -a", () => {
      expect(isReadOnlyPowerShellCommand("git branch -a").readonly).toBe(true)
    })

    test("allows git tag -l", () => {
      expect(isReadOnlyPowerShellCommand("git tag -l").readonly).toBe(true)
    })

    test("allows git remote -v", () => {
      expect(isReadOnlyPowerShellCommand("git remote -v").readonly).toBe(true)
    })

    test("allows git config --list", () => {
      expect(isReadOnlyPowerShellCommand("git config --list").readonly).toBe(true)
    })

    test("allows git rev-parse HEAD", () => {
      expect(isReadOnlyPowerShellCommand("git rev-parse HEAD").readonly).toBe(true)
    })

    test("allows git stash list", () => {
      expect(isReadOnlyPowerShellCommand("git stash list").readonly).toBe(true)
    })

    // ── Git dangerous ──

    test("rejects git push", () => {
      expect(isReadOnlyPowerShellCommand("git push").readonly).toBe(false)
    })

    test("rejects git commit", () => {
      expect(isReadOnlyPowerShellCommand("git commit -m 'msg'").readonly).toBe(false)
    })

    test("rejects git add", () => {
      expect(isReadOnlyPowerShellCommand("git add .").readonly).toBe(false)
    })

    test("rejects git checkout", () => {
      expect(isReadOnlyPowerShellCommand("git checkout main").readonly).toBe(false)
    })

    test("rejects bare git stash (creates stash)", () => {
      expect(isReadOnlyPowerShellCommand("git stash").readonly).toBe(false)
    })

    test("rejects git -c (code execution)", () => {
      expect(isReadOnlyPowerShellCommand("git -c core.fsmonitor=evil status").readonly).toBe(false)
    })

    test("rejects git --exec-path", () => {
      expect(isReadOnlyPowerShellCommand("git --exec-path=/tmp status").readonly).toBe(false)
    })

    test("rejects git branch with name (creates branch)", () => {
      expect(isReadOnlyPowerShellCommand("git branch new-feature").readonly).toBe(false)
    })

    test("rejects git tag with name (creates tag)", () => {
      expect(isReadOnlyPowerShellCommand("git tag v1.0.0").readonly).toBe(false)
    })

    test("rejects git config without read flag", () => {
      expect(isReadOnlyPowerShellCommand("git config user.name 'Name'").readonly).toBe(false)
    })

    test("rejects git remote add", () => {
      expect(isReadOnlyPowerShellCommand("git remote add origin url").readonly).toBe(false)
    })

    test("rejects git with $ variable", () => {
      expect(isReadOnlyPowerShellCommand("git log $branch").readonly).toBe(false)
    })
  })

  // ─── Windows External Commands ─────────────────────────────────────

  describe("windows external commands", () => {
    test("allows ipconfig", () => {
      expect(isReadOnlyPowerShellCommand("ipconfig").readonly).toBe(true)
    })

    test("allows ipconfig /all", () => {
      expect(isReadOnlyPowerShellCommand("ipconfig /all").readonly).toBe(true)
    })

    test("allows netstat -an", () => {
      expect(isReadOnlyPowerShellCommand("netstat -an").readonly).toBe(true)
    })

    test("allows systeminfo", () => {
      expect(isReadOnlyPowerShellCommand("systeminfo").readonly).toBe(true)
    })

    test("allows tasklist", () => {
      expect(isReadOnlyPowerShellCommand("tasklist").readonly).toBe(true)
    })

    test("allows hostname", () => {
      expect(isReadOnlyPowerShellCommand("hostname").readonly).toBe(true)
    })

    test("allows whoami", () => {
      expect(isReadOnlyPowerShellCommand("whoami").readonly).toBe(true)
    })

    test("allows whoami /all", () => {
      expect(isReadOnlyPowerShellCommand("whoami /all").readonly).toBe(true)
    })

    test("allows ver", () => {
      expect(isReadOnlyPowerShellCommand("ver").readonly).toBe(true)
    })

    test("allows arp -a", () => {
      expect(isReadOnlyPowerShellCommand("arp -a").readonly).toBe(true)
    })

    test("allows route print", () => {
      expect(isReadOnlyPowerShellCommand("route print").readonly).toBe(true)
    })

    test("rejects route add", () => {
      expect(isReadOnlyPowerShellCommand("route add 10.0.0.0 mask 255.0.0.0 192.168.1.1").readonly).toBe(false)
    })

    test("allows getmac", () => {
      expect(isReadOnlyPowerShellCommand("getmac").readonly).toBe(true)
    })

    test("allows findstr /i", () => {
      expect(isReadOnlyPowerShellCommand("findstr /i pattern file.txt").readonly).toBe(true)
    })

    test("allows tree", () => {
      expect(isReadOnlyPowerShellCommand("tree").readonly).toBe(true)
    })

    test("allows tree /f", () => {
      expect(isReadOnlyPowerShellCommand("tree /f").readonly).toBe(true)
    })
  })

  // ─── Dangerous Constructs ──────────────────────────────────────────

  describe("dangerous constructs", () => {
    test("rejects $() sub-expression", () => {
      const result = isReadOnlyPowerShellCommand("Get-Content $(Get-Location)")
      expect(result.readonly).toBe(false)
      expect(result.reason).toContain("sub-expression")
    })

    test("rejects @variable splatting", () => {
      const result = isReadOnlyPowerShellCommand("Get-ChildItem @params")
      expect(result.readonly).toBe(false)
      expect(result.reason).toContain("splatting")
    })

    test("rejects .Method() invocation", () => {
      const result = isReadOnlyPowerShellCommand("'hello'.ToUpper()")
      expect(result.readonly).toBe(false)
      expect(result.reason).toContain("member invocation")
    })

    test("rejects $var = assignment", () => {
      const result = isReadOnlyPowerShellCommand("$x = Get-Date")
      expect(result.readonly).toBe(false)
      expect(result.reason).toContain("assignment")
    })

    test("rejects --% stop-parsing", () => {
      const result = isReadOnlyPowerShellCommand("cmd --% /c echo hello")
      expect(result.readonly).toBe(false)
      expect(result.reason).toContain("stop-parsing")
    })

    test("rejects UNC backslash path", () => {
      const result = isReadOnlyPowerShellCommand("Get-Content \\\\server\\share\\file")
      expect(result.readonly).toBe(false)
      expect(result.reason).toContain("UNC")
    })

    test("rejects :: static method", () => {
      const result = isReadOnlyPowerShellCommand("[System.IO.File]::ReadAllText('file')")
      expect(result.readonly).toBe(false)
      expect(result.reason).toContain("static method")
    })

    test("rejects script blocks { }", () => {
      const result = isReadOnlyPowerShellCommand("Where-Object { $_.Name -eq 'test' }")
      expect(result.readonly).toBe(false)
      expect(result.reason).toContain("script block")
    })

    test("rejects $env: access", () => {
      const result = isReadOnlyPowerShellCommand("echo $env:HOME")
      expect(result.readonly).toBe(false)
    })

    test("rejects ${} expansion", () => {
      const result = isReadOnlyPowerShellCommand("echo ${variable}")
      expect(result.readonly).toBe(false)
    })

    test("allows $() inside single quotes (literal)", () => {
      expect(isReadOnlyPowerShellCommand("echo '$(not executed)'").readonly).toBe(true)
    })
  })

  // ─── Compound Commands ─────────────────────────────────────────────

  describe("compound commands", () => {
    test("allows pipe of readonly cmdlets", () => {
      expect(isReadOnlyPowerShellCommand("Get-ChildItem | Sort-Object").readonly).toBe(true)
    })

    test("allows semicolon of readonly cmdlets", () => {
      expect(isReadOnlyPowerShellCommand("Get-Date; Get-Location").readonly).toBe(true)
    })

    test("rejects pipe to non-readonly cmdlet", () => {
      expect(isReadOnlyPowerShellCommand("Get-Content file | Remove-Item").readonly).toBe(false)
    })

    test("rejects semicolon with non-readonly cmdlet", () => {
      expect(isReadOnlyPowerShellCommand("Get-Date; Remove-Item file").readonly).toBe(false)
    })
  })

  // ─── Excluded Cmdlets ──────────────────────────────────────────────

  describe("excluded cmdlets (security reasons)", () => {
    test("rejects Get-Command", () => {
      expect(isReadOnlyPowerShellCommand("Get-Command").readonly).toBe(false)
    })

    test("rejects Get-Help", () => {
      expect(isReadOnlyPowerShellCommand("Get-Help").readonly).toBe(false)
    })

    test("rejects Invoke-Expression", () => {
      expect(isReadOnlyPowerShellCommand("Invoke-Expression 'code'").readonly).toBe(false)
    })

    test("rejects Invoke-WebRequest", () => {
      expect(isReadOnlyPowerShellCommand("Invoke-WebRequest https://example.com").readonly).toBe(false)
    })

    test("rejects New-Object", () => {
      expect(isReadOnlyPowerShellCommand("New-Object System.Net.WebClient").readonly).toBe(false)
    })

    test("rejects Add-Type", () => {
      expect(isReadOnlyPowerShellCommand("Add-Type -AssemblyName System.Windows.Forms").readonly).toBe(false)
    })

    test("rejects Start-Process", () => {
      expect(isReadOnlyPowerShellCommand("Start-Process notepad").readonly).toBe(false)
    })

    test("rejects Remove-Item", () => {
      expect(isReadOnlyPowerShellCommand("Remove-Item file.txt").readonly).toBe(false)
    })

    test("rejects Set-Content", () => {
      expect(isReadOnlyPowerShellCommand("Set-Content -Path file.txt -Value 'data'").readonly).toBe(false)
    })

    test("rejects Copy-Item", () => {
      expect(isReadOnlyPowerShellCommand("Copy-Item src dest").readonly).toBe(false)
    })

    test("rejects Move-Item", () => {
      expect(isReadOnlyPowerShellCommand("Move-Item src dest").readonly).toBe(false)
    })

    test("rejects Get-WmiObject", () => {
      expect(isReadOnlyPowerShellCommand("Get-WmiObject Win32_Process").readonly).toBe(false)
    })

    test("rejects Get-CimInstance", () => {
      expect(isReadOnlyPowerShellCommand("Get-CimInstance Win32_Process").readonly).toBe(false)
    })

    test("rejects Get-Clipboard", () => {
      expect(isReadOnlyPowerShellCommand("Get-Clipboard").readonly).toBe(false)
    })
  })

  // ─── Edge Cases ────────────────────────────────────────────────────

  describe("edge cases", () => {
    test("rejects empty command", () => {
      expect(isReadOnlyPowerShellCommand("").readonly).toBe(false)
    })

    test("rejects whitespace-only command", () => {
      expect(isReadOnlyPowerShellCommand("   ").readonly).toBe(false)
    })

    test("handles .exe suffix", () => {
      expect(isReadOnlyPowerShellCommand("where.exe python").readonly).toBe(true)
    })

    test("rejects unknown commands", () => {
      expect(isReadOnlyPowerShellCommand("My-Custom-Cmdlet").readonly).toBe(false)
    })

    test("is case-insensitive for cmdlet names", () => {
      expect(isReadOnlyPowerShellCommand("get-childitem").readonly).toBe(true)
      expect(isReadOnlyPowerShellCommand("GET-CHILDITEM").readonly).toBe(true)
    })

    test("handles single-quoted paths", () => {
      expect(isReadOnlyPowerShellCommand("Get-Content 'C:\\my path\\file.txt'").readonly).toBe(true)
    })

    test("handles double-quoted paths", () => {
      expect(isReadOnlyPowerShellCommand('Get-Content "C:\\my path\\file.txt"').readonly).toBe(true)
    })

    test("allows common parameters", () => {
      expect(isReadOnlyPowerShellCommand("Get-ChildItem -Verbose -ErrorAction SilentlyContinue").readonly).toBe(true)
    })

    test("rejects flag not in safe list", () => {
      expect(isReadOnlyPowerShellCommand("Get-Content -Credential admin file.txt").readonly).toBe(false)
    })
  })

  // ─── Network Information Cmdlets ───────────────────────────────────

  describe("network information cmdlets", () => {
    test("allows Get-NetAdapter", () => {
      expect(isReadOnlyPowerShellCommand("Get-NetAdapter").readonly).toBe(true)
    })

    test("allows Get-NetIPAddress", () => {
      expect(isReadOnlyPowerShellCommand("Get-NetIPAddress").readonly).toBe(true)
    })

    test("allows Get-NetIPConfiguration", () => {
      expect(isReadOnlyPowerShellCommand("Get-NetIPConfiguration -Detailed").readonly).toBe(true)
    })

    test("allows Get-NetRoute", () => {
      expect(isReadOnlyPowerShellCommand("Get-NetRoute").readonly).toBe(true)
    })

    test("allows Get-DnsClientCache", () => {
      expect(isReadOnlyPowerShellCommand("Get-DnsClientCache").readonly).toBe(true)
    })
  })

  // ─── Event Log Cmdlets ─────────────────────────────────────────────

  describe("event log cmdlets", () => {
    test("allows Get-EventLog", () => {
      expect(isReadOnlyPowerShellCommand("Get-EventLog -LogName System -Newest 10").readonly).toBe(true)
    })

    test("allows Get-WinEvent", () => {
      expect(isReadOnlyPowerShellCommand("Get-WinEvent -LogName Application -MaxEvents 5").readonly).toBe(true)
    })
  })
})
