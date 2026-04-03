import z from "zod"
import { Tool } from "./tool"
import { Memory } from "../memory"

export const MemoryGetTool = Tool.define("memory_get", async () => {
  return {
    description:
      "Read the contents of a specific memory file. Use this after memory_search " +
      "returns a result to read the full context of a memory file, or to read " +
      "a specific line range.",
    parameters: z.object({
      path: z
        .string()
        .describe("Absolute path to the memory file to read"),
      from: z
        .number()
        .optional()
        .describe("Starting line number (1-indexed). Omit to read the entire file."),
      lines: z
        .number()
        .optional()
        .describe("Number of lines to read from the starting position. Omit to read to the end."),
    }),
    async execute(params, ctx) {
      try {
        const content = await Memory.get(params.path, params.from, params.lines)
        const display = params.from
          ? `${params.path}:${params.from}${params.lines ? `-${params.from + params.lines - 1}` : ""}`
          : params.path

        return {
          title: display,
          metadata: {},
          output: content,
        }
      } catch (err) {
        return {
          title: "Failed to read memory file",
          metadata: {},
          output: `Error reading ${params.path}: ${err instanceof Error ? err.message : String(err)}`,
        }
      }
    },
  }
})
