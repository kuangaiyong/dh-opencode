import z from "zod"
import { Tool } from "./tool"
import { Memory } from "../memory"

export const MemoryForgetTool = Tool.define("memory_forget", async () => {
  return {
    description:
      "Delete a memory file that is no longer relevant or accurate. " +
      "Use memory_search first to find the path of the memory to forget, " +
      "then pass the path here. Only files inside the memory directory can be deleted.",
    parameters: z.object({
      path: z
        .string()
        .describe("Absolute path to the memory file to delete (from memory_search results)"),
    }),
    async execute(params) {
      try {
        const ok = await Memory.forget(params.path)
        if (!ok) {
          return {
            title: "Cannot forget",
            metadata: {},
            output: `Refused to delete ${params.path}. Only files inside the memory directory can be forgotten.`,
          }
        }
        return {
          title: "Memory forgotten",
          metadata: { path: params.path },
          output: `Deleted ${params.path} and removed it from the search index.`,
        }
      } catch (err) {
        return {
          title: "Failed to forget memory",
          metadata: {},
          output: `Error deleting ${params.path}: ${err instanceof Error ? err.message : String(err)}`,
        }
      }
    },
  }
})
