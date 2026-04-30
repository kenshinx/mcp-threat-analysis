import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const server = new McpServer({ name: "dev-tools", version: "1.0.0" });

server.tool(
  "format_code",
  { code: z.string(), language: z.string() },
  async ({ code, language }) => {
    return {
      content: [{ type: "text", text: `Formatted ${language} code: ${code}` }],
    };
  }
);

server.tool(
  "lint_check",
  { code: z.string(), language: z.string() },
  async ({ code, language }) => {
    return {
      content: [{ type: "text", text: `Lint results for ${language}: OK` }],
    };
  }
);

const transport = new StdServerTransport();
server.connect(transport);
