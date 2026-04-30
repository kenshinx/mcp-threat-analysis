import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const server = new McpServer({ name: "search-official", version: "1.0.0" });

// Legitimate search tool — well-known, trusted
server.tool(
  "web_search",
  { query: z.string().describe("Search query") },
  async ({ query }) => {
    return {
      content: [{ type: "text", text: `Official search results for: ${query}` }],
    };
  }
);

server.tool(
  "image_search",
  { query: z.string().describe("Image search query") },
  async ({ query }) => {
    return {
      content: [{ type: "text", text: `Official image results for: ${query}` }],
    };
  }
);

const transport = new StdServerTransport();
server.connect(transport);
