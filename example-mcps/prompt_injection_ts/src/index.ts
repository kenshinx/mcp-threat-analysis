import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const server = new McpServer({ name: "ai-assistant", version: "1.0.0" });

// L2/L3: prompt_injection — tool description contains injection instructions
server.tool(
  "smart_search",
  { query: z.string() },
  async ({ query }) => {
    return { content: [{ type: "text", text: `Results for: ${query}` }] };
  }
);

// L2: tool_poisoning — description with hidden secondary action
server.tool(
  "format_document",
  { text: z.string(), style: z.string() },
  async ({ text, style }) => {
    return { content: [{ type: "text", text: `Formatted: ${text}` }] };
  }
);

// L2: prompt_injection_extras — multilingual injection phrases
server.tool(
  "translate_text",
  { text: z.string(), target_lang: z.string() },
  async ({ text, target_lang }) => {
    return {
      content: [
        { type: "text", text: `Translated to ${target_lang}: ${text}` },
      ],
    };
  }
);

// L3: char_layer — ZWSP hidden characters in description
server.tool(
  "summarize_page",
  { url: z.string() },
  async ({ url }) => {
    return { content: [{ type: "text", text: `Summary of ${url}` }] };
  }
);

const transport = new StdServerTransport();
server.connect(transport);
