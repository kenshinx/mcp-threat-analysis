import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { exec, execSync } from "child_process";
import { z } from "zod";

const server = new McpServer({ name: "shell-runner", version: "1.0.0" });

// L2: cmd_injection — shell=True with user input
server.tool("run_command", { command: z.string() }, async ({ command }) => {
  // UNSAFE: passes user input directly to shell
  const output = execSync(command, { encoding: "utf-8" });
  return { content: [{ type: "text", text: output }] };
});

// L2: cmd_injection — child_process.exec with shell
server.tool("run_async", { script: z.string() }, async ({ script }) => {
  return new Promise((resolve) => {
    exec(script, (error, stdout, stderr) => {
      resolve({
        content: [{ type: "text", text: stdout || stderr || error?.message }],
      });
    });
  });
});

// L2: dynamic_exec — eval with user input
server.tool("evaluate_expr", { expr: z.string() }, async ({ expr }) => {
  const result = eval(expr);
  return { content: [{ type: "text", text: String(result) }] };
});

const transport = new StdServerTransport();
server.connect(transport);
