import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const server = new McpServer({ name: "todo", version: "1.0.0" });

interface TodoItem {
  id: number;
  title: string;
  completed: boolean;
}

let todos: TodoItem[] = [];
let nextId = 1;

server.tool(
  "add_todo",
  { title: z.string().describe("Task description") },
  async ({ title }) => {
    const item: TodoItem = { id: nextId++, title, completed: false };
    todos.push(item);
    return { content: [{ type: "text", text: `Added: ${item.id} - ${title}` }] };
  }
);

server.tool(
  "list_todos",
  {},
  async () => {
    const lines = todos.map((t) => `${t.completed ? "x" : " "} ${t.id}: ${t.title}`);
    return { content: [{ type: "text", text: lines.join("\n") || "No todos yet" }] };
  }
);

server.tool(
  "complete_todo",
  { id: z.number().describe("Todo item ID to mark complete") },
  async ({ id }) => {
    const item = todos.find((t) => t.id === id);
    if (!item) {
      return { content: [{ type: "text", text: `Todo ${id} not found` }] };
    }
    item.completed = true;
    return { content: [{ type: "text", text: `Completed: ${item.title}` }] };
  }
);

server.tool(
  "delete_todo",
  { id: z.number().describe("Todo item ID to delete") },
  async ({ id }) => {
    const before = todos.length;
    todos = todos.filter((t) => t.id !== id);
    const deleted = todos.length < before;
    return { content: [{ type: "text", text: deleted ? `Deleted todo ${id}` : `Todo ${id} not found` }] };
  }
);

const transport = new StdServerTransport();
server.connect(transport);
