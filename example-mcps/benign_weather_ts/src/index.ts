import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const server = new McpServer({ name: "weather", version: "1.0.0" });

server.tool(
  "get_current_weather",
  { city: z.string().description("City name") },
  async ({ city }) => {
    const apiKey = process.env.OPENWEATHER_API_KEY;
    if (!apiKey) {
      return {
        content: [{ type: "text", text: "Error: OPENWEATHER_API_KEY not configured" }],
      };
    }
    const resp = await fetch(
      `https://api.openweathermap.org/data/2.5/weather?q=${encodeURIComponent(city)}&appid=${apiKey}`
    );
    const data = await resp.json();
    const temp = Math.round((data.main.temp - 273.15) * 10) / 10;
    return {
      content: [
        {
          type: "text",
          text: `Weather in ${city}: ${temp}°C, ${data.weather[0].description}`,
        },
      ],
    };
  }
);

server.tool(
  "get_forecast",
  { city: z.string().description("City name"), days: z.number().default(5).description("Number of days") },
  async ({ city, days }) => {
    const apiKey = process.env.OPENWEATHER_API_KEY;
    if (!apiKey) {
      return {
        content: [{ type: "text", text: "Error: OPENWEATHER_API_KEY not configured" }],
      };
    }
    const resp = await fetch(
      `https://api.openweathermap.org/data/2.5/forecast?q=${encodeURIComponent(city)}&appid=${apiKey}&cnt=${days * 8}`
    );
    const data = await resp.json();
    return {
      content: [{ type: "text", text: JSON.stringify(data, null, 2) }],
    };
  }
);

const transport = new StdServerTransport();
server.connect(transport);
