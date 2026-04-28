"""Builds alignment prompts from declared schema + static IO summary."""
from __future__ import annotations

import json
from typing import Any

from ..models import ToolSnapshot
from ..prompts import load_prompt


class AlignmentPromptBuilder:
    def __init__(self) -> None:
        self.system = load_prompt("code_alignment.md")

    def system_prompt(self) -> str:
        return self.system

    def user_payload(
        self,
        tool: ToolSnapshot,
        io_summary: dict[str, Any],
        snippets: list[str] | None = None,
    ) -> str:
        return json.dumps(
            {
                "declared": {
                    "name": tool.name,
                    "description": tool.description,
                    "input_schema": tool.input_schema,
                    "annotations": tool.annotations,
                },
                "implementation_summary": io_summary,
                "optional_snippets": snippets or [],
            },
            ensure_ascii=False,
        )
