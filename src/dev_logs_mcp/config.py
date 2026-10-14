"""Pure configuration validation; filesystem authorization is not implemented here."""

import tomllib
from typing import Literal

from pydantic import Field, model_validator

from dev_logs_mcp.contracts import MAX_SOURCES, BoundaryModel, SourceId
from dev_logs_mcp.parse import source_timezone
from dev_logs_mcp.shared.mcpkit.errors import MAX_CUSTOM_RULES, MAX_PATTERN_BYTES
from dev_logs_mcp.shared.mcpkit.redact import CustomRule, Redactor


class DetectorConfig(BoundaryModel):
    type_name: str = Field(min_length=1, max_length=32, pattern=r"^[A-Z][A-Z0-9_]{0,31}$")
    pattern: str = Field(min_length=1, max_length=MAX_PATTERN_BYTES, repr=False)

    @model_validator(mode="after")
    def bounded_utf8_pattern(self):
        if len(self.pattern.encode("utf-8")) > MAX_PATTERN_BYTES:
            raise ValueError("configured detector exceeds UTF8 ceiling")
        return self


class SourceConfig(BoundaryModel):
    id: SourceId
    path: str = Field(min_length=1, max_length=4096)
    format: str = Field(default="auto", pattern=r"^(auto|plain_iso|jsonl|plain)$")
    timezone: str = Field(default="UTC", min_length=1, max_length=128)
    kind: Literal["file", "directory"] = "file"
    extensions: list[str] = Field(default_factory=lambda: [".log", ".jsonl", ".txt"], max_length=16)

    @model_validator(mode="after")
    def no_null_path(self):
        if "\x00" in self.path:
            raise ValueError("path contains NUL")
        source_timezone(self.timezone)
        if self.kind == "directory" and not self.extensions:
            raise ValueError("directory sources require explicit extensions")
        if len(set(self.extensions)) != len(self.extensions) or any(
            not 2 <= len(ext) <= 16
            or not ext.startswith(".")
            or not ext[1:].isascii()
            or not ext[1:].isalnum()
            for ext in self.extensions
        ):
            raise ValueError("invalid source extension")
        return self


class AppConfig(BoundaryModel):
    schema_version: int = Field(default=1, ge=1, le=1)
    allowed_roots: list[str] = Field(min_length=1, max_length=MAX_SOURCES)
    sources: list[SourceConfig] = Field(min_length=1, max_length=MAX_SOURCES)
    redaction_rules: list[DetectorConfig] = Field(default_factory=list, max_length=MAX_CUSTOM_RULES)

    @model_validator(mode="after")
    def unique_source_ids(self):
        if len({source.id for source in self.sources}) != len(self.sources):
            raise ValueError("duplicate source ids")
        if any(not root or "\x00" in root for root in self.allowed_roots):
            raise ValueError("empty or NUL root")
        if self.redaction_rules:
            Redactor(
                custom_rules=tuple(
                    CustomRule(rule.type_name, rule.pattern) for rule in self.redaction_rules
                )
            )
        return self


def parse_config(text: str) -> AppConfig:
    """Parse TOML shape only; this does not authorize or open any log path."""
    return AppConfig.model_validate(tomllib.loads(text))
