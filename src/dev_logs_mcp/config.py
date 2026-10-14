"""Pure configuration validation; filesystem authorization is not implemented here."""

import tomllib

from pydantic import Field, model_validator

from dev_logs_mcp.contracts import MAX_SOURCES, BoundaryModel, SourceId


class SourceConfig(BoundaryModel):
    id: SourceId
    path: str = Field(min_length=1, max_length=4096)
    format: str = Field(default="auto", pattern=r"^(auto|plain_iso|jsonl|plain)$")
    timezone: str = Field(default="UTC", min_length=1, max_length=128)

    @model_validator(mode="after")
    def no_null_path(self):
        if "\x00" in self.path:
            raise ValueError("path contains NUL")
        return self


class AppConfig(BoundaryModel):
    schema_version: int = Field(default=1, ge=1, le=1)
    allowed_roots: list[str] = Field(min_length=1, max_length=MAX_SOURCES)
    sources: list[SourceConfig] = Field(min_length=1, max_length=MAX_SOURCES)

    @model_validator(mode="after")
    def unique_source_ids(self):
        if len({source.id for source in self.sources}) != len(self.sources):
            raise ValueError("duplicate source ids")
        if any(not root or "\x00" in root for root in self.allowed_roots):
            raise ValueError("empty or NUL root")
        return self


def parse_config(text: str) -> AppConfig:
    """Parse TOML shape only; this does not authorize or open any log path."""
    return AppConfig.model_validate(tomllib.loads(text))
