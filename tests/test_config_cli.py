import pytest
from pydantic import ValidationError

from dev_logs_mcp.cli import main
from dev_logs_mcp.config import AppConfig, parse_config

SAMPLE = """
allowed_roots = ["./synthetic-logs-not-created"]
[[sources]]
id = "web"
path = "./synthetic-logs-not-created/web.log"
"""


def test_keyless_config_shape_does_not_require_source_files(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    config = parse_config(SAMPLE)
    assert config.sources[0].id == "web"
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    "value",
    [
        {"allowed_roots": [], "sources": []},
        {"allowed_roots": [""], "sources": [{"id": "web", "path": "web.log"}]},
        {"allowed_roots": ["."], "sources": []},
        {
            "allowed_roots": ["."],
            "sources": [{"id": "web", "path": "one"}, {"id": "web", "path": "two"}],
        },
        {
            "allowed_roots": ["."],
            "sources": [{"id": "web", "path": "one", "append_only": True}],
        },
    ],
)
def test_config_rejects_missing_duplicate_or_unsupported_authority(value):
    with pytest.raises(ValidationError):
        AppConfig.model_validate(value)


def test_cli_reports_shape_without_claiming_authorization(tmp_path, monkeypatch, capsys):
    config_path = tmp_path / "config.toml"
    config_path.write_text(SAMPLE, encoding="utf-8")
    monkeypatch.setattr("sys.argv", ["dev-logs-mcp", "check-config", str(config_path)])
    assert main() == 0
    assert "paths not authorized or read" in capsys.readouterr().out


def test_invalid_config_never_echoes_value(tmp_path, monkeypatch, capsys):
    config_path = tmp_path / "bad.toml"
    config_path.write_text('secret = "sentinel-private-value"', encoding="utf-8")
    monkeypatch.setattr("sys.argv", ["dev-logs-mcp", "check-config", str(config_path)])
    assert main() == 2
    captured = capsys.readouterr()
    assert "CONFIG_INVALID" in captured.err
    assert "sentinel-private-value" not in captured.err + captured.out


def test_config_size_limit(tmp_path, monkeypatch, capsys):
    config_path = tmp_path / "large.toml"
    config_path.write_text("#" * (128 * 1024 + 1), encoding="utf-8")
    monkeypatch.setattr("sys.argv", ["dev-logs-mcp", "check-config", str(config_path)])
    assert main() == 2
    assert "CONFIG_INVALID" in capsys.readouterr().err


@pytest.mark.parametrize(
    "patch",
    [
        {"timezone": "Not/A/Timezone"},
        {"kind": "directory", "extensions": []},
        {"kind": "directory", "extensions": ["../log"]},
        {"kind": "directory", "extensions": [".log", ".log"]},
        {"kind": "device"},
    ],
)
def test_source_format_authority_rejects_invalid_timezone_and_directory_filters(patch):
    with pytest.raises(ValidationError):
        AppConfig.model_validate(
            {"allowed_roots": ["."], "sources": [{"id": "web", "path": "web.log", **patch}]}
        )


def test_directory_shape_is_one_explicit_configured_source_not_discovery():
    config = AppConfig.model_validate(
        {
            "allowed_roots": ["."],
            "sources": [{"id": "web", "path": "logs", "kind": "directory", "extensions": [".log"]}],
        }
    )
    assert config.sources[0].kind == "directory"
