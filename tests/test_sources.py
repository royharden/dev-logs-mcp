"""Catalog shape/mock metadata controls; actual POSIX cases are separately marked."""

import os
from pathlib import Path

import pytest

import dev_logs_mcp.sources as sources
from dev_logs_mcp.config import AppConfig
from dev_logs_mcp.index import ReadBudget, ReadFailure
from dev_logs_mcp.shared.mcpkit.redact import Redactor
from dev_logs_mcp.shared.mcpkit.safe_path import PathPolicyError
from dev_logs_mcp.sources import SourceCatalog


def config(root, path, **kwargs):
    return AppConfig.model_validate(
        {"allowed_roots": [str(root)], "sources": [{"id": "web", "path": str(path), **kwargs}]}
    )


def test_relative_sources_bind_to_explicit_config_base_without_resolving_or_opening(tmp_path):
    catalog = SourceCatalog(config("logs", "logs/web.log"), tmp_path)
    assert catalog.get("web").path == tmp_path / "logs" / "web.log"
    assert list(tmp_path.iterdir()) == []
    assert len(catalog.config_hash) == 64
    assert "web.log" not in repr(catalog.get("web"))


@pytest.mark.parametrize("kind", ["file", "directory"])
def test_escape_and_broad_authority_are_rejected_before_any_discovery(tmp_path, monkeypatch, kind):
    def forbidden(*args, **kwargs):
        raise AssertionError("must reject before metadata enumeration")

    monkeypatch.setattr(sources, "_metadata_open", forbidden)
    for root, path in [
        (tmp_path, tmp_path / ".." / "elsewhere"),
        (Path.home(), Path.home() / "app.log"),
    ]:
        with pytest.raises(PathPolicyError):
            SourceCatalog(config(root, path, kind=kind), tmp_path)


def test_combined_directory_catalog_overflow_is_not_silently_partial(tmp_path, monkeypatch):
    def discover(path, source_id, extensions, budget):
        return [(f"s_{n}", path / f"{n}.log") for n in range(100)]

    monkeypatch.setattr(SourceCatalog, "_discover", staticmethod(discover))
    value = AppConfig.model_validate(
        {
            "allowed_roots": [str(tmp_path)],
            "sources": [
                {"id": "dir", "path": str(tmp_path / "logs"), "kind": "directory"},
                {"id": "explicit", "path": str(tmp_path / "extra.log")},
            ],
        }
    )
    with pytest.raises(ReadFailure) as error:
        SourceCatalog(value, tmp_path)
    assert error.value.code == "CONFIG_INVALID"


def test_metadata_unavailable_is_visible_without_opening_data(tmp_path, monkeypatch):
    catalog = SourceCatalog(config(tmp_path, tmp_path / "source.log"), tmp_path)

    def unavailable(*args, **kwargs):
        raise ReadFailure("SOURCE_NOT_LOCAL")

    def data_forbidden(*args, **kwargs):
        raise AssertionError("listing cannot open data")

    monkeypatch.setattr(sources, "_metadata_open", unavailable)
    monkeypatch.setattr(catalog._policy, "open_source", data_forbidden)
    info = catalog.infos(Redactor(), ReadBudget())[0]
    assert not info.readable and info.problem == "SOURCE_NOT_LOCAL" and info.size is None
    assert info.display_path == "source.log"


def test_display_metadata_redacted_before_bounding(tmp_path, monkeypatch):
    catalog = SourceCatalog(
        config(tmp_path, tmp_path / ("password=" + "synthetic-marker" + ".log")), tmp_path
    )

    def unavailable(*args, **kwargs):
        raise ReadFailure("SOURCE_NOT_LOCAL")

    monkeypatch.setattr(sources, "_metadata_open", unavailable)
    assert "synthetic-marker" not in catalog.infos(Redactor(), ReadBudget())[0].model_dump_json()


@pytest.mark.skipif(
    os.name != "posix", reason="required POSIX metadata/discovery actual execution pending"
)
def test_native_posix_one_level_discovery_and_metadata_no_data(tmp_path):
    """what_bug_this_catches: matching directory entries are bounded, nonrecursive and no-follow."""
    folder = tmp_path / "logs"
    folder.mkdir()
    (folder / "one.log").write_text("synthetic\n")
    (folder / "ignored.bin").write_bytes(b"ignored")
    (folder / "nested").mkdir()
    (folder / "nested" / "not-discovered.log").write_text("synthetic\n")
    catalog = SourceCatalog(
        config(tmp_path, folder, kind="directory", extensions=[".log"]), tmp_path
    )
    infos = catalog.infos(Redactor(), ReadBudget())
    assert len(infos) == 1 and infos[0].readable and infos[0].size == 10
    assert infos[0].id.startswith("s_") and infos[0].display_path == "logs/one.log"
    (folder / "link.log").symlink_to(folder / "one.log")
    with pytest.raises(ReadFailure):
        SourceCatalog(config(tmp_path, folder, kind="directory"), tmp_path)
