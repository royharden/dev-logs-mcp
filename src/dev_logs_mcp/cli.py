"""Keyless stdio/configuration/catalog/preflight commands; no network effects."""

import argparse
import sys
from pathlib import Path

from dev_logs_mcp import __version__
from dev_logs_mcp.config import parse_config

MAX_CONFIG_BYTES = 128 * 1024


def main() -> int:
    parser = argparse.ArgumentParser(description="Bounded local development log tools")
    parser.add_argument("--version", action="version", version=__version__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    check = subparsers.add_parser("check-config", help="Check TOML shape; does not open log paths")
    check.add_argument("config", type=Path)
    serve = subparsers.add_parser("serve", help="Run the local read-only stdio MCP server")
    serve.add_argument("config", type=Path)
    serve.add_argument("--cache-dir", type=Path)
    prepare = subparsers.add_parser(
        "index-source", help="Explicitly index a stable configured source"
    )
    prepare.add_argument("config", type=Path)
    prepare.add_argument("source_id")
    prepare.add_argument("--cache-dir", type=Path, required=True)
    export = subparsers.add_parser(
        "export-tools", help="Generate tool schemas without opening logs"
    )
    destination = export.add_mutually_exclusive_group()
    destination.add_argument("--out", type=Path)
    destination.add_argument("--check", type=Path)
    args = parser.parse_args()
    if args.command == "export-tools":
        from .server import exported_tools
        from .shared.mcpkit.tools_json import catalog_json

        try:
            content = catalog_json(exported_tools())
            if args.check is not None:
                if args.check.read_text(encoding="utf-8") != content:
                    print("CATALOG_STALE: regenerate the complete tool catalog", file=sys.stderr)
                    return 2
            elif args.out is not None:
                args.out.write_text(content, encoding="utf-8", newline="\n")
            else:
                print(content, end="")
            return 0
        except (OSError, ValueError):
            print("CATALOG_INVALID: tool export could not complete", file=sys.stderr)
            return 2
    try:
        with args.config.open("rb") as config_file:
            raw = config_file.read(MAX_CONFIG_BYTES + 1)
        if len(raw) > MAX_CONFIG_BYTES:
            raise ValueError("configuration too large")
        config = parse_config(raw.decode("utf-8-sig"))
    except (OSError, ValueError):
        # Pydantic/TOML exception text can contain configured secrets: do not echo it.
        print("CONFIG_INVALID: check UTF-8 TOML shape and configured source IDs", file=sys.stderr)
        return 2
    if args.command == "check-config":
        print(
            f"Configuration shape valid: {len(config.sources)} sources; "
            "paths not authorized or read"
        )
        return 0
    from .index import PrivateIndexCache, ReadFailure
    from .query import LogEngine
    from .shared.mcpkit.safe_path import PathPolicyError
    from .sources import SourceCatalog

    try:
        catalog = SourceCatalog(config, args.config.resolve(strict=True).parent)
        cache = PrivateIndexCache(args.cache_dir.absolute()) if args.cache_dir else None
        engine = LogEngine(catalog, cache=cache)
        if args.command == "index-source":
            index = engine.prepare(args.source_id)
            print(f"Indexed generation {index.generation_id}; {index.total_lines} physical lines")
        else:
            import anyio

            from .server import serve

            anyio.run(serve, engine)
        return 0
    except (ReadFailure, PathPolicyError) as failure:
        print(f"{failure.code}: configured operation could not complete safely", file=sys.stderr)
    except Exception:
        # Includes transport ExceptionGroups; never echo SDK or OS exception text.
        print("SERVER_STOPPED: bounded local operation could not complete", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
