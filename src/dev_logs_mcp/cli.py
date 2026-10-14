"""W01 configuration-only CLI; the log-reading server is a later work package."""

import argparse
import sys
from pathlib import Path

from dev_logs_mcp import __version__
from dev_logs_mcp.config import parse_config

MAX_CONFIG_BYTES = 128 * 1024


def main() -> int:
    parser = argparse.ArgumentParser(description="Dev Logs MCP contract/bootstrap tools")
    parser.add_argument("--version", action="version", version=__version__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    check = subparsers.add_parser("check-config", help="Check TOML shape; does not open log paths")
    check.add_argument("config", type=Path)
    args = parser.parse_args()
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
    print(f"Configuration shape valid: {len(config.sources)} sources; paths not authorized or read")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
