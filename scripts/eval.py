"""Inspect fixed evaluation configuration without acquiring or executing a campaign."""

import argparse
import json

from dev_logs_mcp.evaluation.controller import implementation_digest, method_config_hashes


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--preflight",
        action="store_true",
        required=True,
        help="print installed method identity only; no dataset, log or transport is opened",
    )
    parser.parse_args(argv)
    implementation = implementation_digest()
    print(
        json.dumps(
            {
                "status": "not_measured",
                "reason": "configuration_only_no_campaign_admission",
                "implementation_sha256": implementation,
                "method_config_sha256": method_config_hashes(implementation),
                "execution_entry": "dev_logs_mcp.evaluation.controller.evaluate",
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
