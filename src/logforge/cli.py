import argparse
import json
from dataclasses import asdict
from pathlib import Path

from .core import analyze, parse


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="logforge",
        description="Analyze authentication logs for repeated failures.",
    )
    parser.add_argument("log", help="Path to the log file")
    parser.add_argument(
        "-t",
        "--threshold",
        type=int,
        default=5,
        help="Failures from one source required to flag it",
    )
    parser.add_argument(
        "-j",
        "--json",
        action="store_true",
        dest="json_output",
        help="Print the full report as JSON",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    path = Path(args.log)
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    events = parse(lines)
    summary = analyze(events, threshold=args.threshold)

    if args.json_output:
        print(
            json.dumps(
                {
                    "summary": summary,
                    "events": [asdict(event) for event in events],
                },
                indent=2,
            )
        )
        return

    print(f"Events: {summary['events']}")
    if summary["by_type"]:
        details = ", ".join(
            f"{kind}={count}"
            for kind, count in summary["by_type"].items()
        )
        print(f"By type: {details}")

    print("Suspicious sources:")
    if not summary["suspicious_sources"]:
        print("  none")
    else:
        for source in summary["suspicious_sources"]:
            print(f"  {source['ip']}  {source['failures']} failures")


if __name__ == "__main__":
    main()
