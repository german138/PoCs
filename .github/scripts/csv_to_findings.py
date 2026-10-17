#!/usr/bin/env python3
"""Convert SDP CSV output to the SCM-neutral findings contract (sdp.findings/v1).

Usage: csv_to_findings.py <input.csv> <output.json> --repository R --commit-sha S
                           --start-date A --end-date B --tool-version V

CSV schema (v0.1.1 mock): id,column1,column2,file_path,function_name,fixes,start_line
All rows are emitted; `defect` is true only when fixes/predicted_defect == 1.
Fingerprint = sha256("<file_path>::<function_name>")[:16] — identical algorithm to
csv_to_sarif.py so GHAS alerts and backend dedup stay consistent.
"""
import argparse
import csv
import hashlib
import json
import sys
from pathlib import Path

SCHEMA = "sdp.findings/v1"


def fingerprint(file_path: str, function_name: str) -> str:
    digest = hashlib.sha256(f"{file_path}::{function_name}".encode()).hexdigest()
    return digest[:16]


def build_findings(csv_path: Path) -> list[dict]:
    findings = []
    with csv_path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            file_path = (row.get("file_path") or "").strip().replace("\\", "/").lstrip("./")
            function_name = (row.get("function_name") or "unknown").strip()
            is_defect = (row.get("fixes") or row.get("predicted_defect") or "").strip() == "1"
            try:
                start_line = max(1, int(row.get("start_line") or 1))
            except ValueError:
                start_line = 1
            findings.append({
                "file_path": file_path,
                "function_name": function_name,
                "start_line": start_line,
                "defect": is_defect,
                "fingerprint": fingerprint(file_path, function_name),
            })
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input_csv", type=Path)
    parser.add_argument("output_json", type=Path)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--commit-sha", required=True)
    parser.add_argument("--start-date", required=True)
    parser.add_argument("--end-date", required=True)
    parser.add_argument("--tool-version", required=True)
    args = parser.parse_args()

    findings = build_findings(args.input_csv)
    payload = {
        "schema": SCHEMA,
        "repository": args.repository,
        "commit_sha": args.commit_sha,
        "start_date": args.start_date,
        "end_date": args.end_date,
        "tool": {"name": "SDP", "version": args.tool_version},
        "findings": findings,
    }
    args.output_json.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    defects = sum(1 for f in findings if f["defect"])
    print(f"Wrote {len(findings)} finding(s) ({defects} defective) to {args.output_json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
