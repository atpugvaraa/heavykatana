#!/usr/bin/env python3
"""Post-run checker for HeavyKatana call-recorder instrumentation logs.

This parser extracts objective run evidence from syslog captures and reports
R-01..R-03 checks from Plan.md.

Usage examples:
  python3 tools/post_run_checker.py logs/syslog_2026-04-20_18-08-56.txt
  python3 tools/post_run_checker.py logs --glob 'syslog_*.txt' --out logs/run_summary.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable, List, Optional

CALLREC_RE = re.compile(
    r"\[CALLREC\](?:\[(?P<run>[^\]]+)\])?(?:\[\+(?P<elapsed>\d+)ms\])?\s*(?P<msg>.*)"
)
RESULT_RE = re.compile(r"result=([-]?\d+)")
SIZE_RE = re.compile(r"file size:\s*(\d+)\s*bytes", re.IGNORECASE)
MAGIC_RE = re.compile(r"artifact header magic:\s*(.+)$", re.IGNORECASE)
PATH_RE = re.compile(r"output path:\s*(\S+)$", re.IGNORECASE)
FINAL_RE = re.compile(r"call_recorder_katana result=(true|false)", re.IGNORECASE)
ARTIFACT_FINAL_RE = re.compile(r"artifact validation\s+(PASS|FAIL)\s+file=(\S+)", re.IGNORECASE)


@dataclass
class RunSummary:
    log_file: str
    run_id: str = "unknown"
    callrec_lines: int = 0
    r01_payload_start: bool = False
    set_category_result: Optional[int] = None
    set_mode_result: Optional[int] = None
    set_active_result: Optional[int] = None
    init_errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    output_path: Optional[str] = None
    artifact_size_bytes: Optional[int] = None
    artifact_magic: Optional[str] = None
    artifact_validation: Optional[str] = None
    final_result: Optional[bool] = None

    @property
    def r02_init_ok(self) -> bool:
        if self.set_category_result in (None, 0):
            return False
        if self.set_mode_result in (None, 0):
            return False
        if self.set_active_result in (None, 0):
            return False
        return len(self.init_errors) == 0

    def r03_artifact_ok(self, min_size: int) -> bool:
        if self.artifact_validation == "PASS":
            return True
        if self.artifact_size_bytes is None or self.artifact_magic is None:
            return False
        return self.artifact_size_bytes >= min_size and self.artifact_magic.strip() == "caff"


def _coerce_result(msg: str) -> Optional[int]:
    match = RESULT_RE.search(msg)
    if not match:
        return None
    try:
        return int(match.group(1))
    except ValueError:
        return None


def parse_log(log_path: Path) -> RunSummary:
    summary = RunSummary(log_file=str(log_path))

    with log_path.open("r", encoding="utf-8", errors="replace") as f:
        for raw in f:
            m = CALLREC_RE.search(raw)
            if not m:
                continue

            summary.callrec_lines += 1
            msg = (m.group("msg") or "").strip()
            run_id = m.group("run")
            if run_id:
                summary.run_id = run_id

            if "=== call_recorder_katana entry ===" in msg:
                summary.r01_payload_start = True

            if msg.startswith("setCategory result="):
                summary.set_category_result = _coerce_result(msg)
            elif msg.startswith("setMode (VoiceChat) result="):
                summary.set_mode_result = _coerce_result(msg)
            elif msg.startswith("setActive result="):
                summary.set_active_result = _coerce_result(msg)

            path_match = PATH_RE.search(msg)
            if path_match:
                summary.output_path = path_match.group(1)

            size_match = SIZE_RE.search(msg)
            if size_match:
                try:
                    summary.artifact_size_bytes = int(size_match.group(1))
                except ValueError:
                    pass

            magic_match = MAGIC_RE.search(msg)
            if magic_match:
                summary.artifact_magic = magic_match.group(1).strip()

            artifact_match = ARTIFACT_FINAL_RE.search(msg)
            if artifact_match:
                summary.artifact_validation = artifact_match.group(1).upper()
                if not summary.output_path:
                    summary.output_path = artifact_match.group(2)

            final_match = FINAL_RE.search(msg)
            if final_match:
                summary.final_result = final_match.group(1).lower() == "true"

            if " ERROR:" in msg:
                summary.init_errors.append(msg)
            if msg.startswith("WARNING:"):
                summary.warnings.append(msg)

    return summary


def expand_inputs(inputs: Iterable[str], glob_pattern: str) -> List[Path]:
    files: List[Path] = []
    seen = set()

    for item in inputs:
        p = Path(item)
        if p.is_dir():
            for candidate in sorted(p.glob(glob_pattern)):
                if candidate.is_file() and candidate not in seen:
                    files.append(candidate)
                    seen.add(candidate)
        elif p.is_file():
            if p not in seen:
                files.append(p)
                seen.add(p)

    return files


def print_report(summaries: List[RunSummary], min_size: int) -> None:
    if not summaries:
        print("No matching log files found.")
        return

    print("# HeavyKatana Post-Run Summary")
    print()
    print("| Log | Run ID | R-01 Start | R-02 Init | R-03 Artifact | Size | Magic | Final | Warnings |")
    print("|---|---|---|---|---|---:|---|---|---:|")

    for s in summaries:
        r03 = s.r03_artifact_ok(min_size)
        size = str(s.artifact_size_bytes) if s.artifact_size_bytes is not None else "n/a"
        magic = s.artifact_magic or "n/a"
        final = "true" if s.final_result is True else "false" if s.final_result is False else "n/a"
        print(
            "| {log} | {run} | {r01} | {r02} | {r03} | {size} | {magic} | {final} | {warns} |".format(
                log=Path(s.log_file).name,
                run=s.run_id,
                r01="PASS" if s.r01_payload_start else "FAIL",
                r02="PASS" if s.r02_init_ok else "FAIL",
                r03="PASS" if r03 else "FAIL",
                size=size,
                magic=magic,
                final=final,
                warns=len(s.warnings),
            )
        )

    total = len(summaries)
    full_pass = sum(
        1
        for s in summaries
        if s.r01_payload_start and s.r02_init_ok and s.r03_artifact_ok(min_size)
    )
    pass_rate = (full_pass / total) * 100.0

    print()
    print("Aggregate:")
    print(f"- Total runs: {total}")
    print(f"- Full R-01/R-02/R-03 passes: {full_pass}")
    print(f"- Pass rate: {pass_rate:.1f}%")


def main() -> int:
    parser = argparse.ArgumentParser(description="Summarize call-recorder run evidence from syslog logs.")
    parser.add_argument("inputs", nargs="+", help="Log files or directories to parse")
    parser.add_argument("--glob", default="syslog_*.txt", help="Glob used when an input is a directory")
    parser.add_argument("--min-size", type=int, default=4096, help="Minimum file size for R-03 artifact check")
    parser.add_argument("--out", help="Optional JSON output path")
    args = parser.parse_args()

    files = expand_inputs(args.inputs, args.glob)
    if not files:
        print("No input files found.", file=sys.stderr)
        return 1

    summaries = [parse_log(p) for p in files]
    print_report(summaries, args.min_size)

    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "min_size": args.min_size,
            "runs": [asdict(s) for s in summaries],
        }
        with out_path.open("w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        print(f"\nWrote JSON summary to: {out_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
