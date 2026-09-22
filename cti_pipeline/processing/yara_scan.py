#!/usr/bin/env python3
"""Recursive YARA scanner module for CTI Lab."""

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path
import yara

def compile_rules(rules_dir: Path) -> yara.Rules:
    """Recursively find and compile all .yar / .yara rules in a directory."""
    rule_filepaths = {}
    for root, _, files in os.walk(rules_dir):
        for file in files:
            if file.endswith((".yar", ".yara")):
                full_path = os.path.join(root, file)
                # Create a clean key namespace for YARA compilation
                namespace = os.path.splitext(file)[0]
                rule_filepaths[namespace] = full_path

    if not rule_filepaths:
        raise FileNotFoundError(f"No .yar or .yara rules found in {rules_dir}")

    print(f"[*] Compiling {len(rule_filepaths)} rule file(s)...")
    return yara.compile(filepaths=rule_filepaths)

def scan_directory(compiled_rules: yara.Rules, target_dir: Path) -> list:
    """Recursively scan files in target directory against compiled rules."""
    scan_results = []
    print(f"[*] Scanning target directory: {target_dir}")

    for root, _, files in os.walk(target_dir):
        for file in files:
            file_path = Path(root) / file
            try:
                matches = compiled_rules.match(str(file_path))
                if matches:
                    matched_rules = []
                    for match in matches:
                        matched_rules.append({
                            "rule": match.rule,
                            "tags": match.tags,
                            "meta": match.meta,
                            "namespace": match.namespace
                        })
                    
                    scan_results.append({
                        "file_path": str(file_path),
                        "file_name": file_path.name,
                        "matched_count": len(matches),
                        "matches": matched_rules
                    })
            except Exception as e:
                print(f"[!] Error scanning {file_path}: {e}", file=sys.stderr)

    return scan_results

def main():
    parser = argparse.ArgumentParser(description="Recursive YARA Scanner for CTI Lab")
    parser.add_argument("--rules", type=Path, default=Path("yara-workbench/rules"), help="Directory containing YARA rules")
    parser.add_argument("--target", type=Path, default=Path("yara-workbench/samples"), help="Directory containing target files to scan")
    parser.add_argument("--output", type=Path, default=Path("yara-workbench/reports/scan_report.json"), help="Output path for JSON detection report")

    args = parser.parse_args()

    try:
        compiled_rules = compile_rules(args.rules)
        detections = scan_directory(compiled_rules, args.target)

        report = {
            "scan_timestamp": datetime.utcnow().isoformat() + "Z",
            "rules_directory": str(args.rules),
            "target_directory": str(args.target),
            "total_detections": len(detections),
            "detections": detections
        }

        args.output.parent.mkdir(parents=True, exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

        print(f"[+] Scan complete! Detections: {len(detections)}. Report saved to: {args.output}")

    except Exception as e:
        print(f"[!] Scan failed: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
