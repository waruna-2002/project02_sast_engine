import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import argparse
from core.sast_analyzer import SASTScanner
import sys
import argparse
from core.sast_analyzer import SASTScanner

def main():
    parser = argparse.ArgumentParser(description="DevSecOps SAST Engine with SARIF Support")
    parser.add_argument("--path", required=True, help="Path to project directory or file")
    parser.add_argument("--rules", default="rules.yaml", help="Path to custom YAML rules file")
    parser.add_argument("--sarif", help="Output path for SARIF report file (e.g. results.sarif)")
    parser.add_argument("--threshold", default="HIGH", choices=["CRITICAL", "HIGH", "MEDIUM"])

    args = parser.parse_args()

    scanner = SASTScanner(rules_file=args.rules)
    print(f"🔍 Executing SAST Engine Scan on: {args.path}")
    print(f"📜 Loaded Rules Engine: {args.rules}")

    findings = scanner.scan_directory(args.path)

    if args.sarif:
        sarif_file = scanner.export_sarif(findings, output_path=args.sarif)
        print(f"📄 Industry Standard SARIF Report Exported to: {sarif_file}")

    critical_count = sum(1 for f in findings if f['severity'] == 'CRITICAL')
    high_count = sum(1 for f in findings if f['severity'] == 'HIGH')

    print("\n================ SAST AUDIT REPORT ================")
    if not findings:
        print("✅ No Code Vulnerabilities Detected. Security Gate PASSED.")
        sys.exit(0)

    for f in findings:
        print(f"[{f['severity']}] [{f.get('rule_id', 'SEC')}] {f['file']}:{f['line']} -> {f['issue']}")
        print(f"   Code: {f['code_snippet']}\n")

    print(f"Total Findings: {len(findings)} (Critical: {critical_count}, High: {high_count})")

    if args.threshold == "CRITICAL" and critical_count > 0:
        print("\n❌ CI/CD BUILD FAILED: Critical Security Violations Detected!")
        sys.exit(1)
    elif args.threshold == "HIGH" and (critical_count > 0 or high_count > 0):
        print("\n❌ CI/CD BUILD FAILED: High/Critical Security Violations Detected!")
        sys.exit(1)
    else:
        print("\n⚠️ BUILD PASSED WITH WARNINGS.")
        sys.exit(0)

if __name__ == "__main__":
    main()