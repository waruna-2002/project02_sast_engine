import ast
import re
import os
import yaml
import json

class SASTScanner:
    def __init__(self, rules_file="rules.yaml"):
        self.rules = []
        self.load_rules(rules_file)

    def load_rules(self, rules_file):
        """Loads security detection rules from an external YAML configuration."""
        if os.path.exists(rules_file):
            with open(rules_file, 'r') as f:
                data = yaml.safe_load(f)
                self.rules = data.get("rules", [])
        else:
            # Fallback default rule if rules.yaml missing
            self.rules = [{
                "id": "SEC-001",
                "name": "Hardcoded Secret",
                "severity": "CRITICAL",
                "type": "regex",
                "pattern": r'(?i)(api_key|secret|password)\s*=\s*["\'][A-Za-z0-9_\-\.]{8,}["\']'
            }]

    def scan_file(self, file_path):
        findings = []
        if not os.path.exists(file_path):
            return findings

        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
            content = "".join(lines)

        # 1. Evaluate YAML Regex Rules
        for idx, line in enumerate(lines, 1):
            for rule in self.rules:
                if rule.get("type") == "regex":
                    if re.search(rule["pattern"], line):
                        findings.append({
                            "rule_id": rule["id"],
                            "file": file_path,
                            "line": idx,
                            "severity": rule["severity"],
                            "issue": rule["name"],
                            "code_snippet": line.strip()
                        })

        # 2. AST Dynamic Syntax Analysis (Python Files)
        if file_path.endswith(".py"):
            try:
                tree = ast.parse(content, filename=file_path)
                for node in ast.walk(tree):
                    if isinstance(node, ast.Call):
                        func_name = ""
                        if isinstance(node.func, ast.Name):
                            func_name = node.func.id
                        elif isinstance(node.func, ast.Attribute):
                            func_name = node.func.attr

                        for rule in self.rules:
                            if rule.get("type") == "ast_sink" and func_name in rule.get("sinks", []):
                                findings.append({
                                    "rule_id": rule["id"],
                                    "file": file_path,
                                    "line": getattr(node, 'lineno', 1),
                                    "severity": rule["severity"],
                                    "issue": f"{rule['name']} (`{func_name}`)",
                                    "code_snippet": lines[getattr(node, 'lineno', 1)-1].strip()
                                })

                    # Dynamic Query / SQL Injection Check
                    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
                        findings.append({
                            "rule_id": "SEC-SQLI",
                            "file": file_path,
                            "line": getattr(node, 'lineno', 1),
                            "severity": "HIGH",
                            "issue": "Potential SQL Injection Hazard (% formatting)",
                            "code_snippet": lines[getattr(node, 'lineno', 1)-1].strip()
                        })
            except SyntaxError:
                pass

        return findings

    def scan_directory(self, target_dir):
        all_findings = []
        for root, _, files in os.walk(target_dir):
            if 'venv' in root or '.git' in root or '__pycache__' in root:
                continue
            for file in files:
                if file.endswith(('.py', '.js', '.json', '.env', '.yml', '.yaml')):
                    file_path = os.path.join(root, file)
                    results = self.scan_file(file_path)
                    all_findings.extend(results)
        return all_findings

    def export_sarif(self, findings, output_path="results.sarif"):
        """Exports findings in Industry Standard SARIF (Static Analysis Results Interchange Format)."""
        sarif_structure = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "DevSecOps-SAST-Engine",
                        "informationUri": "https://github.com/waruna-2002/project02_sast_engine",
                        "rules": [{"id": r["id"], "name": r["name"]} for r in self.rules]
                    }
                },
                "results": []
            }]
        }

        for f in findings:
            sarif_structure["runs"][0]["results"].append({
                "ruleId": f.get("rule_id", "SEC-GENERIC"),
                "level": "error" if f["severity"] == "CRITICAL" else "warning",
                "message": {"text": f["issue"]},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f["file"]},
                        "region": {"startLine": f["line"]}
                    }
                }]
            })

        with open(output_path, "w") as sarif_file:
            json.dump(sarif_structure, sarif_file, indent=2)
        return output_path