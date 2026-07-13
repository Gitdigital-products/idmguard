"""IAM policy security scanner."""
import re; from pathlib import Path

WARNINGS = [
    (re.compile(r'"Action"\s*:\s*"\*"'), "critical", "Wildcard Action allows all API calls"),
    (re.compile(r'"Resource"\s*:\s*"\*"'), "high", "Wildcard Resource gives access to all resources"),
    (re.compile(r'"Effect"\s*:\s*"Allow"'), "info", "Allow effect - ensure this is scoped"),
    (re.compile(r'"Principal"\s*:\s*"\*"'), "critical", "Wildcard Principal allows anyone to access"),
    (re.compile(r'iam:PassRole'), "medium", "iam:PassRole can lead to privilege escalation"),
]

class PolicyScanner:
    def scan(self, path: Path) -> dict:
        findings = []
        for f in list(path.rglob("*.json")) + list(path.rglob("*.yaml")) + list(path.rglob("*.yml")):
            if ".venv" in str(f): continue
            try:
                c = f.read_text(errors="ignore")
                for i, line in enumerate(c.split("\n"),1):
                    for p, sev, msg in WARNINGS:
                        if p.search(line) and sev != "info":
                            findings.append({"severity": sev, "message": f"{msg} ({f.name}:{i})", "file_path": str(f), "line": i})
            except: pass
        return {"findings": findings, "total": len(findings), "critical": sum(1 for f in findings if f["severity"]=="critical"), "high": sum(1 for f in findings if f["severity"]=="high")}
