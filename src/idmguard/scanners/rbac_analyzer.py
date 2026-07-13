"""RBAC permission risk analyzer."""
from pathlib import Path
class RBACAnalyzer:
    def analyze(self, path: Path) -> dict:
        risks = []
        findings = []
        for f in path.rglob("*"):
            if not f.is_file(): continue
            try:
                c = f.read_text(errors="ignore")
                if "admin" in c.lower():
                    risks.append(f"Admin-level permissions in {f.name}")
                if "root" in c.lower() or "superuser" in c.lower():
                    risks.append(f"Superuser/root access in {f.name}")
                if ":" in c and "*" in c:
                    for i, line in enumerate(c.split("\n"),1):
                        if "*" in line and (":" in line or "arn:" in line):
                            findings.append({"risk": "Wildcard permission", "file": str(f), "line": i})
            except: pass
        return {"risks": risks, "findings": findings, "total_risks": len(risks), "total_findings": len(findings)}
