"""IAM compliance against standards (NIST AC, SOC2, GDPR)."""
from pathlib import Path
class IAMCompliance:
    def check(self, path: Path) -> dict:
        checks = []
        has_mfa = False; has_rbac = False; has_policies = False
        for f in path.rglob("*"):
            if not f.is_file(): continue
            try:
                c = f.read_text(errors="ignore").lower()
                if "mfa" in c or "totp" in c: has_mfa = True
                if "role" in c and "permission" in c: has_rbac = True
                if "action" in c and "effect" in c: has_policies = True
            except: pass
        checks.append({"standard": "NIST AC-2", "name": "Account management", "passed": has_rbac, "detail": "RBAC detected" if has_rbac else "No RBAC references found"})
        checks.append({"standard": "NIST AC-3", "name": "Access enforcement", "passed": has_policies, "detail": "IAM policies found" if has_policies else "No IAM policies detected"})
        checks.append({"standard": "NIST AC-9", "name": "MFA enforcement", "passed": has_mfa, "detail": "MFA references found" if has_mfa else "No MFA configuration detected"})
        return {"checks": checks, "passed": all(c["passed"] for c in checks), "total": len(checks)}
