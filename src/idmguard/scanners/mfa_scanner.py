"""MFA configuration checker."""
from pathlib import Path
class MFAScanner:
    def scan(self, path: Path) -> dict:
        checks = []
        for f in path.rglob("*"):
            if not f.is_file(): continue
            try:
                c = f.read_text(errors="ignore").lower()
                if "mfa" in c or "multi_factor" in c or "totp" in c or "authenticator" in c:
                    checks.append({"file": str(f), "mfa_detected": True, "detail": "MFA references found"})
                    break
            except: pass
        if not checks:
            checks.append({"file": "all", "mfa_detected": False, "detail": "No MFA configuration found"})
        return {"checks": checks, "mfa_enforced": any(c["mfa_detected"] for c in checks)}
