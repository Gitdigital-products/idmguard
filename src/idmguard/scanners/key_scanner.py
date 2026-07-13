"""Secret key scanner for IAM systems."""
import re; from pathlib import Path
PATTERNS = [
    (re.compile(r"AWS\d{19}"), "AWS access key"),
    (re.compile(r"(?:A3T|AKIA|ABIA|ACCA)[0-9A-Z]{16}"), "AWS access key ID"),
    (re.compile(r"(?:ghp|gho|ghu|ghs)_[A-Za-z0-9_]{36}"), "GitHub token"),
    (re.compile(r"sk-[A-Za-z0-9]{32,}"), "OpenAI API key"),
    (re.compile(r"xox[bpasr]-[0-9A-Za-z-]+"), "Slack token"),
    (re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"), "Private key"),
    (re.compile(r"?:postgres|mysql|mongodb|redis)://[^:]+:[^@]+@", re.I), "DB connection string"),
]
class KeyScanner:
    def scan(self, path: Path) -> dict:
        findings = []
        for f in path.rglob("*"):
            if f.is_dir() or f.suffix in (".pyc",".so",".png",".jpg",".git"): continue
            try:
                c = f.read_text(errors="ignore")
                for i, line in enumerate(c.split("\n"),1):
                    for p, name in PATTERNS:
                        if p.search(line):
                            findings.append({"type": name, "file": str(f), "line": i, "severity": "critical"})
                            break
            except: pass
        return {"findings": findings, "total": len(findings)}
