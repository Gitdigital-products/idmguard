import sys, json, argparse; from pathlib import Path; from idmguard import __version__
def build_parser():
    p = argparse.ArgumentParser(prog="idmguard", description="IDMGuard - IAM Security Toolkit")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command")
    sub.add_parser("audit", help="Audit IAM policies").add_argument("path", nargs="?", default=".")
    sub.add_parser("scan-keys", help="Scan for exposed keys").add_argument("path", nargs="?", default=".")
    sub.add_parser("mfa-check", help="Check MFA configuration").add_argument("path", nargs="?", default=".")
    sub.add_parser("rbac", help="Analyze RBAC permissions").add_argument("path", nargs="?", default=".")
    sub.add_parser("compliance", help="Check IAM compliance").add_argument("path", nargs="?", default=".")
    return p
def main(argv=None):
    args = build_parser().parse_args(argv)
    if not args.command:
        build_parser().print_help(); return 0
    if args.command == "audit":
        from idmguard.scanners.policy_scanner import PolicyScanner
        result = PolicyScanner().scan(Path(args.path))
        print(json.dumps(result, indent=2))
        return 1 if result.get("critical", 0) > 0 else 0
    elif args.command == "scan-keys":
        from idmguard.scanners.key_scanner import KeyScanner
        result = KeyScanner().scan(Path(args.path))
        print(json.dumps(result, indent=2))
        return 1 if result.get("total", 0) > 0 else 0
    elif args.command == "mfa-check":
        from idmguard.scanners.mfa_scanner import MFAScanner
        result = MFAScanner().scan(Path(args.path))
        print(json.dumps(result, indent=2))
        return 0
    elif args.command == "rbac":
        from idmguard.scanners.rbac_analyzer import RBACAnalyzer
        result = RBACAnalyzer().analyze(Path(args.path))
        print(json.dumps(result, indent=2))
        return 1 if result.get("risks", 0) > 0 else 0
    elif args.command == "compliance":
        from idmguard.compliance.iam_checks import IAMCompliance
        result = IAMCompliance().check(Path(args.path))
        for c in result["checks"]:
            s = "PASS" if c["passed"] else "FAIL"
            print(f"  [{s}] {c['standard']}: {c['detail']}")
        return 0 if result["passed"] else 1
if __name__ == "__main__":
    sys.exit(main())
