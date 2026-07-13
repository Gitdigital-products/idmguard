from pathlib import Path
from idmguard.scanners.policy_scanner import PolicyScanner
def test_wildcard_action(tmp_path):
    (tmp_path / "policy.json").write_text('{"Action": "*", "Resource": "*", "Effect": "Allow"}')
    result = PolicyScanner().scan(tmp_path)
    assert result["critical"] >= 1
def test_clean_policy(tmp_path):
    (tmp_path / "policy.json").write_text('{"Action": "s3:GetObject", "Resource": "arn:aws:s3:::bucket/*", "Effect": "Allow"}')
    result = PolicyScanner().scan(tmp_path)
    assert result["critical"] == 0
