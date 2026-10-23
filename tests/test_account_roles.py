"""Onboarding must persist both remediation role ARNs (v18 feedback)."""
import os
import sys
sys.path.insert(0, os.path.dirname(__file__))
from test_workers import _register, _auth


def test_connect_account_persists_both_remediation_roles(auth_client):
    tokens = _register(auth_client, "roles-persist", "roles@persist.com")
    r = auth_client.post("/accounts", headers=_auth(tokens), json={
        "aws_account_id": "123456789012",
        "display_name": "prod",
        "role_arn": "arn:aws:iam::123456789012:role/CgDetection",
        "auto_remediation_role_arn": "arn:aws:iam::123456789012:role/CgAutoRemediation",
        "destructive_remediation_role_arn": "arn:aws:iam::123456789012:role/CgDestructiveRemediation",
        "primary_region": "us-east-1",
    })
    assert r.status_code == 201, r.text
    listing = auth_client.get("/accounts", headers=_auth(tokens)).json()
    saved = next(a for a in listing if a["aws_account_id"] == "123456789012")
    assert saved["auto_remediation_role_arn"] == "arn:aws:iam::123456789012:role/CgAutoRemediation"
    assert saved["destructive_remediation_role_arn"] == "arn:aws:iam::123456789012:role/CgDestructiveRemediation"


def test_connect_account_roles_optional(auth_client):
    tokens = _register(auth_client, "roles-opt", "opt@roles.com")
    r = auth_client.post("/accounts", headers=_auth(tokens), json={
        "aws_account_id": "123456789013",
        "display_name": "partial",
        "role_arn": "arn:aws:iam::123456789013:role/CgDetection",
        "primary_region": "us-east-1",
    })
    assert r.status_code == 201, r.text
