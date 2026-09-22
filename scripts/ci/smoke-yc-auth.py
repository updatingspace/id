#!/usr/bin/env python3
"""Check auth form handling without creating accounts or sending email."""

import json
import os
import urllib.error
import urllib.request
import uuid

base = os.environ["SMOKE_BASE_URL"].rstrip("/")
headers = {"User-Agent": "UpdSpace-ID-deploy-smoke", "Cache-Control": "no-cache"}
if os.environ.get("SMOKE_HOST_HEADER"):
    headers["Host"] = os.environ["SMOKE_HOST_HEADER"]


def request(path, payload=None):
    request_headers = dict(headers)
    if payload is not None:
        request_headers["Content-Type"] = "application/json"
    req = urllib.request.Request(
        base + path,
        data=None if payload is None else json.dumps(payload).encode(),
        headers=request_headers,
    )
    try:
        response = urllib.request.urlopen(req, timeout=30)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        status, body = response.status, json.load(response)
    return status, body


run_id = uuid.uuid4().hex
email = "deploy-smoke-" + run_id + "@example.invalid"
status, body = request("/api/v1/auth/form_token?purpose=login")
assert status == 200, "Cannot issue a login form token"
payload = {
    "email": email,
    "password": "nonexistent-account-test",
    "form_token": body["form_token"],
}
status, body = request("/api/v1/auth/login", payload)
assert status == 401 and body.get("code") == "INVALID_CREDENTIALS", (
    f"Login did not reach credential validation: {status} {body.get('code')}"
)
status, body = request("/api/v1/auth/login", payload)
assert status == 400 and body.get("code") == "INVALID_FORM_TOKEN", (
    "Replayed form token was accepted"
)
status, body = request("/api/v1/auth/form_token?purpose=register")
assert status == 200
# The deliberately short password is rejected by form validation after the
# duplicate-email database query, before any user creation or email delivery.
status, body = request(
    "/api/v1/auth/signup",
    {
        "email": email,
        "username": "smoke-" + run_id,
        "password": "x",
        "consent_data_processing": True,
        "form_token": body["form_token"],
    },
)
assert status == 400 and body.get("code") != "INVALID_FORM_TOKEN", (
    f"Signup validation failed: {status} {body.get('code')}"
)

# A unique nonexistent address exercises recovery without sending email.
for purpose, path in [
    ("password_reset", "password/reset/request"),
    ("email_verification", "email/verification/request"),
]:
    status, body = request("/api/v1/auth/form_token?purpose=" + purpose)
    assert status == 200, f"Cannot issue a {purpose} form token"
    payload = {"email": email, "form_token": body["form_token"]}
    status, body = request("/api/v1/auth/" + path, payload)
    assert status == 200 and body.get("ok") is True, (
        f"Recovery request failed: {path} {status} {body.get('code')}"
    )
    status, body = request("/api/v1/auth/" + path, payload)
    assert status == 400 and body.get("code") == "INVALID_FORM_TOKEN"

for path, payload in [
    ("password/reset/confirm", {"key": "invalid", "password": "Unused-Password-123!"}),
    ("email/verification/confirm", {"key": "invalid"}),
]:
    status, body = request("/api/v1/auth/" + path, payload)
    assert status == 400 and body.get("code") == "INVALID_RECOVERY_LINK", (
        f"Invalid recovery link not rejected: {path} {status} {body.get('code')}"
    )
print(
    "Auth smoke passed: login, signup, recovery requests, form token replay and invalid recovery links"
)
