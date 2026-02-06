# UpdSpace ID Service - Troubleshooting Guide

This guide helps diagnose and resolve common issues with the UpdSpace ID Service.

## Table of Contents

1. [Authentication Issues](#authentication-issues)
2. [MFA Issues](#mfa-issues)
3. [OIDC Issues](#oidc-issues)
4. [OAuth Provider Issues](#oauth-provider-issues)
5. [Performance Issues](#performance-issues)
6. [Configuration Issues](#configuration-issues)

---

## Authentication Issues

### Problem: "INVALID_CREDENTIALS" Error

**Symptoms:**
- User cannot log in
- API returns `{"code": "INVALID_CREDENTIALS", "message": "..."}`

**Possible Causes & Solutions:**

1. **Wrong password**
   - User should use "Forgot Password" flow
   - Admin can reset via Django admin or shell

2. **Account not activated**
   ```bash
   # Check account status
   python src/manage.py shell
   
   from django.contrib.auth import get_user_model
   User = get_user_model()
   user = User.objects.get(email='user@example.com')
   print(f"Active: {user.is_active}")
   print(f"Email verified: {user.emailaddress_set.filter(verified=True).exists()}")
   ```

3. **Account suspended/banned**
   ```python
   # Check master rules
   profile = user.updspaceuser
   print(f"Suspended: {profile.suspended}")
   print(f"Banned: {profile.banned}")
   ```

4. **Rate limited**
   - Check logs for rate limit messages
   - Clear rate limit cache if needed (see Runbook)

### Problem: "RATE_LIMIT_EXCEEDED" Error

**Symptoms:**
- Error: `{"code": "RATE_LIMIT_EXCEEDED", "retry_after": 300}`

**Solution:**
- Wait for `retry_after` seconds
- If legitimate user, clear rate limit:
  ```python
  from django.core.cache import cache
  cache.delete(f"rl:login:ip:{user_ip}")
  cache.delete(f"rl:login:email:{user_email}")
  ```

### Problem: Session Not Persisting

**Symptoms:**
- User gets logged out immediately
- Session cookie not being set

**Possible Causes & Solutions:**

1. **Cookie settings mismatch**
   - Check `SESSION_COOKIE_SAMESITE` setting
   - For cross-site requests, may need `SameSite=None; Secure`

2. **HTTPS not configured**
   - `SESSION_COOKIE_SECURE=true` requires HTTPS
   - In development, set to `false`

3. **Frontend not sending credentials**
   ```typescript
   // Ensure fetch includes credentials
   fetch('/api/v1/auth/login', {
     method: 'POST',
     credentials: 'include',  // Required!
     headers: { 'Content-Type': 'application/json' },
     body: JSON.stringify(data)
   })
   ```

### Problem: "Неверный или просроченный токен формы"

**Symptoms:**
- Login/signup returns code `INVALID_FORM_TOKEN`
- Message: `Неверный или просроченный токен формы`

**Cause:** `/api/v1/auth/login` and `/api/v1/auth/signup` require a single-use `form_token` from `/api/v1/auth/form_token`.

**Correct flow:**
```typescript
const tokenResp = await fetch('/api/v1/auth/form_token?purpose=login', {
  method: 'GET',
  credentials: 'include',
});
const { form_token } = await tokenResp.json();

const loginResp = await fetch('/api/v1/auth/login', {
  method: 'POST',
  credentials: 'include',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    email,
    password,
    mfa_code,       // optional
    recovery_code,  // optional
    form_token,
  }),
});
```

**Server-side checks:**
```bash
# Check token rejections in logs
rg -n "Form token rejected|Form token expired|Form token reused" /var/log/id-service*.log
```

**Important:**
- Token TTL is 15 minutes
- Token is single-use
- `purpose=login` token cannot be used for `signup` and vice versa

---

## MFA Issues

### Problem: "TOTP_SETUP_REQUIRED" Error

**Symptoms:**
- User sees `TOTP_SETUP_REQUIRED` after entering TOTP code
- MFA setup not completing

**Cause:** Session secret lost between setup begin and confirm.

**Solution:**
```bash
# Check if user has partial MFA setup
python src/manage.py shell

from allauth.mfa.models import Authenticator
from django.contrib.auth import get_user_model

User = get_user_model()
user = User.objects.get(email='user@example.com')

# List authenticators
for auth in Authenticator.objects.filter(user=user):
    print(f"Type: {auth.type}, Created: {auth.created_at}")

# If stuck, delete partial and retry
Authenticator.objects.filter(user=user, type='totp').delete()
```

### Problem: "INVALID_CODE" for TOTP

**Symptoms:**
- User enters TOTP code, gets invalid error
- Code appears correct in authenticator app

**Possible Causes & Solutions:**

1. **Time sync issue**
   - Server time must be accurate (NTP)
   - User device time must be accurate
   - TOTP has 30-second window

2. **Wrong authenticator entry**
   - User may have multiple entries
   - Delete and re-enroll

3. **Secret mismatch**
   ```python
   # Verify TOTP secret exists
   from allauth.mfa.models import Authenticator
   auth = Authenticator.objects.get(user=user, type='totp')
   print(f"Has secret: {bool(auth.data.get('secret'))}")
   ```

### Problem: "MFA_REQUIRED" When Using Recovery Code

**Symptoms:**
- User trying to use recovery code gets MFA_REQUIRED

**Cause:** Recovery codes require `reauthenticate` flow.

**Solution:**
- User must first authenticate with password
- Then use recovery code in MFA step
- If locked out, admin can disable MFA:
  ```python
  from allauth.mfa.models import Authenticator
  Authenticator.objects.filter(user=user).delete()
  ```

---

## OIDC Issues

### Problem: "invalid_client" Error

**Symptoms:**
- OIDC flow fails with `invalid_client`
- Token exchange returns 401

**Possible Causes & Solutions:**

1. **Client not found**
   ```python
   from idp.models import OidcClient
   try:
       client = OidcClient.objects.get(client_id='your-client-id')
       print(f"Found: {client.name}")
   except OidcClient.DoesNotExist:
       print("Client not registered!")
   ```

2. **Wrong client_secret**
   ```python
   # Verify secret (don't log actual secret!)
   import hashlib
   provided_hash = hashlib.sha256(provided_secret.encode()).hexdigest()[:16]
   stored_hash = hashlib.sha256(client.client_secret.encode()).hexdigest()[:16]
   print(f"Match: {provided_hash == stored_hash}")
   ```

3. **Client is disabled**
   ```python
   print(f"Active: {client.is_active}")
   ```

### Problem: "invalid_redirect_uri" Error

**Symptoms:**
- Authorization request fails
- Error: `redirect_uri not in allowed list`

**Solution:**
```python
from idp.models import OidcClient
client = OidcClient.objects.get(client_id='your-client-id')
print(f"Allowed URIs: {client.redirect_uris}")

# Add new URI
uris = client.redirect_uris or []
uris.append('https://new-app.example.com/callback')
client.redirect_uris = uris
client.save()
```

### Problem: JWT Signature Verification Failed

**Symptoms:**
- Resource servers reject tokens
- Error: `invalid signature`

**Possible Causes & Solutions:**

1. **JWKS not updated after key rotation**
   - Resource servers should fetch JWKS periodically
   - Force refresh: clear JWKS cache on resource server

2. **Key mismatch**
   ```bash
   # Check JWKS endpoint
   curl https://id.updspace.com/.well-known/jwks.json | jq '.keys[].kid'
   
   # Compare with token
   # Decode JWT header to get kid
   ```

3. **Wrong issuer**
   - Token `iss` claim must match `OIDC_ISSUER` setting
   - Check for trailing slashes

### Problem: Refresh Token Invalid

**Symptoms:**
- Refresh token exchange fails
- Error: `invalid_grant`

**Possible Causes:**

1. **Token expired** - Refresh tokens have 30-day lifetime by default
2. **Token already used** - Rotation enabled, token was already exchanged
3. **Token revoked** - User logged out or admin revoked

**Diagnosis:**
```python
from idp.models import OidcToken
# Note: Tokens are hashed, need to search by user/client
```

---

## OAuth Provider Issues

### Problem: "PROVIDER_CIRCUIT_OPEN" Error

**Symptoms:**
- Error 503: `OAuth provider is temporarily unavailable`
- Users cannot link OAuth accounts

**Cause:** Circuit breaker triggered due to provider failures.

**Solution:**
1. Check provider status (GitHub Status, Discord Status)
2. Wait for automatic recovery (60 seconds)
3. Manual reset if needed:
   ```python
   from core.resilience import CircuitBreaker
   cb = CircuitBreaker.get("github_oauth")
   print(f"State: {cb.stats.state}, Failures: {cb.stats.total_failures}")
   
   # Manual reset (use with caution)
   from core.resilience import CircuitState
   cb.stats.state = CircuitState.CLOSED
   cb.stats.failure_count = 0
   ```

### Problem: "PROVIDER_NOT_CONFIGURED" Error

**Symptoms:**
- OAuth login/link returns 501
- Error: `Provider integration is not configured`

**Solution:**
Check environment variables:
```bash
# For GitHub
echo $GITHUB_CLIENT_ID
echo $GITHUB_CLIENT_SECRET

# For Discord  
echo $DISCORD_CLIENT_ID
echo $DISCORD_CLIENT_SECRET
```

### Problem: OAuth Callback Fails

**Symptoms:**
- User redirected back with error
- Error in logs: `state mismatch` or `code invalid`

**Possible Causes:**

1. **Session expired during OAuth flow**
   - User took too long
   - Session cookie not persisted

2. **Redirect URI mismatch**
   - Check provider's registered callback URLs
   - Must exactly match including trailing slashes

3. **CSRF state mismatch**
   - Browser may have blocked cookies
   - Try in incognito mode

---

## Performance Issues

### Problem: Slow Response Times

**Symptoms:**
- API latency > 500ms
- Health check shows high latency

**Diagnosis:**

1. **Check database latency**
   ```bash
   curl https://id.updspace.com/health | jq '.components[] | select(.name=="database")'
   ```

2. **Check cache latency**
   ```bash
   curl https://id.updspace.com/health | jq '.components[] | select(.name=="cache")'
   ```

3. **Check for N+1 queries** (development)
   ```python
   # Enable query logging
   import logging
   logging.getLogger('django.db.backends').setLevel(logging.DEBUG)
   ```

**Solutions:**
- Scale up replicas if CPU-bound
- Add database indexes if query-bound
- Increase cache TTLs if cache-miss heavy

### Problem: High Memory Usage

**Symptoms:**
- Pods being OOMKilled
- Memory usage > 80%

**Solutions:**
1. Increase memory limits
2. Check for memory leaks (use `tracemalloc`)
3. Reduce worker count if using gunicorn

---

## Configuration Issues

### Problem: "SECURITY ERROR: DJANGO_SECRET_KEY must be set"

**Symptoms:**
- Service fails to start in production
- Error in logs about SECRET_KEY

**Cause:** Production mode requires explicit secret key.

**Solution:**
```bash
# Generate new key
python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"

# Set in environment/secret
export DJANGO_SECRET_KEY="your-generated-key"
```

### Problem: CORS Errors

**Symptoms:**
- Browser shows CORS error
- Preflight requests failing

**Solution:**
Check `CORS_ALLOWED_ORIGINS`:
```bash
# In settings or environment
CORS_ALLOWED_ORIGINS=https://portal.updspace.com,https://id.updspace.com
```

For development:
```python
# settings.py (development only!)
CORS_ALLOW_ALL_ORIGINS = True
```

### Problem: Email Not Sending

**Symptoms:**
- Activation emails not received
- No errors in logs

**Diagnosis:**
```python
# Test email sending
from django.core.mail import send_mail
send_mail(
    'Test',
    'Test message',
    'no-reply@updspace.com',
    ['test@example.com'],
    fail_silently=False,
)
```

**Check configuration:**
```bash
echo $EMAIL_BACKEND
echo $EMAIL_HOST
echo $EMAIL_PORT
```

---

## Getting Help

If this guide doesn't resolve your issue:

1. Check logs with correlation ID
2. Review recent deployments/changes
3. Contact on-call engineer via PagerDuty
4. For security issues, contact security@updspace.com immediately
