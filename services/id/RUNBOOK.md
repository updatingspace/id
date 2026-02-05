# UpdSpace ID Service - Operations Runbook

This document provides operational procedures for the UpdSpace ID Service in production environments.

## Table of Contents

1. [Quick Reference](#quick-reference)
2. [Health Monitoring](#health-monitoring)
3. [Common Operations](#common-operations)
4. [Incident Response](#incident-response)
5. [Key Rotation](#key-rotation)
6. [Database Operations](#database-operations)
7. [Scaling Guidelines](#scaling-guidelines)

---

## Quick Reference

### Service Endpoints

| Environment | URL | Health Check |
|-------------|-----|--------------|
| Production | https://id.updspace.com | /health |
| Staging | https://id.staging.updspace.com | /health |

### Critical Metrics to Monitor

```
# Authentication failure rate (alert if > 10%)
id_auth_login_failure_total / id_auth_login_attempts_total

# OIDC token issuance rate
rate(id_oidc_token_issued_total[5m])

# Rate limit triggers (alert if sustained)
rate(id_rate_limit_triggered_total[5m])

# Request latency p99 (alert if > 500ms)
histogram_quantile(0.99, id_http_request_duration_seconds_bucket)
```

### Emergency Contacts

| Role | Contact |
|------|---------|
| On-call Engineer | PagerDuty |
| Security Team | security@updspace.com |
| Database Admin | dba@updspace.com |

---

## Health Monitoring

### Health Check Endpoints

```bash
# Liveness probe (is the service running?)
curl https://id.updspace.com/healthz

# Readiness probe (is the service ready?)
curl https://id.updspace.com/readyz

# Detailed health status
curl https://id.updspace.com/health
```

### Expected Health Response

```json
{
  "status": "healthy",
  "version": "1.0.0",
  "uptime_seconds": 86400,
  "components": [
    {"name": "database", "status": "healthy", "latency_ms": 2.5},
    {"name": "cache", "status": "healthy", "latency_ms": 1.2},
    {"name": "oidc_keys", "status": "healthy", "details": {"key_count": 2}},
    {"name": "email", "status": "healthy"}
  ]
}
```

### Status Meanings

- **healthy**: All systems operational
- **degraded**: Service operational but with reduced functionality
- **unhealthy**: Service cannot handle requests

---

## Common Operations

### 1. Manually Activate a User

When a user needs manual activation (e.g., lost activation email):

```bash
# Connect to pod
kubectl exec -it deployment/id-service -n updspace-id -- bash

# Django shell
python src/manage.py shell

# In shell:
from django.contrib.auth import get_user_model
from updspaceid.models import Application, ActivationToken

User = get_user_model()
app = Application.objects.get(email='user@example.com')

# Create activation token manually
token = ActivationToken.create_for_application(app)
print(f"Activation URL: https://id.updspace.com/activate?token={token.token}")

# Or activate directly
from updspaceid.services import ApplicationService
ApplicationService.activate_user_from_application(app, "Manually activated by admin")
```

### 2. Revoke All Sessions for a User

When a user reports compromised credentials:

```bash
python src/manage.py shell

from django.contrib.auth import get_user_model
from allauth.usersessions.models import UserSession

User = get_user_model()
user = User.objects.get(email='user@example.com')

# Revoke all sessions
UserSession.objects.filter(user=user).delete()

# Also invalidate refresh tokens
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken
OutstandingToken.objects.filter(user=user).delete()

print(f"Revoked all sessions for user {user.email}")
```

### 3. Check OIDC Client Configuration

```bash
python src/manage.py shell

from idp.models import OidcClient

# List all clients
for client in OidcClient.objects.all():
    print(f"ID: {client.client_id}")
    print(f"Name: {client.name}")
    print(f"Redirect URIs: {client.redirect_uris}")
    print(f"Allowed scopes: {client.allowed_scopes}")
    print("---")
```

### 4. View Recent Login Events

```bash
python src/manage.py shell

from accounts.models import LoginEvent
from django.utils import timezone
from datetime import timedelta

# Last 24 hours
recent = LoginEvent.objects.filter(
    created_at__gte=timezone.now() - timedelta(days=1)
).order_by('-created_at')[:100]

for event in recent:
    print(f"{event.created_at} | {event.user.email if event.user else 'Unknown'} | {event.ip_address} | {event.success}")
```

### 5. Reset Rate Limits for IP/User

```bash
python src/manage.py shell

from django.core.cache import cache

# Clear rate limit for specific IP
ip = "192.168.1.100"
for scope in ["login", "register", "oidc_token", "oidc_userinfo", "oidc_authorize"]:
    cache.delete(f"rl:{scope}:ip:{ip}")

print(f"Rate limits cleared for IP {ip}")
```

---

## Incident Response

### High Authentication Failure Rate

**Symptoms:**
- Alert: `id_auth_login_failure_rate > 0.1`
- Users reporting login failures

**Investigation:**

```bash
# Check recent failure reasons
python src/manage.py shell

from accounts.models import LoginEvent
from django.utils import timezone
from datetime import timedelta
from django.db.models import Count

# Failures by reason in last hour
failures = LoginEvent.objects.filter(
    success=False,
    created_at__gte=timezone.now() - timedelta(hours=1)
).values('failure_reason').annotate(count=Count('id')).order_by('-count')

for f in failures:
    print(f"{f['failure_reason']}: {f['count']}")
```

**Resolution:**
1. If credential stuffing attack: Enable enhanced rate limiting
2. If database issue: Check database connectivity
3. If configuration issue: Verify DJANGO_SECRET_KEY hasn't changed

### OIDC Token Endpoint Errors

**Symptoms:**
- Alert: `id_oidc_token_issued_success_rate < 0.95`
- BFF/clients reporting token exchange failures

**Investigation:**

```bash
# Check recent OIDC errors in logs
kubectl logs deployment/id-service -n updspace-id | grep "OIDC" | tail -100

# Check OIDC signing keys
python src/manage.py shell

from idp.keys import KeyManager
jwks = KeyManager.jwks()
print(f"Active keys: {len(jwks['keys'])}")
for key in jwks['keys']:
    print(f"  Kid: {key['kid']}, Alg: {key['alg']}")
```

**Resolution:**
1. If keys expired: Rotate OIDC keys (see Key Rotation section)
2. If client misconfigured: Verify client_id/client_secret
3. If redirect_uri mismatch: Check OIDC client configuration

### Database Connection Issues

**Symptoms:**
- Health check shows database unhealthy
- 500 errors on all endpoints

**Investigation:**

```bash
# Check database connectivity
kubectl exec -it deployment/id-service -n updspace-id -- python src/manage.py dbshell

# Check connection pool status
kubectl exec -it deployment/id-service -n updspace-id -- python -c "
from django.db import connection
cursor = connection.cursor()
cursor.execute('SELECT count(*) FROM pg_stat_activity')
print(f'Active connections: {cursor.fetchone()[0]}')
"
```

**Resolution:**
1. If connection limit reached: Increase `max_connections` in PostgreSQL
2. If database down: Check PostgreSQL pod/service
3. If network issue: Verify DNS resolution and network policies

### Circuit Breaker Open for OAuth Provider

**Symptoms:**
- Users cannot link GitHub/Discord accounts
- Logs show "circuit breaker open"

**Investigation:**

```bash
# Check circuit breaker status
python src/manage.py shell

from core.resilience import CircuitBreaker
print(CircuitBreaker.get_all_stats())
```

**Resolution:**
1. Wait for automatic recovery (60 seconds timeout)
2. If provider is down: Monitor provider status page
3. Manual reset (use with caution):

```python
from core.resilience import CircuitBreaker
cb = CircuitBreaker.get("github_oauth")
cb.stats.state = "closed"
cb.stats.failure_count = 0
```

---

## Key Rotation

### OIDC Signing Key Rotation

**When to rotate:**
- Scheduled: Every 90 days
- Emergency: Key compromise suspected

**Procedure:**

1. Generate new key pair:
```bash
# Generate RSA key pair
openssl genrsa -out new_private.pem 2048
openssl rsa -in new_private.pem -pubout -out new_public.pem
```

2. Update Kubernetes secret:
```bash
# Base64 encode keys
PRIVATE_KEY=$(cat new_private.pem | base64 -w 0)
PUBLIC_KEY=$(cat new_public.pem | base64 -w 0)

# Update secret
kubectl patch secret id-service-secrets -n updspace-id --type='json' -p="[
  {\"op\": \"replace\", \"path\": \"/data/OIDC_PRIVATE_KEY_PEM\", \"value\": \"$PRIVATE_KEY\"},
  {\"op\": \"replace\", \"path\": \"/data/OIDC_PUBLIC_KEY_PEM\", \"value\": \"$PUBLIC_KEY\"}
]"
```

3. Rolling restart:
```bash
kubectl rollout restart deployment/id-service -n updspace-id
kubectl rollout status deployment/id-service -n updspace-id
```

4. Verify:
```bash
curl https://id.updspace.com/.well-known/jwks.json | jq '.keys | length'
```

**Note:** Old keys should remain valid for token verification during transition. The service supports multiple keys via `OIDC_KEY_PAIRS` environment variable.

### Django SECRET_KEY Rotation

**⚠️ Warning:** Rotating SECRET_KEY will invalidate all existing sessions!

1. Generate new key:
```bash
python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"
```

2. Schedule maintenance window
3. Update secret and restart
4. Users will need to re-authenticate

---

## Database Operations

### Running Migrations

```bash
# Via Kubernetes Job (recommended)
kubectl apply -f k8s/jobs.yaml

# Or manually
kubectl exec -it deployment/id-service -n updspace-id -- python src/manage.py migrate
```

### Database Backup

```bash
# Create backup
kubectl exec -it postgres-0 -n updspace-id -- pg_dump -U postgres id_service > backup_$(date +%Y%m%d).sql

# Restore (caution!)
kubectl exec -i postgres-0 -n updspace-id -- psql -U postgres id_service < backup_20260116.sql
```

### Clear Expired Sessions

```bash
# Manual cleanup
kubectl exec -it deployment/id-service -n updspace-id -- python src/manage.py clearsessions

# This also runs daily via CronJob
```

---

## Scaling Guidelines

### When to Scale

| Metric | Threshold | Action |
|--------|-----------|--------|
| CPU > 70% sustained | 5 minutes | Scale up |
| Memory > 80% | Immediate | Scale up |
| Request latency p99 > 500ms | 5 minutes | Scale up |
| Queue depth > 100 | Immediate | Scale up |

### Manual Scaling

```bash
# Scale to specific replica count
kubectl scale deployment/id-service -n updspace-id --replicas=5

# View current status
kubectl get hpa id-service -n updspace-id
```

### Capacity Planning

- Each pod handles ~500 req/s at p99 < 100ms
- Recommended: 2 pods minimum for HA
- Peak load: 4-6 pods
- Max tested: 10 pods

---

## Appendix: Useful Commands

```bash
# View logs
kubectl logs -f deployment/id-service -n updspace-id

# View logs with correlation ID filter
kubectl logs deployment/id-service -n updspace-id | grep "correlation_id.*abc123"

# Port forward for local debugging
kubectl port-forward svc/id-service -n updspace-id 8001:80

# Get pod status
kubectl get pods -n updspace-id -l app=id-service

# Describe pod (for troubleshooting)
kubectl describe pod -n updspace-id -l app=id-service

# View metrics
curl http://localhost:8001/metrics
```
