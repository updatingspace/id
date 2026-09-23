# Profile before tenant selection

`GET /api/v1/me` accepts a tenantless internal request from Portal BFF with a valid
`X-Updspace-Signature`, timestamp, request ID and canonical UUID in `X-User-Id`.
It returns the active principal and only that principal's active memberships.
The request does not create identities, tenants, memberships, profiles or preferences.
Account profile fields are read through the existing immutable identity binding;
matching email addresses never establish ownership.

Missing/invalid signatures and unknown users return 401; missing request IDs and malformed user IDs return
400; suspended or banned users return 403. If either tenant header is present,
the normal tenant-context and membership checks apply. Incomplete headers return
400 and never fall back to the global response. A scoped response remains limited
to its selected tenant.

The internal signature authenticates the trusted BFF caller. The existing HMAC
format does not bind context headers; changing that protocol is outside this patch.
The caller must supply the authenticated session's canonical user ID, never a value
chosen directly from a public request header.

Avatar URLs from private S3 storage retain their original host, path and signature.
Only relative local-media URLs are resolved against the public ID origin. The
managed Yandex Cloud stack keeps media private and enables signed object URLs;
the standalone S3 storage configuration also defaults to signing. Disable
`S3_QUERYSTRING_AUTH` only for an intentionally public media bucket.
