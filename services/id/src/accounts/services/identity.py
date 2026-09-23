"""One-time identity binding; subsequent email changes never resolve a new owner."""

from allauth.account.models import EmailAddress
from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction
from django.db.models import Q
from ninja.errors import HttpError

from accounts.models import AccountIdentity
from updspaceid.enums import UserStatus
from updspaceid.models import User as UpdspaceUser


def _conflict(*, verification_required: bool = False) -> HttpError:
    return HttpError(
        409,
        {
            "code": "IDENTITY_VERIFICATION_REQUIRED"
            if verification_required
            else "IDENTITY_LINK_CONFLICT",
            "message": "Identity ownership requires review",
        },
    )


def _verified_email(user) -> str | None:
    email = (user.email or "").strip().lower()
    if (
        not email
        or not EmailAddress.objects.filter(
            user=user, email__iexact=email, verified=True, primary=True
        ).exists()
    ):
        return None
    if (
        get_user_model()
        .objects.filter(email__iexact=email)
        .exclude(pk=user.pk)
        .exists()
    ):
        raise _conflict()
    return email


@transaction.atomic
def resolve_identity(
    user, *, create: bool = True, provision: bool = True
) -> AccountIdentity | None:
    binding = (
        AccountIdentity.objects.select_related("identity").filter(user=user).first()
    )
    if binding is not None:
        ownership = Q(public_subject=binding.public_subject)
        if binding.identity_id:
            ownership |= Q(identity_id=binding.identity_id)
        if AccountIdentity.objects.filter(ownership).exclude(pk=binding.pk).exists():
            raise _conflict()
        return (
            _ensure_global_identity(user, binding) if create and provision else binding
        )
    if not create:
        return binding
    # Email is a one-time migration aid requiring ownership proof. No email join
    # occurs after this record exists, including a binding with no master identity.
    email = _verified_email(user)
    candidate = None
    if (
        not email
        and UpdspaceUser.objects.filter(
            email__iexact=(user.email or "").strip()
        ).exists()
    ):
        # An unverified address cannot claim an existing identity or sidestep
        # its suspension by creating an unrelated fallback principal.
        raise _conflict(verification_required=True)
    if email:
        candidates = list(UpdspaceUser.objects.filter(email__iexact=email)[:2])
        if len(candidates) > 1:
            raise _conflict()
        candidate = candidates[0] if candidates else None
    if (
        candidate
        and AccountIdentity.objects.filter(identity=candidate)
        .exclude(user=user)
        .exists()
    ):
        raise _conflict()
    # Old binaries used an exact match against the normalized Django email.
    # Ownership may safely match case-insensitively, but the public subject must
    # retain the value those binaries actually issued before this migration.
    subject = (
        str(candidate.pk) if candidate and candidate.email == email else str(user.pk)
    )
    try:
        with transaction.atomic():
            binding, _ = AccountIdentity.objects.get_or_create(
                user=user, defaults={"identity": candidate, "public_subject": subject}
            )
    except (IntegrityError, ValueError) as exc:
        raise _conflict() from exc
    return _ensure_global_identity(user, binding) if provision else binding


def _ensure_global_identity(user, binding: AccountIdentity) -> AccountIdentity:
    """Provision a verified global principal, without granting tenant access.

    A previously issued public subject stays opaque and unchanged. An empty
    binding may only gain a newly created identity, never an email-matched one
    that appeared after that binding was established.
    """
    if binding.identity_id or not user.is_active:
        return binding
    binding = AccountIdentity.objects.select_for_update().get(pk=binding.pk)
    if binding.identity_id:
        return binding
    email = _verified_email(user)
    existing = UpdspaceUser.objects.filter(
        email__iexact=email or (user.email or "").strip()
    ).exists()
    if existing:
        raise _conflict(verification_required=not bool(email))
    if not email or not settings.ID_GLOBAL_IDENTITY_PROVISIONING:
        return binding
    display_name = f"{user.first_name or ''} {user.last_name or ''}".strip()
    username = (user.username or email.split("@")[0])[:64]
    try:
        with transaction.atomic():
            identity = UpdspaceUser.objects.create(
                email=email,
                email_verified=True,
                username=username,
                display_name=(display_name or username)[:128],
                status=UserStatus.ACTIVE,
                system_admin=bool(user.is_staff or user.is_superuser),
            )
            return attach_identity(binding, identity)
    except IntegrityError as exc:
        raise _conflict() from exc


def backfill_identity_bindings(*, using: str = "default") -> dict[str, int]:
    """Resumable YDB rollout backfill; each principal has its own transaction.

    This only freezes legacy subjects: it never creates master identities, even
    when runtime provisioning is enabled. Existing bindings are never rewritten.
    Unverified legacy matches remain
    blocked at runtime; ambiguous verified matches stop the rollout for review.
    """
    if using != "default":
        raise ValueError("Identity binding backfill supports the default database only")
    counts = {"created": 0, "existing": 0, "verification_required": 0}
    for user in get_user_model().objects.all().iterator():
        if AccountIdentity.objects.filter(user=user).exists():
            counts["existing"] += 1
            continue
        try:
            resolve_identity(user, provision=False)
        except HttpError as exc:
            if exc.message.get("code") != "IDENTITY_VERIFICATION_REQUIRED":
                raise
            counts["verification_required"] += 1
        else:
            counts["created"] += 1
    return counts


@transaction.atomic
def attach_identity(
    binding: AccountIdentity, identity: UpdspaceUser
) -> AccountIdentity:
    """Complete an explicitly verified link without changing its public subject."""
    binding = AccountIdentity.objects.select_for_update().get(pk=binding.pk)
    if binding.identity_id == identity.pk:
        return binding
    if binding.identity_id is not None:
        raise _conflict()
    email = _verified_email(binding.user)
    if not email or email != identity.email.strip().lower():
        raise _conflict()
    if (
        AccountIdentity.objects.filter(identity=identity)
        .exclude(pk=binding.pk)
        .exists()
    ):
        raise _conflict()
    binding.identity = identity
    try:
        with transaction.atomic():
            binding.save(update_fields=["identity"])
    except (IntegrityError, ValueError) as exc:
        raise _conflict() from exc
    return binding
