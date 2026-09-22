from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend


class EmailBackend(ModelBackend):
    """Authenticate the canonical email without resolving a legacy username."""

    def authenticate(self, request, *, email=None, password=None, **kwargs):
        if email is None or password is None:
            return None
        User = get_user_model()
        user = User.objects.filter(email__iexact=email.strip()).first()
        if user is None:
            # Keep the password-hashing work for unknown addresses as in Django.
            User().set_password(password)
            return None
        if user.check_password(password) and self.user_can_authenticate(user):
            return user
        return None
