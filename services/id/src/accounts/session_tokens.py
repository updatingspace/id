from allauth.headless.internal import sessionkit
from allauth.headless.tokens.strategies.sessions import SessionTokenStrategy
from django.contrib.sessions.backends.base import SessionBase


class LoadedSessionTokenStrategy(SessionTokenStrategy):
    """Load and validate a session without a separate existence query."""

    def lookup_session(self, session_token: str) -> SessionBase | None:
        session = sessionkit.session_store(session_key=session_token)
        # Django loads, verifies and checks expiry here, retaining the data on
        # this SessionStore only. A fresh lookup still observes revocation.
        session.get("_auth_user_id")
        return session if session.session_key else None
