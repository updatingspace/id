from unittest.mock import patch

import pytest

from app.jobs import application

pytestmark = pytest.mark.django_db(transaction=True)


def invoke(path="/refresh-gravatars", method="POST"):
    responses = []
    body = application(
        {"PATH_INFO": path, "REQUEST_METHOD": method},
        lambda status, headers: responses.append((status, headers)),
    )
    return responses[0][0], b"".join(body)


def test_job_runs_fixed_bounded_command(monkeypatch):
    monkeypatch.setenv("GRAVATAR_BATCH_LIMIT", "25")
    with patch("app.jobs.call_command") as command:
        assert invoke() == ("200 OK", b"Completed")
        command.assert_called_once_with("refresh_gravatars", limit=25)


def test_job_failure_is_retryable_without_exposing_exception():
    with patch("app.jobs.call_command", side_effect=RuntimeError("private detail")):
        assert invoke() == ("500 Internal Server Error", b"Job failed")


@pytest.mark.parametrize(
    "path,method,status", [("/", "POST", "404"), ("/refresh-gravatars", "GET", "405")]
)
def test_job_rejects_other_requests(path, method, status):
    with patch("app.jobs.call_command") as command:
        assert invoke(path, method)[0].startswith(status)
        command.assert_not_called()


@pytest.mark.parametrize("limit", ["0", "101", "invalid"])
def test_job_rejects_invalid_batch_limit(monkeypatch, limit):
    monkeypatch.setenv("GRAVATAR_BATCH_LIMIT", limit)
    with patch("app.jobs.call_command") as command:
        assert invoke()[0].startswith("500")
        command.assert_not_called()
