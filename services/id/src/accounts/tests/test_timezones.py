from datetime import datetime
from unittest.mock import patch

import pytest

from accounts.services.timezone import TimezoneService, _timezones_at_minute


@pytest.fixture(autouse=True)
def isolated_timezone_cache():
    _timezones_at_minute.cache_clear()
    yield
    _timezones_at_minute.cache_clear()


def zones_at(instant: str):
    with patch("accounts.services.timezone.datetime") as clock:
        clock.now.return_value = datetime.fromisoformat(instant)
        return {item.name: item for item in TimezoneService.get_all_timezones()}


def test_offsets_preserve_the_sign_of_negative_fractional_hours():
    zones = zones_at("2026-09-23T00:00:00+00:00")
    assert zones["America/St_Johns"].offset == "-02:30"
    assert zones["America/St_Johns"].offset_seconds == -9000
    assert zones["Asia/Kathmandu"].offset == "+05:45"
    assert zones["UTC"].offset == "+00:00"


def test_current_offsets_follow_real_utc_instants_across_dst_folds():
    before = zones_at("2026-11-01T05:59:59+00:00")
    after = zones_at("2026-11-01T06:00:00+00:00")
    assert before["America/New_York"].offset == "-04:00"
    assert after["America/New_York"].offset == "-05:00"
    assert set(before) == set(after)


def test_dst_gap_does_not_remove_a_zone():
    before = zones_at("2026-03-08T06:59:59+00:00")
    after = zones_at("2026-03-08T07:00:00+00:00")
    assert before["America/New_York"].offset == "-05:00"
    assert after["America/New_York"].offset == "-04:00"
    assert set(before) == set(after)


def test_warm_calls_reuse_metadata_without_sharing_a_mutable_list():
    with patch("accounts.services.timezone.datetime") as clock:
        clock.now.return_value = datetime.fromisoformat("2026-09-23T00:00:01+00:00")
        first = TimezoneService.get_all_timezones()
        expected = list(first)
        first.clear()
        clock.now.return_value = datetime.fromisoformat("2026-09-23T00:00:59+00:00")
        with patch("accounts.services.timezone.pytz.timezone") as load_zone:
            second = TimezoneService.get_all_timezones()
            load_zone.assert_not_called()
        assert second == expected
        assert second == sorted(
            second, key=lambda item: (item.offset_seconds, item.name)
        )
