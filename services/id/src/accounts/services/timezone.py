"""
Timezone service for managing user timezone preferences.
Uses pytz for timezone validation and data.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache

import pytz

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class TimezoneInfo:
    """Information about a timezone."""

    name: str
    display_name: str
    offset: str
    offset_seconds: int


@lru_cache(maxsize=1)
def _timezones_at_minute(instant: datetime) -> tuple[TimezoneInfo, ...]:
    """Cache only public metadata; replace the entry every UTC minute for DST."""
    result = []
    for name in pytz.common_timezones:
        tz = pytz.timezone(name)
        # Convert one real instant to each zone. Localizing naive wall time can
        # omit zones during a DST gap/fold or calculate the wrong current offset.
        offset = instant.astimezone(tz).utcoffset()
        if offset is None:
            continue
        seconds = int(offset.total_seconds())
        hours, remainder = divmod(abs(seconds), 3600)
        minutes = remainder // 60
        sign = "-" if seconds < 0 else "+"
        text = f"{sign}{hours:02d}:{minutes:02d}"
        result.append(
            TimezoneInfo(
                name=name,
                display_name=f"{name} (UTC{text})",
                offset=text,
                offset_seconds=seconds,
            )
        )
    return tuple(sorted(result, key=lambda item: (item.offset_seconds, item.name)))


@dataclass(slots=True)
class TimezoneService:
    """Service for managing timezone operations."""

    @staticmethod
    def get_all_timezones() -> list[TimezoneInfo]:
        instant = datetime.now(timezone.utc).replace(second=0, microsecond=0)
        # Return a new list so callers cannot mutate the cached ordering.
        return list(_timezones_at_minute(instant))

    @staticmethod
    def validate_timezone(timezone_name: str | None) -> bool:
        """
        Validate if the timezone name is valid.
        Returns True if valid, False otherwise.
        """
        if not timezone_name:
            return True  # Empty timezone is allowed

        timezone_name = timezone_name.strip()
        if not timezone_name:
            return True

        return timezone_name in pytz.common_timezones

    @staticmethod
    def normalize_timezone(timezone_name: str | None) -> str:
        """
        Normalize timezone name (trim whitespace).
        Returns empty string if invalid.
        """
        if not timezone_name:
            return ""

        timezone_name = timezone_name.strip()

        if not timezone_name:
            return ""

        if timezone_name not in pytz.common_timezones:
            logger.warning(f"Invalid timezone name: {timezone_name}")
            return ""

        return timezone_name

    @staticmethod
    def detect_timezone_from_browser(browser_timezone: str | None) -> str:
        """
        Detect and validate timezone from browser's
        Intl.DateTimeFormat().resolvedOptions().timeZone
        Returns normalized timezone name or empty string if invalid.
        """
        if not browser_timezone:
            return ""

        # Browser typically sends IANA timezone names like "Europe/Moscow"
        normalized = TimezoneService.normalize_timezone(browser_timezone)

        if normalized:
            logger.info(f"Detected timezone from browser: {normalized}")
            return normalized

        # If browser sent invalid timezone, log and return empty
        logger.warning(f"Invalid timezone from browser: {browser_timezone}")
        return ""

    @staticmethod
    def get_timezone_groups() -> dict[str, list[TimezoneInfo]]:
        """
        Get timezones grouped by region (first part of name before /).
        Returns dict where key is region name and value is list of timezones.
        """
        all_timezones = TimezoneService.get_all_timezones()
        groups: dict[str, list[TimezoneInfo]] = {}

        for tz_info in all_timezones:
            # Split by "/" and use first part as region
            parts = tz_info.name.split("/", 1)
            region = parts[0] if len(parts) > 1 else "Other"

            if region not in groups:
                groups[region] = []

            groups[region].append(tz_info)

        return groups
