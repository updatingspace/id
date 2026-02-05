"""
Timezone service for managing user timezone preferences.
Uses pytz for timezone validation and data.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime

import pytz

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class TimezoneInfo:
    """Information about a timezone."""

    name: str
    display_name: str
    offset: str
    offset_seconds: int


@dataclass(slots=True)
class TimezoneService:
    """Service for managing timezone operations."""

    @staticmethod
    def get_all_timezones() -> list[TimezoneInfo]:
        """
        Get all available timezones with their display information.
        Returns a list sorted by offset and then by name.
        """
        # Use naive datetime for pytz offset calculation
        now = datetime.now()
        timezones_info = []

        for tz_name in pytz.common_timezones:
            try:
                tz = pytz.timezone(tz_name)
                offset = tz.utcoffset(now)
                if offset is None:
                    continue

                offset_seconds = int(offset.total_seconds())
                offset_hours = offset_seconds // 3600
                offset_minutes = abs(offset_seconds % 3600) // 60

                # Format offset as "+HH:MM" or "-HH:MM"
                offset_str = f"{offset_hours:+03d}:{offset_minutes:02d}"

                # Create display name: "Europe/Moscow (UTC+03:00)"
                display_name = f"{tz_name} (UTC{offset_str})"

                timezones_info.append(
                    TimezoneInfo(
                        name=tz_name,
                        display_name=display_name,
                        offset=offset_str,
                        offset_seconds=offset_seconds,
                    )
                )
            except Exception as e:
                logger.warning(f"Failed to process timezone {tz_name}: {e}")
                continue

        # Sort by offset first, then by name
        timezones_info.sort(key=lambda x: (x.offset_seconds, x.name))
        return timezones_info

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
