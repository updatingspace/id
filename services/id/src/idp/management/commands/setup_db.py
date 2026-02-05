"""
Management command for initial database setup including cache table creation.

Usage:
    python manage.py setup_db
"""

from django.conf import settings
from django.contrib.sites.models import Site
from django.core.management import call_command
from django.core.management.base import BaseCommand
from django.db import connection


class Command(BaseCommand):
    help = "Run migrations and create required database resources (cache table, sites)"

    def add_arguments(self, parser):
        parser.add_argument(
            "--skip-migrate",
            action="store_true",
            help="Skip running migrations",
        )

    def handle(self, *args, **options):
        # Run migrations
        if not options["skip_migrate"]:
            self.stdout.write("Running migrations...")
            call_command("migrate", verbosity=1)
            self.stdout.write(self.style.SUCCESS("✓ Migrations complete"))

        # Create cache table if using DatabaseCache
        cache_config = getattr(settings, "CACHES", {}).get("default", {})
        if cache_config.get("BACKEND") == "django.core.cache.backends.db.DatabaseCache":
            table_name = cache_config.get("LOCATION", "django_cache_table")
            # Check if table exists
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT EXISTS (
                        SELECT FROM information_schema.tables 
                        WHERE table_name = %s
                    );
                    """,
                    [table_name],
                )
                exists = cursor.fetchone()[0]

            if not exists:
                self.stdout.write(f"Creating cache table: {table_name}")
                call_command("createcachetable", table_name)
                self.stdout.write(
                    self.style.SUCCESS(f"✓ Created cache table: {table_name}")
                )
            else:
                self.stdout.write(
                    self.style.SUCCESS(f"✓ Cache table already exists: {table_name}")
                )

        # Ensure django_site entry exists
        site, created = Site.objects.update_or_create(
            id=1,
            defaults={
                "domain": "id.localhost",
                "name": "UpdSpace ID",
            },
        )
        if created:
            self.stdout.write(self.style.SUCCESS("✓ Created django_site entry"))
        else:
            self.stdout.write(self.style.SUCCESS("✓ django_site entry already exists"))

        self.stdout.write(self.style.SUCCESS("\n✓ Database setup complete!"))
