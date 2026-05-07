from django.core.management.base import BaseCommand

from apps.accounts.backup import create_backup


class Command(BaseCommand):
    help = "Create a pg_dump backup of the database (stored in /app/backups/)"

    def add_arguments(self, parser):
        parser.add_argument(
            "--label",
            default="manual",
            help="Label embedded in the filename, e.g. 'pre-update' or 'scheduled'",
        )

    def handle(self, *args, **options):
        try:
            result = create_backup(label=options["label"])
        except Exception as exc:
            self.stderr.write(self.style.ERROR(f"Backup failed: {exc}"))
            raise SystemExit(1) from exc

        self.stdout.write(self.style.SUCCESS(
            f"Backup created: {result['filename']} ({result['size_bytes']} bytes)"
        ))
