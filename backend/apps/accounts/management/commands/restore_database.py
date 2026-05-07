from django.core.management.base import BaseCommand, CommandError

from apps.accounts.backup import list_backups, restore_backup


class Command(BaseCommand):
    help = "Restore the database from a backup file in /app/backups/"

    def add_arguments(self, parser):
        parser.add_argument(
            "filename",
            nargs="?",
            help="Backup filename to restore (omit to list available backups)",
        )
        parser.add_argument(
            "--yes",
            action="store_true",
            help="Skip the confirmation prompt",
        )

    def handle(self, *args, **options):
        filename = options.get("filename")

        if not filename:
            backups = list_backups()
            if not backups:
                self.stdout.write("No backups found in /app/backups/")
                return
            self.stdout.write("Available backups (newest first):")
            for b in backups:
                self.stdout.write(f"  {b['filename']}  ({b['size_bytes']} bytes)  {b['created_at']}")
            return

        if not options["yes"]:
            self.stdout.write(self.style.WARNING(
                f"This will OVERWRITE the current database with: {filename}"
            ))
            confirm = input("Type RESTORE to confirm: ")
            if confirm.strip() != "RESTORE":
                self.stdout.write("Aborted.")
                return

        try:
            restore_backup(filename)
        except FileNotFoundError as exc:
            raise CommandError(str(exc)) from exc
        except Exception as exc:
            raise CommandError(f"Restore failed: {exc}") from exc

        self.stdout.write(self.style.SUCCESS(f"Database restored from: {filename}"))
