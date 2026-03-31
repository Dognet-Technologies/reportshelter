"""
Management command: show license status for all organizations.

Usage:
    python manage.py license_status
    python manage.py license_status --fix       # resets INVALID → TRIAL_ACTIVE for dev
    python manage.py license_status --org <id>  # specific org only
"""

from __future__ import annotations

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone


class Command(BaseCommand):
    help = "Show license status for all organizations (diagnostic tool)"

    def add_arguments(self, parser):
        parser.add_argument(
            "--org",
            type=int,
            help="Show only the organization with this ID",
        )
        parser.add_argument(
            "--fix",
            action="store_true",
            help="Reset INVALID licenses back to TRIAL_ACTIVE (dev/debug only)",
        )

    def handle(self, *args, **options):
        from apps.licensing.models import License, LicenseStatus

        qs = License.objects.select_related("organization").all()
        if options["org"]:
            qs = qs.filter(organization_id=options["org"])

        if not qs.exists():
            self.stdout.write(self.style.WARNING("No license records found."))
            return

        now = timezone.now()
        self.stdout.write("\n── License Status ──────────────────────────────")

        for lic in qs:
            integrity_ok = lic.verify_integrity()
            color = {
                LicenseStatus.TRIAL_ACTIVE:  self.style.SUCCESS,
                LicenseStatus.PRO_ACTIVE:    self.style.SUCCESS,
                LicenseStatus.TRIAL_EXPIRED: self.style.WARNING,
                LicenseStatus.PRO_EXPIRED:   self.style.WARNING,
                LicenseStatus.INVALID:       self.style.ERROR,
            }.get(lic.status, str)

            self.stdout.write(
                f"\nOrg [{lic.organization_id}] {lic.organization.name}"
            )
            self.stdout.write(f"  Status:           {color(lic.status)}")
            self.stdout.write(f"  Integrity hash:   {'✓ OK' if integrity_ok else self.style.ERROR('✗ FAILED')}")
            self.stdout.write(f"  License key:      {lic.license_key[:8] + '****' if lic.license_key else '(none)'}")
            self.stdout.write(f"  Activation token: {'set (' + lic.activation_token[:8] + '…)' if lic.activation_token else '(none)'}")
            self.stdout.write(f"  Trial started:    {lic.trial_started_at}")
            self.stdout.write(f"  Trial expires:    {lic.trial_expires_at}")
            self.stdout.write(f"  PRO activated:    {lic.pro_activated_at}")
            self.stdout.write(f"  PRO expires:      {lic.pro_expires_at or '(no expiry)'}")
            self.stdout.write(f"  Last online check:{lic.last_online_checked_at}")

            if lic.last_online_checked_at:
                hours_ago = (now - lic.last_online_checked_at).total_seconds() / 3600
                self.stdout.write(f"  Hours since check:{hours_ago:.1f}h (interval=12h, grace=48h)")

            if options["fix"] and lic.status == LicenseStatus.INVALID:
                lic.status = LicenseStatus.TRIAL_ACTIVE
                lic.integrity_hash = ""
                lic.save()
                self.stdout.write(self.style.WARNING(
                    f"  → Reset to TRIAL_ACTIVE (dev fix)"
                ))

        self.stdout.write("\n── End ─────────────────────────────────────────\n")
