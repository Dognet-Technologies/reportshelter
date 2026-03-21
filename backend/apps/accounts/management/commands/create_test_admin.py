"""
Management command to create a pre-verified admin user for development/testing.
"""

from django.core.management.base import BaseCommand

from apps.accounts.models import Organization, User


class Command(BaseCommand):
    help = "Create a pre-verified admin test user (email: admin@dognet.tech, password: Admin!!)"

    def handle(self, *args, **options) -> None:
        email = "admin@dognet.tech"
        password = "Admin!!"

        org, org_created = Organization.objects.get_or_create(
            slug="dognet",
            defaults={"name": "Dognet"},
        )
        if org_created:
            self.stdout.write(self.style.SUCCESS(f"Created organization: {org.name}"))

        if User.objects.filter(email=email).exists():
            self.stdout.write(self.style.WARNING(f"User {email} already exists — skipping."))
            return

        user = User.objects.create_user(
            email=email,
            password=password,
            organization=org,
            role=User.Role.ADMIN,
            is_email_verified=True,
            is_active=True,
            is_staff=True,
        )
        self.stdout.write(self.style.SUCCESS(f"Created admin user: {user.email}"))
