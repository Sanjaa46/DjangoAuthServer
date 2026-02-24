import csv
from django.core.management.base import BaseCommand
from django.db import transaction
from ssoAuthServer.models import AuthUser


class Command(BaseCommand):
    help = "Import users from CSV into ssoAuthServer_authuser table"

    def add_arguments(self, parser):
        parser.add_argument("csv_path", type=str, help="Path to users.csv")

    def handle(self, *args, **options):
        csv_path = options["csv_path"]

        created = 0
        skipped = 0

        with open(csv_path, newline="", encoding="utf-8") as csvfile:
            reader = csv.DictReader(csvfile)

            with transaction.atomic():
                for row in reader:
                    phone = row["phone"].strip()
                    password_hash = row["password_hash"].strip()

                    if not phone or not password_hash:
                        skipped += 1
                        continue

                    if AuthUser.objects.filter(phone=phone).exists():
                        skipped += 1
                        continue

                    AuthUser.objects.create(
                        phone=phone,
                        password_hash=password_hash,
                        is_active=True,
                    )

                    created += 1

        self.stdout.write(
            self.style.SUCCESS(
                f"Import completed. Created: {created}, Skipped: {skipped}"
            )
        )