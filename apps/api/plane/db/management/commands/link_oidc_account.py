# SPDX-License-Identifier: AGPL-3.0-only
"""Explicit administrator mapping. Never links users merely by matching email."""

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from plane.authentication.provider.oidc import account_id, https_url
from plane.db.models import Account, User


class Command(BaseCommand):
    help = "Link an existing active human Plane user UUID to an OIDC issuer and subject."

    def add_arguments(self, parser):
        parser.add_argument("--user-id", required=True)
        parser.add_argument("--issuer", required=True)
        parser.add_argument("--subject", required=True)

    @transaction.atomic
    def handle(self, *args, **options):
        issuer, subject = https_url(options["issuer"]), options["subject"]
        if not subject or len(subject) > 255:
            raise CommandError("Invalid subject")
        user = User.objects.select_for_update().filter(pk=options["user_id"], is_active=True, is_bot=False).first()
        if not user:
            raise CommandError("Active human user not found")
        identity = account_id(issuer, subject)
        account, created = Account.objects.get_or_create(
            provider="oidc",
            provider_account_id=identity,
            defaults={"user": user, "access_token": "", "metadata": {"issuer": issuer, "subject": subject}},
        )
        if account.user_id != user.id:
            raise CommandError("Identity already linked to a different user; refusing reassignment")
        self.stdout.write("OIDC account linked." if created else "OIDC account already linked.")
