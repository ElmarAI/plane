# SPDX-License-Identifier: AGPL-3.0-only
import hmac
import secrets
import time

import jwt
import requests
from django.http import HttpResponse, HttpResponseRedirect
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.cache import never_cache

from plane.authentication.provider.oidc import (
    OIDCError,
    account_id,
    authorization_url,
    configuration,
    discovery,
    exchange,
)
from plane.authentication.utils.login import user_login
from plane.authentication.utils.redirection_path import get_redirection_path
from plane.db.models import Account
from plane.license.models import Instance
from plane.utils.path_validator import get_safe_redirect_url

ERRORS = (OIDCError, jwt.PyJWTError, requests.RequestException, ValueError, KeyError, TypeError, OSError)


def denied():
    return HttpResponse("SSO login failed. Please contact your administrator or retry the login.", status=403)


@method_decorator(never_cache, name="dispatch")
class OIDCInitiateEndpoint(View):
    def get(self, request):
        try:
            config = configuration()
            if not Instance.objects.filter(is_setup_done=True).exists():
                return denied()
            document = discovery(config)
            transaction = dict(
                state=secrets.token_urlsafe(32),
                nonce=secrets.token_urlsafe(32),
                verifier=secrets.token_urlsafe(48),
                started=time.time(),
                next_path=request.GET.get("next_path", ""),
            )
            request.session.cycle_key()
            request.session["oidc_transaction"] = transaction
            return HttpResponseRedirect(authorization_url(config, document, transaction))
        except ERRORS:
            return denied()


@method_decorator(never_cache, name="dispatch")
class OIDCCallbackEndpoint(View):
    def get(self, request):
        # Consume state before exchanging any code; reject missing, stale and replayed callbacks.
        transaction = request.session.pop("oidc_transaction", None)
        try:
            if not transaction or request.GET.get("error"):
                return denied()
            state, code = request.GET.get("state", ""), request.GET.get("code", "")
            if not state or not code or not hmac.compare_digest(state, transaction["state"]):
                return denied()
            if not 0 <= time.time() - transaction["started"] <= 300:
                return denied()
            config = configuration()
            claims = exchange(config, discovery(config), code, transaction)
            account = (
                Account.objects.select_related("user")
                .filter(provider="oidc", provider_account_id=account_id(config["issuer"], claims["sub"]))
                .first()
            )
            if not account or not account.user.is_active or account.user.is_bot:
                return denied()
            # No email-based linking, user creation, role changes or token persistence.
            account.last_connected_at = timezone.now()
            account.save(update_fields=["last_connected_at"])
            user_login(request=request, user=account.user, is_app=True)
            request.session.set_expiry(3600)
            path = transaction["next_path"] or get_redirection_path(account.user)
            origin = config["callback"].split("/auth/", 1)[0]
            return HttpResponseRedirect(get_safe_redirect_url(base_url=origin, next_path=path, params={}))
        except ERRORS:
            return denied()
