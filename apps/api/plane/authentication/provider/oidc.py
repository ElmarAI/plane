# SPDX-License-Identifier: AGPL-3.0-only
"""Confidential OIDC code flow for explicitly linked, existing Plane users."""

import base64
import hashlib
import hmac
import os
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlencode, urlsplit

import jwt
import requests


class OIDCError(Exception):
    """Deliberately carries no provider response, authorization code or token."""


def https_url(value):
    url = urlsplit(value)
    if url.scheme != "https" or not url.hostname or url.username or url.password or url.fragment:
        raise OIDCError("Invalid OIDC URL")
    return value


def configuration():
    if os.environ.get("OIDC_ENABLED") != "1":
        raise OIDCError("OIDC disabled")
    issuer = https_url(os.environ.get("OIDC_ISSUER", ""))
    callback = https_url(os.environ.get("OIDC_REDIRECT_URI", ""))
    client_id = os.environ.get("OIDC_CLIENT_ID", "")
    secret_file = os.environ.get("OIDC_CLIENT_SECRET_FILE", "")
    secret = Path(secret_file).read_text().strip() if secret_file else ""
    group = os.environ.get("OIDC_REQUIRED_GROUP", "")
    if not all((client_id, secret, group)):
        raise OIDCError("Incomplete OIDC configuration")
    return dict(issuer=issuer, callback=callback, client_id=client_id, secret=secret, group=group)


def discovery(config):
    response = requests.get(
        config["issuer"].rstrip("/") + "/.well-known/openid-configuration", timeout=10, allow_redirects=False
    )
    if response.status_code != 200:
        raise OIDCError("Discovery unavailable")
    document = response.json()
    if document.get("issuer") != config["issuer"]:
        raise OIDCError("Issuer mismatch")
    for field in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        https_url(document.get(field, ""))
    if "S256" not in document.get("code_challenge_methods_supported", []):
        raise OIDCError("PKCE S256 required")
    return document


def challenge(verifier):
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")


def authorization_url(config, document, transaction):
    return (
        document["authorization_endpoint"]
        + "?"
        + urlencode(
            {
                "response_type": "code",
                "client_id": config["client_id"],
                "redirect_uri": config["callback"],
                "scope": "openid profile email",
                "state": transaction["state"],
                "nonce": transaction["nonce"],
                "code_challenge": challenge(transaction["verifier"]),
                "code_challenge_method": "S256",
            }
        )
    )


@lru_cache(maxsize=8)
def jwks_client(url):
    return jwt.PyJWKClient(url, timeout=10)


def validate_token(token, config, document, nonce, access_token=None):
    key = jwks_client(document["jwks_uri"]).get_signing_key_from_jwt(token).key
    claims = jwt.decode(
        token,
        key,
        algorithms=["RS256"],
        audience=config["client_id"],
        issuer=config["issuer"],
        options={"require": ["iss", "sub", "aud", "exp", "iat", "nonce"]},
        leeway=30,
    )
    if not isinstance(claims["sub"], str) or not claims["sub"] or len(claims["sub"]) > 255:
        raise OIDCError("Invalid subject")
    if not isinstance(claims["nonce"], str) or not hmac.compare_digest(claims["nonce"], nonce):
        raise OIDCError("Nonce mismatch")
    aud = claims["aud"]
    if (isinstance(aud, list) and len(aud) > 1) or "azp" in claims:
        if claims.get("azp") != config["client_id"]:
            raise OIDCError("Authorized party mismatch")
    groups = claims.get("groups")
    if not isinstance(groups, list) or config["group"] not in groups:
        raise OIDCError("Group denied")
    if "at_hash" in claims:
        if not isinstance(access_token, str):
            raise OIDCError("Access token missing")
        expected = base64.urlsafe_b64encode(hashlib.sha256(access_token.encode()).digest()[:16]).decode().rstrip("=")
        if not isinstance(claims["at_hash"], str) or not hmac.compare_digest(claims["at_hash"], expected):
            raise OIDCError("Access token mismatch")
    return claims


def exchange(config, document, code, transaction):
    response = requests.post(
        document["token_endpoint"],
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": config["callback"],
            "code_verifier": transaction["verifier"],
            "client_id": config["client_id"],
            "client_secret": config["secret"],
        },
        timeout=15,
        allow_redirects=False,
    )
    if response.status_code != 200:
        raise OIDCError("Token exchange failed")
    tokens = response.json()
    return validate_token(tokens["id_token"], config, document, transaction["nonce"], tokens.get("access_token"))


def account_id(issuer, subject):
    # Separate identical subject values from different issuers; fits Account's 255 chars.
    return hashlib.sha256((issuer + "\x00" + subject).encode()).hexdigest()
