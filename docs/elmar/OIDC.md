# Elmar OIDC pilot (based on Plane CE v1.4.3)

This fork adds optional OIDC login to existing human Plane accounts. The initial
pilot is backend-only: open `/auth/oidc/` (or make that your portal/IdP launch URL).
The upstream frontend and password/API login endpoints remain unchanged. There
is no SAML, automatic signup, role synchronization or God Mode SSO in this patch.
No commercial Plane code is included.

## Configuration

| Environment variable | Value |
| --- | --- |
| `OIDC_ENABLED` | `1`; disabled by default |
| `OIDC_ISSUER` | Exact HTTPS discovery issuer, including its trailing slash |
| `OIDC_CLIENT_ID` | Confidential client ID |
| `OIDC_CLIENT_SECRET_FILE` | Mounted secret file; never put it in the image |
| `OIDC_REDIRECT_URI` | Exact HTTPS `/auth/oidc/callback/` URL |
| `OIDC_REQUIRED_GROUP` | Required entry in the signed ID-token `groups` array |

Configure an Authentik confidential authorization-code client, an RS256 signing
key, the `openid profile email` scope mappings (profile must emit `groups`),
`user_uuid` subject mode, an exact callback URI, and a group policy on the app.
The client requires PKCE S256 and validates signature/JWKS, issuer, audience,
expiration, issued-at, nonce, authorized party and optional access-token hash.
State is session-bound, consumed on callback and expires after five minutes.
No access, ID or refresh tokens are stored in the database.

## Existing users and recovery

An administrator explicitly binds the immutable `(issuer, subject)` to an existing
active, non-bot Plane user UUID:

```sh
python manage.py link_oidc_account \
  --user-id <plane-user-uuid> \
  --issuer https://auth.example/application/o/plane/ \
  --subject <authentik-user-uuid>
```

The command is idempotent and rejects reassignment to another user. It never
matches by email. User UUIDs, workspace memberships, project roles, history and
API tokens remain intact. Account rows use an issuer/subject SHA-256 key and
`provider=oidc`; metadata records the explicit binding. Migration 0123 only adds
OIDC to the field choices. There is no automatic privilege escalation or signup.

Sessions last one hour. Removing IdP group membership blocks the next OIDC login,
but does not immediately revoke an already-established Plane session. Existing
Plane session termination/deactivation controls are still necessary for urgent
revocation. Local logout does not perform global IdP logout. Existing password
recovery and instance administration remain available; do not disable them before
proving a separate recovery path. No authentication headers are trusted as users.

## Build and tests

```sh
docker compose -f docker-compose-oidc-test.yml up --build --abort-on-container-exit --exit-code-from tests
docker compose -f docker-compose-oidc-test.yml down
docker build -f apps/api/Dockerfile.sso --build-arg REVISION=$(git rev-parse HEAD) \
  -t elmar-plane-sso:$(git rev-parse --short HEAD) apps/api
```

The test stack has its own Postgres, Redis, network and synthetic data. Tests cover
real RSA signatures, invalid claims/keys/algorithms, PKCE, stale/missing/replayed
callbacks, explicit linking, reassignment rejection, disabled accounts, bots,
unmapped accounts and redirect validation. The image builds on the exact upstream
runtime digest and copies the fork's Python sources; no extra production packages.

The pilot deployment lives in `ElmarAI/BusinessSystem/prototyp1/plane-sso-pilot`.
It is separate from the operational Plane instance. The first release uses local
VM image builds; automated registry publication is not configured yet.

## Source availability and updates

Corresponding source: https://github.com/ElmarAI/plane/tree/elmar/authentik-oidc
Original baseline: `v1.4.3` / `37a15d99231042b3ff5a4401fed479fdbec9effe`.
This modification remains AGPL-3.0-only. Operators must offer users the corresponding
source of the deployed revision, including build files; the pilot portal provides
that link. Retain the full upstream license and copyright notices.

Review upstream authentication/model changes, merge them deliberately, rerun the
isolated tests and browser pilot, then build an immutable revision before updating
production. Keep the previous image and a database backup for rollback.
