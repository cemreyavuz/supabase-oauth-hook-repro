# Per-connection capabilities for Supabase OAuth 2.1 server tokens

A self-contained repro. It shows how an app can give each OAuth connection its
own capabilities with the custom access token hook, and where the OAuth 2.1
server's scope model stops.

## Use case

An MCP server is the resource server, and the Supabase OAuth 2.1 server is the
authorization server. RLS controls which rows a user can see. The app also
wants to control which operations one connection can do, for example a
read-only connection for a user whose role allows writes.

## How the repro works

1. The consent page reads the client with `getAuthorizationDetails`. Then it
   stores what the user granted in `public.connection_grants`
   (`user_id`, `client_id`, `capabilities`). The last step is
   `approveAuthorization`.
2. The custom access token hook sees `claims.client_id` on OAuth tokens. It
   reads the grant and sets a `capabilities` claim. Normal sessions (no
   `client_id`) get no claim.
3. RLS reads the claim: `public.documents` is readable by a normal session or
   by a token with `documents:read`.

`public.hook_events` records every hook input.

## Run

Requires the Supabase CLI and Bun. The stack uses ports 563xx (API on 56321), so it can run
next to another local stack.

```sh
bun install
bun run gen-key
supabase start
bun run repro
```

`gen-key` creates the ES256 signing key that `config.toml` points to
(`signing_keys_path`), so tokens are signed like on a hosted project with
asymmetric keys. The script reads the API URL and keys from
`supabase status`, prints each step, and writes `results.json`. One check
fails on purpose: it shows the custom-scope gap below.

## Results (Supabase CLI 2.115.0, supabase-js 2.100.0)

| Check | Result |
| --- | --- |
| Normal session token: no `client_id`, no `capabilities`, RLS returns all rows | Pass |
| `getAuthorizationDetails` gives the consent page the `client_id` | Pass |
| Code exchange: ES256 token with `client_id` and `capabilities: ["documents:read"]`; RLS returns rows | Pass |
| Refresh after the grant is narrowed to `[]`: token keeps `client_id`, `capabilities` is `[]`, RLS returns no rows | Pass |
| Hook input on code exchange (`oauth_provider/authorization_code`) and refresh (`token_refresh`) has `claims.client_id` and `claims.scope` | Pass |
| Refresh fails after `revokeGrant` (`refresh_token_not_found`) | Pass |
| Authorize request with a custom scope (`openid email documents:read`) | **Fail**: `invalid_request`, `unsupported scope: documents:read` |

## Gaps in the OAuth 2.1 server

1. **No custom scopes.** `scopes_supported` is fixed to
   `openid profile email phone offline_access`. An unknown scope rejects the
   whole authorization request. The app cannot advertise its own scopes, so a
   client cannot ask for "read only".
2. **No partial approval.** `approveAuthorization(id)` takes no scopes. The
   app must store the user's choice in its own table, as this repro does.
3. **`scope` and `listGrants` show only the standard scopes.** The capability
   lives only in the custom claim, so the token's `scope` claim and
   `listGrants()` do not show what the user granted.
4. **No `client_credentials` grant.** `grant_types_supported` is
   `authorization_code` and `refresh_token`. A service identity or a
   user-bound API key cannot get a scoped token from Supabase Auth.

## Requested features

- Project-defined scopes that clients can request and that appear in
  `scopes_supported`.
- `approveAuthorization(id, { scopes })` to approve only some of the
  requested scopes.
- The granted scopes in the token's `scope` claim, in the hook input, and in
  `listGrants()`, kept on refresh.
- A way to exchange a user-bound, long-lived credential (API key or personal
  access token) for a short-lived, scoped session JWT. A `client_credentials`
  grant would cover service identities.
