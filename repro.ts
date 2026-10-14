/**
 * Repro: per-connection capabilities for Supabase OAuth 2.1 server tokens,
 * set by the custom access token hook.
 *
 * Runs the full authorization-code flow against the local stack in this
 * folder (DCR → authorize → consent → token → refresh → revoke) and prints
 * what the hook received and what the issued tokens contain.
 *
 * Run: `supabase start && bun install && bun run repro`
 */
import { createClient } from '@supabase/supabase-js';
import { createHash, randomBytes } from 'node:crypto';

const status = Object.fromEntries(
  Bun.spawnSync(['supabase', 'status', '-o', 'env'], { stderr: 'ignore' })
    .stdout.toString()
    .matchAll(/^(\w+)="(.*)"$/gm)
    .map(([, name, value]) => [name, value])
);
const { API_URL, PUBLISHABLE_KEY, SECRET_KEY } = status;
if (!API_URL || !PUBLISHABLE_KEY || !SECRET_KEY) {
  throw new Error('Local stack not found. Run `supabase start` in this folder first.');
}
const REDIRECT_URI = 'http://127.0.0.1:3999/callback';

const clientOptions = { auth: { persistSession: false, autoRefreshToken: false } };
const admin = createClient(API_URL, SECRET_KEY, clientOptions);

type Check = { name: string; pass: boolean; detail: string };
const checks: Check[] = [];
const check = (name: string, pass: boolean, detail: unknown) => {
  checks.push({ name, pass, detail: typeof detail === 'string' ? detail : JSON.stringify(detail) });
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}\n      ${checks.at(-1)!.detail}`);
};
const section = (title: string) => console.log(`\n== ${title} ==`);

const base64url = (buffer: Buffer) => buffer.toString('base64url');
const decodeJwt = (jwt: string) => {
  const [header, payload] = jwt.split('.');
  return {
    header: JSON.parse(Buffer.from(header, 'base64url').toString()),
    payload: JSON.parse(Buffer.from(payload, 'base64url').toString())
  };
};
const must = async <T>(label: string, promise: Promise<{ data: T; error: unknown }>) => {
  const { data, error } = await promise;
  if (error) throw new Error(`${label}: ${JSON.stringify(error)}`);
  return data;
};

const metadata = await fetch(`${API_URL}/auth/v1/.well-known/oauth-authorization-server`).then((r) => r.json());

const tokenRequest = async (params: Record<string, string>) => {
  const response = await fetch(metadata.token_endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(params)
  });
  return { status: response.status, body: await response.json() };
};

const readDocuments = async (accessToken: string) => {
  const response = await fetch(`${API_URL}/rest/v1/documents?select=title`, {
    headers: { apikey: PUBLISHABLE_KEY, authorization: `Bearer ${accessToken}` }
  });
  return (await response.json()) as { title: string }[];
};

const setGrant = async (userId: string, clientId: string, capabilities: string[]) =>
  must(
    'upsert connection_grants',
    admin.from('connection_grants').upsert({ user_id: userId, client_id: clientId, capabilities })
  );

section('Setup');
console.log('scopes_supported:', metadata.scopes_supported);
console.log('grant_types_supported:', metadata.grant_types_supported);

const email = `repro-${Date.now()}@example.com`;
const password = 'repro-password-123';
const { user } = await must('create user', admin.auth.admin.createUser({ email, password, email_confirm: true }));
console.log('user:', user.id);

const registration = await fetch(metadata.registration_endpoint, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({
    client_name: 'Repro MCP client',
    redirect_uris: [REDIRECT_URI],
    token_endpoint_auth_method: 'none',
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code']
  })
}).then((r) => r.json());
const clientId: string = registration.client_id;
console.log('client_id (DCR):', clientId);

const userClient = createClient(API_URL, PUBLISHABLE_KEY, clientOptions);
const { session } = await must('sign in', userClient.auth.signInWithPassword({ email, password }));

section('1. Normal session token (no OAuth client)');
const sessionClaims = decodeJwt(session!.access_token).payload;
check('session token has no client_id', sessionClaims.client_id === undefined, { client_id: sessionClaims.client_id });
check('session token has no capabilities claim', sessionClaims.capabilities === undefined, {
  capabilities: sessionClaims.capabilities
});
const sessionDocuments = await readDocuments(session!.access_token);
check('session token reads all documents through RLS', sessionDocuments.length === 2, { rows: sessionDocuments.length });

section('2. Authorize + consent (consent page stores the grant)');
const codeVerifier = base64url(randomBytes(32));
const codeChallenge = base64url(createHash('sha256').update(codeVerifier).digest());
const state = base64url(randomBytes(8));
const requestedScope = 'openid email documents:read';
const authorizeUrl = new URL(metadata.authorization_endpoint);
authorizeUrl.search = new URLSearchParams({
  response_type: 'code',
  client_id: clientId,
  redirect_uri: REDIRECT_URI,
  code_challenge: codeChallenge,
  code_challenge_method: 'S256',
  state,
  scope: requestedScope
}).toString();
const authorizeResponse = await fetch(authorizeUrl, { redirect: 'manual' });
const consentLocation = new URL(authorizeResponse.headers.get('location')!);
console.log('authorize →', authorizeResponse.status, consentLocation.toString());
const consentError = consentLocation.searchParams.get('error');
check('custom scope in the authorize request is accepted', consentError === null, {
  requested: requestedScope,
  error: consentError,
  error_description: consentLocation.searchParams.get('error_description')
});

let authorizationId = consentLocation.searchParams.get('authorization_id');
if (!authorizationId) {
  console.log('Retrying authorize with standard scopes only.');
  authorizeUrl.searchParams.set('scope', 'openid email');
  const retry = await fetch(authorizeUrl, { redirect: 'manual' });
  authorizationId = new URL(retry.headers.get('location')!).searchParams.get('authorization_id');
}

const details = await must('getAuthorizationDetails', userClient.auth.oauth.getAuthorizationDetails(authorizationId!));
console.log('authorization details:', details);
const detailsClientId = 'client' in details ? details.client.id : undefined;
check('consent page gets the client id from getAuthorizationDetails', detailsClientId === clientId, {
  details_client_id: detailsClientId
});

await setGrant(user.id, clientId, ['documents:read']);
console.log('connection_grants ← ["documents:read"]');

const approval = await must(
  'approveAuthorization',
  userClient.auth.oauth.approveAuthorization(authorizationId!, { skipBrowserRedirect: true })
);
const code = new URL(approval.redirect_url).searchParams.get('code')!;

section('3. Code exchange');
const exchange = await tokenRequest({
  grant_type: 'authorization_code',
  code,
  redirect_uri: REDIRECT_URI,
  client_id: clientId,
  code_verifier: codeVerifier
});
console.log('token endpoint →', exchange.status);
const exchangeToken = decodeJwt(exchange.body.access_token);
console.log('header:', exchangeToken.header);
console.log('claims:', exchangeToken.payload);
check('token is signed with ES256', exchangeToken.header.alg === 'ES256', exchangeToken.header);
check('token carries client_id', exchangeToken.payload.client_id === clientId, {
  client_id: exchangeToken.payload.client_id
});
check('hook copied the grant into capabilities', JSON.stringify(exchangeToken.payload.capabilities) === '["documents:read"]', {
  capabilities: exchangeToken.payload.capabilities
});
const exchangeDocuments = await readDocuments(exchange.body.access_token);
check('RLS lets the token read documents', exchangeDocuments.length === 2, { rows: exchangeDocuments.length });

section('4. Refresh after the user narrows the grant');
await setGrant(user.id, clientId, []);
console.log('connection_grants ← []');
const refresh = await tokenRequest({
  grant_type: 'refresh_token',
  refresh_token: exchange.body.refresh_token,
  client_id: clientId
});
console.log('token endpoint →', refresh.status);
const refreshToken = refresh.body.access_token ? decodeJwt(refresh.body.access_token) : undefined;
console.log('claims:', refreshToken?.payload ?? refresh.body);
check('refreshed token still carries client_id', refreshToken?.payload.client_id === clientId, {
  client_id: refreshToken?.payload.client_id
});
check('refreshed token has the narrowed capabilities', JSON.stringify(refreshToken?.payload.capabilities) === '[]', {
  capabilities: refreshToken?.payload.capabilities
});
const refreshDocuments = refresh.body.access_token ? await readDocuments(refresh.body.access_token) : [];
check('RLS hides documents from the refreshed token', refreshDocuments.length === 0, { rows: refreshDocuments.length });

section('5. What the hook received');
const events = await must(
  'read hook_events',
  admin.from('hook_events').select('event').eq('event->>user_id', user.id).order('id')
);
for (const { event } of events as { event: Record<string, any> }[]) {
  console.log({
    authentication_method: event.authentication_method,
    top_level_keys: Object.keys(event),
    'claims.client_id': event.claims.client_id ?? null,
    'claims.scope': event.claims.scope ?? null,
    'claims.amr': event.claims.amr
  });
}
const oauthEvents = (events as { event: Record<string, any> }[]).filter(({ event }) => event.claims.client_id);
check('hook gets client_id on code exchange and refresh', oauthEvents.length >= 2, {
  oauth_hook_calls: oauthEvents.map(({ event }) => event.authentication_method)
});
check(
  'hook gets the granted scope',
  oauthEvents.some(({ event }) => event.claims.scope !== undefined || event.scope !== undefined),
  { scopes_seen: oauthEvents.map(({ event }) => event.claims.scope ?? event.scope ?? null) }
);

section('6. Grants as Supabase records them');
const grants = await must('listGrants', userClient.auth.oauth.listGrants());
console.log(grants);

section('7. Revoke');
await must('revokeGrant', userClient.auth.oauth.revokeGrant({ clientId }));
const afterRevoke = await tokenRequest({
  grant_type: 'refresh_token',
  refresh_token: refresh.body.refresh_token,
  client_id: clientId
});
check('refresh fails after revokeGrant', afterRevoke.status >= 400, afterRevoke);

section('Summary');
const failed = checks.filter((c) => !c.pass);
console.log(`${checks.length - failed.length}/${checks.length} checks passed`);
for (const c of failed) console.log(`FAIL  ${c.name}`);
await Bun.write('results.json', JSON.stringify({ ranAt: new Date().toISOString(), checks }, null, 2));
