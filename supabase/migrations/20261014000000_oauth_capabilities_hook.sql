-- Repro: per-connection capabilities for OAuth 2.1 server tokens through the
-- custom access token hook.
--
-- The consent page stores what the user granted to one OAuth client in
-- `connection_grants`. The hook copies that grant into a `capabilities` claim
-- when the token belongs to an OAuth client (`claims.client_id` is set).
-- `hook_events` records every hook input so the repro can show what Supabase
-- Auth passes to the hook on code exchange and on refresh.

create table public.hook_events (
  id bigint generated always as identity primary key,
  created_at timestamptz not null default now(),
  event jsonb not null
);
alter table public.hook_events enable row level security;

create table public.connection_grants (
  user_id uuid not null references auth.users (id) on delete cascade,
  client_id text not null,
  capabilities text[] not null,
  primary key (user_id, client_id)
);
alter table public.connection_grants enable row level security;

grant select on public.hook_events to service_role;
grant select, insert, update on public.connection_grants to service_role;

create or replace function public.custom_access_token_hook(event jsonb)
returns jsonb
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  claims jsonb := event->'claims';
  oauth_client_id text := event->'claims'->>'client_id';
  granted text[];
begin
  insert into public.hook_events (event) values (event);

  if oauth_client_id is not null then
    select g.capabilities into granted
    from public.connection_grants g
    where g.user_id = (event->>'user_id')::uuid
      and g.client_id = oauth_client_id;

    claims := jsonb_set(claims, '{capabilities}', coalesce(to_jsonb(granted), '[]'::jsonb));
  end if;

  return jsonb_set(event, '{claims}', claims);
end;
$$;

grant execute on function public.custom_access_token_hook to supabase_auth_admin;
revoke execute on function public.custom_access_token_hook from authenticated, anon, public;

-- RLS demo: an OAuth token reads `documents` only with `documents:read`.
-- A normal session (no `client_id`) keeps full access.
create table public.documents (
  id bigint generated always as identity primary key,
  title text not null
);
alter table public.documents enable row level security;

create policy "Select: session or documents:read capability"
  on public.documents
  for select
  to authenticated
  using (
    (select auth.jwt() ->> 'client_id') is null
    or (select auth.jwt() -> 'capabilities') ? 'documents:read'
  );

grant select on public.documents to authenticated;

insert into public.documents (title) values ('Annual report 2025'), ('Trial balance 2025');

create or replace function public.whoami()
returns jsonb
language sql
stable
as $$
  select auth.jwt();
$$;

grant execute on function public.whoami to authenticated;
