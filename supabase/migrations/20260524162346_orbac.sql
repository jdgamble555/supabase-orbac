
-- Keep the database surface limited to features this authorization model uses.
drop extension if exists pg_graphql;


-- ---------------------------------------------------------------------------
-- Schemas
-- ---------------------------------------------------------------------------
create schema if not exists rbac;
create schema if not exists private;


-- ---------------------------------------------------------------------------
-- Core RBAC tables
-- ---------------------------------------------------------------------------
create table rbac.tenants (
  tenant_id uuid primary key default gen_random_uuid(),
  tenant_name text not null check (length(trim(tenant_name)) > 0),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table rbac.roles (
  role_id uuid primary key default gen_random_uuid(),

  -- `null` means a global role. A non-null tenant_id scopes the role to one tenant.
  tenant_id uuid references rbac.tenants(tenant_id) on delete cascade,

  role_name text not null check (length(trim(role_name)) > 0),
  role_description text,
  is_system boolean not null default false,

  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),

  constraint roles_global_name_uq unique nulls not distinct (tenant_id, role_name)
);

create table rbac.members (
  member_id uuid primary key default gen_random_uuid(),
  -- `null` means a global assignment. A non-null tenant_id scopes membership to one tenant.
  tenant_id uuid references rbac.tenants(tenant_id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role_id uuid not null references rbac.roles(role_id) on delete cascade,
  created_at timestamptz not null default now(),

  constraint members_tenant_user_uq unique nulls not distinct (tenant_id, user_id)
);

create table rbac.permissions (
  permission_id uuid primary key default gen_random_uuid(),
  permission_name text not null unique check (length(trim(permission_name)) > 0),
  permission_description text,
  created_at timestamptz not null default now()
);

create table rbac.role_permissions (
  role_id uuid not null references rbac.roles(role_id) on delete cascade,
  permission_id uuid not null references rbac.permissions(permission_id) on delete cascade,
  created_at timestamptz not null default now(),

  primary key (role_id, permission_id)
);

create table rbac.user_claims (
  user_id uuid primary key references auth.users(id) on delete cascade,
  claims jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now()
);



-- ---------------------------------------------------------------------------
-- Supporting indexes
-- ---------------------------------------------------------------------------
create index members_user_idx
on rbac.members (user_id);

create index members_tenant_idx
on rbac.members (tenant_id);

create index roles_tenant_idx
on rbac.roles (tenant_id);

create index members_role_idx
on rbac.members (role_id);

create index role_permissions_permission_idx
on rbac.role_permissions (permission_id);



-- ---------------------------------------------------------------------------
-- Validation and claims cache helpers
-- ---------------------------------------------------------------------------
-- Ensure each membership row points at a role from the same scope.
create or replace function rbac.validate_member_role_scope()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  assigned_role_tenant_id uuid;
begin
  select r.tenant_id
  into assigned_role_tenant_id
  from rbac.roles r
  where r.role_id = new.role_id;

  if not found then
    raise exception 'Role % does not exist', new.role_id;
  end if;

  if assigned_role_tenant_id is distinct from new.tenant_id then
    raise exception 'Role % scope must match member scope', new.role_id;
  end if;

  return new;
end;
$$;


-- Build the cached claims document stored per user in `rbac.user_claims`.
-- Shape:
-- {
--   "global": { "role": null, "permissions": [] },
--   "tenants": {
--     "<tenant-id>": { "role": null, "permissions": [] }
--   }
-- }
create or replace function rbac.build_claims_cache(target_user_id uuid)
returns jsonb
language sql
stable
security definer
set search_path = ''
as $$
  with assignments as (
    select
      r.tenant_id,
      r.role_name,
      p.permission_name
    from rbac.members m
    join rbac.roles r
      on r.role_id = m.role_id
    left join rbac.role_permissions rp
      on rp.role_id = r.role_id
    left join rbac.permissions p
      on p.permission_id = rp.permission_id
    where m.user_id = target_user_id
  ),
  scoped_claims as (
    select
      tenant_id,
      min(role_name) filter (where role_name is not null) as role,
      coalesce(
        array_agg(distinct permission_name order by permission_name) filter (where permission_name is not null),
        array[]::text[]
      ) as permissions
    from assignments
    group by tenant_id
  ),
  global_claims as (
    select jsonb_build_object(
      'role', to_jsonb(sc.role),
      'permissions', to_jsonb(sc.permissions)
    ) as claims
    from scoped_claims sc
    where sc.tenant_id is null
  ),
  tenant_claims as (
    select coalesce(
      jsonb_object_agg(
        sc.tenant_id::text,
        jsonb_build_object(
          'role', to_jsonb(sc.role),
          'permissions', to_jsonb(sc.permissions)
        )
      ),
      '{}'::jsonb
    ) as claims
    from scoped_claims sc
    where sc.tenant_id is not null
  )
  select jsonb_build_object(
    'global', coalesce(
      (select claims from global_claims),
      jsonb_build_object(
        'role', null,
        'permissions', to_jsonb(array[]::text[])
      )
    ),
    'tenants', coalesce((select claims from tenant_claims), '{}'::jsonb)
  );
$$;

-- Rebuild one user's cached claims snapshot.
create or replace function rbac.refresh_user_claims_cache(target_user_id uuid)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  if target_user_id is null then
    return;
  end if;

  insert into rbac.user_claims (user_id, claims, updated_at)
  values (
    target_user_id,
    rbac.build_claims_cache(target_user_id),
    now()
  )
  on conflict (user_id) do update
  set claims = excluded.claims,
      updated_at = excluded.updated_at;
end;
$$;

-- Rebuild cached claims for a set of users.
create or replace function rbac.refresh_user_claims_cache_for_users(target_user_ids uuid[])
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into rbac.user_claims (user_id, claims, updated_at)
  select
    impacted.user_id,
    rbac.build_claims_cache(impacted.user_id),
    now()
  from (
    select distinct unnest(target_user_ids) as user_id
  ) impacted
  where impacted.user_id is not null
  on conflict (user_id) do update
  set claims = excluded.claims,
      updated_at = excluded.updated_at;
end;
$$;


-- ---------------------------------------------------------------------------
-- Trigger handlers
-- ---------------------------------------------------------------------------
-- Membership changes directly add or remove a user's tenant access.
create or replace function rbac.handle_members_claims_cache()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if tg_op in ('UPDATE', 'DELETE') then
    perform rbac.refresh_user_claims_cache(old.user_id);
  end if;

  if tg_op in ('INSERT', 'UPDATE') then
    perform rbac.refresh_user_claims_cache(new.user_id);
  end if;

  return null;
end;
$$;

-- Role-permission changes affect every user assigned to that role.
create or replace function rbac.handle_role_permissions_claims_cache()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  affected_role_id uuid;
begin
  affected_role_id := coalesce(new.role_id, old.role_id);

  perform rbac.refresh_user_claims_cache_for_users(
    array(
      select distinct m.user_id
      from rbac.members m
      where m.role_id = affected_role_id
    )
  );

  return null;
end;
$$;

-- Role edits or deletes affect every user assigned to that role.
create or replace function rbac.handle_roles_claims_cache()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  perform rbac.refresh_user_claims_cache_for_users(
    array(
      select distinct m.user_id
      from rbac.members m
      where m.role_id = coalesce(new.role_id, old.role_id)
    )
  );

  return null;
end;
$$;

-- Permission edits or deletes affect every user who inherits that permission.
create or replace function rbac.handle_permissions_claims_cache()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  perform rbac.refresh_user_claims_cache_for_users(
    array(
      select distinct m.user_id
      from rbac.role_permissions rp
      join rbac.members m
        on m.role_id = rp.role_id
      where rp.permission_id = coalesce(new.permission_id, old.permission_id)
    )
  );

  return null;
end;
$$;


-- ---------------------------------------------------------------------------
-- Triggers
-- ---------------------------------------------------------------------------
create trigger members_refresh_user_claims_cache
after insert or update or delete on rbac.members
for each row
execute function rbac.handle_members_claims_cache();

create trigger members_validate_role_scope
before insert or update on rbac.members
for each row
execute function rbac.validate_member_role_scope();

create trigger role_permissions_refresh_user_claims_cache
after insert or update or delete on rbac.role_permissions
for each row
execute function rbac.handle_role_permissions_claims_cache();

create trigger roles_refresh_user_claims_cache
after update or delete on rbac.roles
for each row
execute function rbac.handle_roles_claims_cache();

create trigger permissions_refresh_user_claims_cache
after update or delete on rbac.permissions
for each row
execute function rbac.handle_permissions_claims_cache();




-- ---------------------------------------------------------------------------
-- Private RLS predicate helpers
-- ---------------------------------------------------------------------------
-- Read from the cached claims document instead of re-joining the RBAC graph.
create or replace function private.has_permission(
  tenant_id uuid,
  permission_name text,
  user_id uuid default auth.uid()
)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from rbac.user_claims c
    where c.user_id = has_permission.user_id
      and (
        (
          has_permission.tenant_id is not null
          and c.claims -> 'tenants' -> has_permission.tenant_id::text -> 'permissions'
            ? has_permission.permission_name
        )
        or c.claims -> 'global' -> 'permissions'
          ? has_permission.permission_name
      )
  );
$$;


-- Resolve a role to its tenant scope before checking the cached permission set.
create or replace function private.has_role_permission(
  role_id uuid,
  permission_name text,
  user_id uuid default auth.uid()
)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from rbac.roles r
    where r.role_id = has_role_permission.role_id
      and private.has_permission(
        r.tenant_id,
        has_role_permission.permission_name,
        has_role_permission.user_id
      )
  );
$$;


-- ---------------------------------------------------------------------------
-- Grants and default privileges
-- ---------------------------------------------------------------------------
-- Expose RBAC tables through the API roles while keeping helper functions locked down.
grant usage on schema rbac to anon, authenticated, service_role;
grant usage on schema private to anon, authenticated, service_role;

grant select, insert, update, delete
on all tables in schema rbac
to anon, authenticated, service_role;

revoke execute on all functions in schema rbac from public;
revoke execute on all functions in schema rbac from anon, authenticated, service_role;

revoke execute on all functions in schema private from public;
revoke execute on all functions in schema private from anon, authenticated, service_role;

grant execute
on function private.has_permission(uuid, text, uuid)
to anon, authenticated, service_role;

grant execute
on function private.has_role_permission(uuid, text, uuid)
to anon, authenticated, service_role;

alter default privileges in schema rbac
grant select, insert, update, delete
on tables
to anon, authenticated, service_role;

alter default privileges in schema rbac
revoke execute
on functions
from public;

alter default privileges in schema rbac
revoke execute
on functions
from anon, authenticated, service_role;

alter default privileges in schema private
revoke execute
on functions
from public;

alter default privileges in schema private
revoke execute
on functions
from anon, authenticated, service_role;
