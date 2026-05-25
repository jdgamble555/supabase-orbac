
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

  constraint roles_tenant_name_uq
    unique nulls not distinct (tenant_id, role_name)
);

create table rbac.members (
  member_id uuid primary key default gen_random_uuid(),

  -- null = global membership
  -- non-null = tenant membership
  tenant_id uuid references rbac.tenants(tenant_id) on delete cascade,

  user_id uuid not null references auth.users(id) on delete cascade,
  role_id uuid not null references rbac.roles(role_id) on delete cascade,

  created_at timestamptz not null default now(),

  constraint members_tenant_user_uq
    unique nulls not distinct (tenant_id, user_id)
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

create or replace function rbac.get_user_permissions(
  permissions text[]
)
returns text[]
language sql
stable
security invoker
set search_path = ''
as $$
  with requested_permissions as (
    select distinct requested.permission_name
    from unnest(coalesce(get_user_permissions.permissions, array[]::text[])) as requested(permission_name)
    where requested.permission_name is not null
  ),
  user_permissions as (
    select jsonb_array_elements_text(c.claims -> 'global' -> 'permissions') as permission_name
    from rbac.user_claims c
    where c.user_id = auth.uid()

    union

    select jsonb_array_elements_text(tenant_claim.value -> 'permissions') as permission_name
    from rbac.user_claims c
    cross join lateral jsonb_each(c.claims -> 'tenants') as tenant_claim(key, value)
    where c.user_id = auth.uid()
  )
  select coalesce(
    array_agg(requested_permissions.permission_name order by requested_permissions.permission_name),
    array[]::text[]
  )
  from requested_permissions
  where requested_permissions.permission_name in (
    select distinct user_permissions.permission_name
    from user_permissions
  );
$$;

create or replace function private.bootstrap_tenant(
  target_tenant_id uuid,
  target_user_id uuid
)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  admin_role_id uuid;
  admin_permission_names text[] := array[
    'rbac.tenants.select',
    'rbac.tenants.update',
    'rbac.tenants.delete',
    'rbac.roles.select',
    'rbac.roles.insert',
    'rbac.roles.update',
    'rbac.roles.delete',
    'rbac.members.select',
    'rbac.members.insert',
    'rbac.members.update',
    'rbac.members.delete',
    'rbac.role_permissions.select',
    'rbac.role_permissions.insert',
    'rbac.role_permissions.update',
    'rbac.role_permissions.delete'
  ];
  matched_permission_count integer;
begin
  if target_user_id is null then
    raise exception 'target_user_id is required';
  end if;

  if target_tenant_id is null then
    raise exception 'target_tenant_id is required';
  end if;

  select count(*)
  into matched_permission_count
  from rbac.permissions p
  where p.permission_name = any(admin_permission_names);

  if matched_permission_count <> array_length(admin_permission_names, 1) then
    raise exception 'Missing required RBAC permissions for tenant admin role';
  end if;

  insert into rbac.roles (
    tenant_id,
    role_name,
    role_description,
    is_system
  )
  values (
    target_tenant_id,
    'admin',
    'Tenant administrator role created during tenant bootstrap.',
    true
  )
  returning role_id into admin_role_id;

  insert into rbac.role_permissions (role_id, permission_id)
  select
    admin_role_id,
    p.permission_id
  from rbac.permissions p
  where p.permission_name = any(admin_permission_names);

  insert into rbac.members (
    tenant_id,
    user_id,
    role_id
  )
  values (
    target_tenant_id,
    target_user_id,
    admin_role_id
  );
end;
$$;

create or replace function rbac.create_tenant(
  target_tenant_name text
)
returns uuid
language plpgsql
security invoker
set search_path = ''
as $$
declare
  created_tenant_id uuid := gen_random_uuid();
  current_user_id uuid := auth.uid();
begin
  if target_tenant_name is null or length(trim(target_tenant_name)) = 0 then
    raise exception 'target_tenant_name is required';
  end if;

  if current_user_id is null then
    raise exception 'auth.uid() is required';
  end if;

  insert into rbac.tenants (tenant_id, tenant_name)
  values (created_tenant_id, trim(target_tenant_name));

  perform private.bootstrap_tenant(created_tenant_id, current_user_id);

  return created_tenant_id;
end;
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

grant execute
on function rbac.get_user_permissions(text[])
to anon, authenticated, service_role;

grant execute
on function private.bootstrap_tenant(uuid, uuid)
to authenticated;

grant execute
on function rbac.create_tenant(text)
to authenticated;

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


-- ---------------------------------------------------------------------------
-- Row Level Security
-- ---------------------------------------------------------------------------
alter table rbac.tenants enable row level security;
alter table rbac.roles enable row level security;
alter table rbac.members enable row level security;
alter table rbac.permissions enable row level security;
alter table rbac.role_permissions enable row level security;
alter table rbac.user_claims enable row level security;


-- ---------------------------------------------------------------------------
-- Tenant policies
-- ---------------------------------------------------------------------------
create policy "tenants_select"
on rbac.tenants
for select
using ((select private.has_permission(tenant_id, 'rbac.tenants.select')));

create policy "tenants_insert"
on rbac.tenants
for insert
with check (
  auth.role() = 'service_role'
  or auth.uid() is not null
);

create policy "tenants_update"
on rbac.tenants
for update
using ((select private.has_permission(tenant_id, 'rbac.tenants.update')))
with check ((select private.has_permission(tenant_id, 'rbac.tenants.update')));

create policy "tenants_delete"
on rbac.tenants
for delete
using ((select private.has_permission(tenant_id, 'rbac.tenants.delete')));


-- ---------------------------------------------------------------------------
-- Role policies
-- ---------------------------------------------------------------------------
create policy "roles_select"
on rbac.roles
for select
using ((select private.has_permission(tenant_id, 'rbac.roles.select')));

create policy "roles_insert"
on rbac.roles
for insert
with check ((select private.has_permission(tenant_id, 'rbac.roles.insert')));

create policy "roles_update"
on rbac.roles
for update
using ((select private.has_permission(tenant_id, 'rbac.roles.update')))
with check ((select private.has_permission(tenant_id, 'rbac.roles.update')));

create policy "roles_delete"
on rbac.roles
for delete
using ((select private.has_permission(tenant_id, 'rbac.roles.delete')));


-- ---------------------------------------------------------------------------
-- Membership policies
-- ---------------------------------------------------------------------------
create policy "members_select"
on rbac.members
for select
using ((select private.has_permission(tenant_id, 'rbac.members.select')));

create policy "members_insert"
on rbac.members
for insert
with check ((select private.has_permission(tenant_id, 'rbac.members.insert')));

create policy "members_update"
on rbac.members
for update
using ((select private.has_permission(tenant_id, 'rbac.members.update')))
with check ((select private.has_permission(tenant_id, 'rbac.members.update')));

create policy "members_delete"
on rbac.members
for delete
using ((select private.has_permission(tenant_id, 'rbac.members.delete')));


-- ---------------------------------------------------------------------------
-- Permission catalog policies
-- ---------------------------------------------------------------------------
create policy "permissions_select"
on rbac.permissions
for select
using ((select private.has_permission(null, 'rbac.permissions.select')));

create policy "permissions_insert"
on rbac.permissions
for insert
with check ((select private.has_permission(null, 'rbac.permissions.insert')));

create policy "permissions_update"
on rbac.permissions
for update
using ((select private.has_permission(null, 'rbac.permissions.update')))
with check ((select private.has_permission(null, 'rbac.permissions.update')));

create policy "permissions_delete"
on rbac.permissions
for delete
using ((select private.has_permission(null, 'rbac.permissions.delete')));


-- ---------------------------------------------------------------------------
-- Role-permission policies
-- ---------------------------------------------------------------------------
create policy "role_permissions_select"
on rbac.role_permissions
for select
using ((select private.has_role_permission(role_id, 'rbac.role_permissions.select')));

create policy "role_permissions_insert"
on rbac.role_permissions
for insert
with check ((select private.has_role_permission(role_id, 'rbac.role_permissions.insert')));

create policy "role_permissions_update"
on rbac.role_permissions
for update
using ((select private.has_role_permission(role_id, 'rbac.role_permissions.update')))
with check ((select private.has_role_permission(role_id, 'rbac.role_permissions.update')));

create policy "role_permissions_delete"
on rbac.role_permissions
for delete
using ((select private.has_role_permission(role_id, 'rbac.role_permissions.delete')));


-- ---------------------------------------------------------------------------
-- Claims cache policies
-- ---------------------------------------------------------------------------
create policy "user_claims_select"
on rbac.user_claims
for select
using (
  user_id = auth.uid()
  or (select private.has_permission(null, 'rbac.user_claims.select'))
);

create policy "user_claims_insert"
on rbac.user_claims
for insert
with check (auth.role() = 'service_role');

create policy "user_claims_update"
on rbac.user_claims
for update
using (auth.role() = 'service_role')
with check (auth.role() = 'service_role');

create policy "user_claims_delete"
on rbac.user_claims
for delete
using (auth.role() = 'service_role');

