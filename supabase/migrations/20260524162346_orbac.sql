
-- Disable extensions that are not used by this authorization model.
drop extension if exists pg_graphql;

-- Create the schema that owns the ORBAC tables.
create schema if not exists iam;

-- Core resource hierarchy.
create table iam.resources (
  resource_id uuid primary key default extensions.gen_random_uuid(),
  parent_resource_id uuid references iam.resources(resource_id) on delete cascade,
  resource_type text not null check (char_length(trim(resource_type)) >= 1),
  resource_name text not null check (char_length(trim(resource_name)) >= 1),
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),

  -- Global resources are roots; all other resources must have a parent.
  check (
    (resource_type = 'global' and parent_resource_id is null)
    or (resource_type <> 'global' and parent_resource_id is not null)
  )
);

-- Permission catalog.
create table iam.permissions (
  permission_name text primary key,
  created_at timestamptz not null default now()
);

-- Reusable role definitions.
create table iam.roles (
  role_id uuid primary key default extensions.gen_random_uuid(),
  role_name text not null check (char_length(trim(role_name)) >= 1),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),

  unique (role_name)
);

-- Join roles to their granted permissions.
create table iam.role_permissions (
  role_id uuid not null references iam.roles(role_id) on delete cascade,
  permission_name text not null references iam.permissions(permission_name) on delete cascade,
  created_at timestamptz not null default now(),

  primary key (role_id, permission_name)
);

-- Assign roles to users within a resource scope.
create table iam.role_assignments (
  user_id uuid not null references auth.users(id) on delete cascade,
  resource_id uuid not null references iam.resources(resource_id) on delete cascade,
  role_id uuid not null references iam.roles(role_id) on delete cascade,
  created_at timestamptz not null default now(),

  primary key (user_id, resource_id, role_id)
);

-- Supporting indexes for common lookup paths.
create index resources_parent_resource_id_idx
on iam.resources (parent_resource_id);

create index resources_resource_type_idx
on iam.resources (resource_type);

create index role_permissions_permission_name_idx
on iam.role_permissions (permission_name);

create index role_assignments_user_id_idx
on iam.role_assignments (user_id);

create index role_assignments_resource_id_idx
on iam.role_assignments (resource_id);

create index role_assignments_role_id_idx
on iam.role_assignments (role_id);
