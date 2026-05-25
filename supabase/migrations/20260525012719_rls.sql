
-- ---------------------------------------------------------------------------
-- Enable RLS on the RBAC tables
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
with check ((select private.has_permission(tenant_id, 'rbac.tenants.insert')));

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
