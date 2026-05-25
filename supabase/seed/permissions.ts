import { supabaseAdmin } from "../seed";

const permissionSeeds = [
    {
        table: 'tenants',
        actions: ['select', 'insert', 'update', 'delete'],
        descriptionScope: 'tenant-scoped tenant records'
    },
    {
        table: 'roles',
        actions: ['select', 'insert', 'update', 'delete'],
        descriptionScope: 'tenant-scoped role records'
    },
    {
        table: 'members',
        actions: ['select', 'insert', 'update', 'delete'],
        descriptionScope: 'tenant-scoped membership records'
    },
    {
        table: 'permissions',
        actions: ['select', 'insert', 'update', 'delete'],
        descriptionScope: 'global permission records'
    },
    {
        table: 'role_permissions',
        actions: ['select', 'insert', 'update', 'delete'],
        descriptionScope: 'role to permission assignments'
    },
    {
        table: 'user_claims',
        actions: ['select'],
        descriptionScope: 'cached user claims records'
    }
] as const;

const permissionRows = permissionSeeds.flatMap(({ table, actions, descriptionScope }) =>
    actions.map((action) => ({
        permission_name: `rbac.${table}.${action}`,
        permission_description: `${action} ${descriptionScope}`
    }))
);

export const permissionNames = permissionRows.map(({ permission_name }) => permission_name);

export const seedPermissions = async () => {

    const { error: permissionsError } = await supabaseAdmin
        .schema('rbac')
        .from('permissions')
        .upsert(permissionRows, { onConflict: 'permission_name' });

    if (permissionsError) {
        console.error('Error seeding permissions:', permissionsError);
        return;
    }

    console.log(`Seeded ${permissionRows.length} RBAC permissions.`);

};