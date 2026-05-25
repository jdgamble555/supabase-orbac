import { createClient } from '@supabase/supabase-js';
import type { Database } from '../src/lib/database.types';
import 'dotenv/config';

const SUPABASE_URL = process.env.PUBLIC_SUPABASE_URL!;
const SUPABASE_SECRET_KEY = process.env.PRIVATE_SUPABASE_SECRET_KEY!;
const SUPABASE_PUBLISHABLE_KEY = process.env.PUBLIC_SUPABASE_PUBLISHABLE_KEY!;

export const supabaseAdmin = createClient<Database>(SUPABASE_URL, SUPABASE_SECRET_KEY);
export const supabase = createClient<Database>(SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY);

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

async function main() {
    
	const { error: permissionsError } = await supabaseAdmin
		.schema('rbac')
		.from('permissions')
		.upsert(permissionRows, { onConflict: 'permission_name' });

	if (permissionsError) {
		console.error('Error seeding permissions:', permissionsError);
        return;
	}

	console.log(`Seeded ${permissionRows.length} RBAC permissions.`);

}

main();