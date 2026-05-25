import { createClient } from '@supabase/supabase-js';
import type { Database } from '../../src/lib/database.types';
import 'dotenv/config';
import { supabase } from '../seed';
import { permissionNames } from './permissions';

const TEST_USER_EMAIL = 'test@example.com';
const TEST_TENANT_NAME = 'Test Tenant';


export const seedUser = async () => {

    // Create user

    const { data: signUpData, error: signUpError } = await supabase.auth.signUp({
        email: TEST_USER_EMAIL,
        password: crypto.randomUUID()
    });

    if (signUpError && !signUpError.message.includes('User already registered')) {
        console.error(`Unable to create test user: ${signUpError.message}`);
        return;
    }

    const userId = signUpData.user?.id;
    const accessToken = signUpData.session?.access_token;

    if (userId) {
        console.log(`Created test user with email ${TEST_USER_EMAIL} and id ${userId}.`);
    }

    if (!accessToken) {
        console.error('Unable to create test tenant: authenticated session returned no access token.');
        return;
    }

    const authenticatedSupabase = createClient<Database>(
        process.env.PUBLIC_SUPABASE_URL!,
        process.env.PUBLIC_SUPABASE_PUBLISHABLE_KEY!,
        {
            accessToken: async () => accessToken
        }
    );

    const { data: tenantId, error: tenantError } = await authenticatedSupabase
        .schema('rbac')
        .rpc('create_tenant', {
            target_tenant_name: TEST_TENANT_NAME
        });

    if (tenantError) {
        console.error(`Unable to create test tenant: ${tenantError.message}`);
        return;
    }

    if (!tenantId) {
        console.error('Unable to create test tenant: RPC returned no tenant id.');
        return;
    }

    console.log(`Created test tenant ${TEST_TENANT_NAME} with id ${tenantId} and assigned user ${userId} as admin.`);

    const { data: userPermissions, error: userPermissionsError } = await authenticatedSupabase
        .schema('rbac')
        .rpc('get_user_permissions', {
            permissions: permissionNames
        });

    if (userPermissionsError) {
        console.error(`Unable to fetch user permissions: ${userPermissionsError.message}`);
        return;
    }

    console.log(`Permissions number: ${permissionNames.length}`);

    console.log(`User permissions number: ${userPermissions?.length}`);

};