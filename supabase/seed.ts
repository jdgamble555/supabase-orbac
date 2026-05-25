import { createClient } from '@supabase/supabase-js';
import type { Database } from '../src/lib/database.types';
import 'dotenv/config';
import { seedPermissions } from './seed/permissions';
import { seedUser } from './seed/user';

const SUPABASE_URL = process.env.PUBLIC_SUPABASE_URL!;
const SUPABASE_SECRET_KEY = process.env.PRIVATE_SUPABASE_SECRET_KEY!;
const SUPABASE_PUBLISHABLE_KEY = process.env.PUBLIC_SUPABASE_PUBLISHABLE_KEY!;

export const supabaseAdmin = createClient<Database>(SUPABASE_URL, SUPABASE_SECRET_KEY);
export const supabase = createClient<Database>(SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY);


async function main() {

    await seedPermissions();

    await seedUser();

}

main();