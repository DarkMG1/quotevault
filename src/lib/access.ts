import type { User } from '@supabase/supabase-js';

export const ADMIN_EMAIL = 'darkmgdevelopment@gmail.com';

export function isAdminUser(user: Pick<User, 'email'> | null | undefined): boolean {
    return user?.email?.toLowerCase() === ADMIN_EMAIL;
}
