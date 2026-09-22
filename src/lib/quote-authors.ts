import type { AuthorProfile } from './profile-cache';

export const authorName = (profile: AuthorProfile) => [profile.first_name, profile.last_name].filter(Boolean).join(' ').trim();
const normalized = (value: string) => value.normalize('NFKC').trim().replace(/^@/, '').trim().toLowerCase();

export function matchAuthor(value: string, profiles: AuthorProfile[]): string {
    const match = (name: string) => {
        const key = normalized(name);
        const exact = profiles.filter(profile => normalized(authorName(profile)) === key);
        const found = exact.length ? exact : profiles.filter(profile => normalized(profile.first_name) === key);
        return found.length === 1 ? authorName(found[0]) : name.trim();
    };
    const whole = match(value);
    if (whole !== value.trim()) return whole;
    const directed = /^(.*?)\s+to\s+.+$/i.exec(value);
    if (directed && profiles.some(profile => authorName(profile) === match(directed[1]))) return match(directed[1]);
    const parts = value.split(/\s*(?:&|,|\band\b)\s*/i);
    const matched = parts.map(match);
    return matched.some((name, index) => name !== parts[index].trim()) ? matched.join(' & ') : value.trim();
}

export function matchedAuthorContext(before: string, after: string, context = '') {
    return before !== after && /\s+to\s+/i.test(before) && !context.split('\n').includes(`Original attribution: ${before}.`)
        ? [context, `Original attribution: ${before}.`].filter(Boolean).join('\n') : context;
}
