import type { AuthorProfile } from './profile-cache';

export const authorName = (profile: AuthorProfile) => [profile.first_name, profile.last_name].filter(Boolean).join(' ').trim();
const cleanName = (value: string) => value.normalize('NFKC').trim().replace(/^@/, '').trim().replace(/\s+/g, ' ');
const normalized = (value: string) => cleanName(value).toLowerCase();
const capitalizeName = (value: string) => cleanName(value)
    .replace(/(^|[\s-])\p{Ll}/gu, initial => initial.toUpperCase()).replace(/\bNbc\b/g, 'NBC');

export function matchAuthor(value: string, profiles: AuthorProfile[]): string {
    const match = (name: string) => {
        const alias = normalized(name) === 'abhinav daram' ? 'Abhi Daram' : null;
        const key = normalized(alias ?? name);
        const exact = profiles.filter(profile => normalized(authorName(profile)) === key);
        const found = exact.length ? exact : profiles.filter(profile => normalized(profile.first_name) === key);
        return found.length === 1 ? authorName(found[0]) : alias;
    };
    const whole = match(value);
    if (whole !== null) return whole;
    const directed = /^(.*?)\s+to\s+.+$/i.exec(value);
    const speaker = directed ? match(directed[1]) : null;
    if (speaker !== null) return speaker;
    const parts = value.split(/\s*(?:&|,|\band\b)\s*/i);
    const matched = parts.map(match);
    return matched.some(name => name !== null)
        ? matched.map((name, index) => name ?? capitalizeName(parts[index])).join(' & ')
        : capitalizeName(value);
}

export function matchedAuthorContext(before: string, after: string, context = '') {
    return before !== after && /\s+to\s+/i.test(before) && !context.split('\n').includes(`Original attribution: ${before}.`)
        ? [context, `Original attribution: ${before}.`].filter(Boolean).join('\n') : context;
}
