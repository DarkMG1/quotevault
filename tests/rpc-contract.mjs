// Every client RPC call must name arguments that the migrated schema accepts.
// PostgREST resolves functions by argument names, so a misnamed key fails only in production.
// Input (stdin): `name|arg1,arg2,...|default_count` per function executable by authenticated.
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

const signatures = new Map();
for (const line of readFileSync(0, 'utf8').split('\n').filter(Boolean)) {
  const [name, args, defaults] = line.split('|');
  const names = args ? args.split(',') : [];
  signatures.set(name, [...(signatures.get(name) ?? []), { names, required: names.length - Number(defaults) }]);
}
if (signatures.size === 0) throw new Error('No function signatures received.');

const files = dir => readdirSync(dir).flatMap(entry => statSync(join(dir, entry)).isDirectory() ? files(join(dir, entry)) : /\.tsx?$/.test(entry) ? [join(dir, entry)] : []);
const topLevelKeys = (text, start) => {
  const keys = [];
  let depth = 0;
  for (let index = start; index < text.length; index++) {
    const char = text[index];
    if (char === '{') depth++;
    else if (char === '}' && --depth === 0) return keys;
    else if (depth === 1) {
      const key = /^(p_[a-z_]+)\s*:/.exec(text.slice(index));
      if (key && /[\s{,]/.test(text[index - 1])) { keys.push(key[1]); index += key[1].length; }
    }
  }
  return keys;
};

const problems = [];
let checked = 0;
for (const file of files('src')) {
  const text = readFileSync(file, 'utf8');
  for (const call of text.matchAll(/rpc\(\s*'([a-z_]+)'\s*(,\s*)?/gi)) {
    const [, name] = call;
    const at = `${file}:${text.slice(0, call.index).split('\n').length}`;
    const known = signatures.get(name);
    if (!known) { problems.push(`${at} calls ${name}, which authenticated cannot execute`); continue; }
    const argsStart = call.index + call[0].length;
    const keys = text[argsStart] === '{' ? topLevelKeys(text, argsStart) : [];
    checked++;
    if (!known.some(({ names, required }) => keys.every(key => names.includes(key)) && names.slice(0, required).every(key => keys.includes(key)))) {
      problems.push(`${at} ${name}(${keys.join(', ')}) matches no signature: ${known.map(({ names }) => `(${names.join(', ')})`).join(' | ')}`);
    }
  }
}
if (checked === 0) throw new Error('No RPC calls found in src.');
if (problems.length) { console.error(problems.join('\n')); process.exit(1); }
console.log(`RPC contract: ${checked} client calls match the migrated schema.`);
