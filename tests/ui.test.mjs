import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import { createRequire } from 'node:module';
import ts from 'typescript';

const root = new URL('../', import.meta.url);
const require = createRequire(import.meta.url);

function load(path, dependencies = {}, globals = {}) {
  const source = readFileSync(new URL(path, root), 'utf8');
  const { outputText } = ts.transpileModule(source, {
    compilerOptions: {
      module: ts.ModuleKind.CommonJS,
      jsx: ts.JsxEmit.ReactJSX,
      target: ts.ScriptTarget.ES2022,
    },
    fileName: path,
  });
  const exports = {};
  runInNewContext(outputText, {
    exports,
    require: name => {
      if (name in dependencies) return dependencies[name];
      if (name === 'react/jsx-runtime') return require(name);
      throw new Error(`Unexpected import: ${name}`);
    },
    console: { error() {} },
    ...globals,
  }, { filename: path });
  return exports;
}

const ui = load('src/components/ui.ts', {
  react: { useEffect: () => {}, useRef: initial => ({ current: initial }) },
  '../lib/crypto': { decryptData: async () => JSON.stringify({ text: 'decoded', author: 'Ada', context: 'letter', id: 'evil', user_id: 'evil', sync_status: 'synced', extra: 'ignored' }) },
});

const previousTimezone = process.env.TZ;
process.env.TZ = 'America/Detroit';
assert.equal(ui.localDateInputValue(new Date('2026-09-21T01:00:00Z')), '2026-09-20');
if (previousTimezone === undefined) delete process.env.TZ;
else process.env.TZ = previousTimezone;
assert.equal(ui.getErrorMessage(new Error('save failed'), 'fallback'), 'save failed');
assert.equal(ui.getErrorMessage({ message: 'delete failed' }, 'fallback'), 'delete failed');
assert.equal(ui.getErrorMessage({ message: 42 }, 'fallback'), 'fallback');
assert.equal(ui.isDecryptedPayload({ text: 'hello', author: 'Ada', context: 'note' }), true);
assert.equal(ui.isDecryptedPayload({ text: 'hello', author: 'Ada', extra: 'must not be merged' }), true);
assert.equal(ui.isDecryptedPayload({ text: 'hello', author: 42 }), false);
const decrypted = await ui.decryptQuoteForDisplay({
  id: 'q1', text: '$$E2E$${"iv":"iv","data":"data"}', author: 'ENCRYPTED',
  created_at: '2026-09-20T12:00:00Z', user_id: 'user-a', vault_generation: 'g1', sync_status: 'pending',
}, {});
assert.deepEqual({ text: decrypted.text, author: decrypted.author, context: decrypted.context }, {
  text: 'decoded', author: 'Ada', context: 'letter',
});
assert.equal('extra' in decrypted, false);
assert.equal(decrypted.id, 'q1');
assert.equal(decrypted.user_id, 'user-a');
assert.equal(decrypted.vault_generation, 'g1');
assert.equal(decrypted.sync_status, 'pending');

const components = load('src/components/AddQuote.tsx', {
  react: {
    useState: initial => [initial, () => {}],
    useEffect: () => {},
    useRef: initial => ({ current: initial }),
  },
  'framer-motion': { AnimatePresence: 'div', motion: new Proxy({}, { get: (_, key) => key }) },
  'lucide-react': new Proxy({}, { get: (_, key) => key }),
  '../hooks/useQuotes': { useQuotes: () => ({ addQuote: async () => {} }) },
  '../hooks/useAuth': { useAuth: () => ({ user: null }) },
  '../hooks/useCrypto': { useCrypto: () => ({ encryptionKey: {}, isLocked: false }) },
  '../lib/crypto': { encryptData: async () => ({}) },
  '../lib/supabase': { supabase: { from: () => ({ select: () => ({ order: async () => ({ data: [], error: null }) }) }) } },
  './ui': ui,
});
const addQuoteTree = components.AddQuote({ isOpen: true, onClose: () => {} });
const childrenOf = node => [node?.props?.children].flat(Infinity).filter(Boolean);
const find = (node, predicate) => {
  if (!node || typeof node !== 'object') return null;
  if (predicate(node)) return node;
  return childrenOf(node).map(child => find(child, predicate)).find(Boolean) || null;
};
assert.equal(find(addQuoteTree, node => node.type === 'dialog')?.props?.role, 'dialog');
assert.equal(find(addQuoteTree, node => node.type === 'textarea')?.props?.id, 'quote-text');
assert.equal(find(addQuoteTree, node => node.type === 'label' && node.props.htmlFor === 'quote-text') !== null, true);

console.log('ui audit checks passed');
