import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { runInNewContext } from 'node:vm';
import ts from 'typescript';

const require = createRequire(import.meta.url);

export function loadModule(path, dependencies = {}, globals = {}) {
  const source = readFileSync(new URL('../' + path, import.meta.url), 'utf8');
  const { outputText } = ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, target: ts.ScriptTarget.ES2022 },
    fileName: path,
  });
  const exports = {};
  runInNewContext(outputText, {
    exports,
    require: name => dependencies[name] ?? require(name),
    ...globals,
  }, { filename: path });
  return exports;
}
