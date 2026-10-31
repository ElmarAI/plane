// SPDX-License-Identifier: AGPL-3.0-only
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
const source = readFileSync(new URL('./bootstrap.js', import.meta.url), 'utf8');
async function browser(path, status = 401) {
  const redirects = [];
  const location = { href: 'https://plane.example.org' + path, replace: value => redirects.push(value) };
  const window = { location, fetch: async () => ({ status }), addEventListener() {}, history: {} };
  for (const method of ['pushState', 'replaceState']) window.history[method] = (_, __, path) => { location.href = new URL(path, location.href).href; };
  runInNewContext(source, { window, URL, URLSearchParams });
  await new Promise(resolve => setImmediate(resolve));
  return { window, redirects };
}
test('anonymous deep link preserves path, query and fragment', async () => {
  const { redirects } = await browser('/customers/projects/abc/issues/?view=board#task');
  assert.equal(new URL(redirects[0], 'https://plane.example.org').searchParams.get('next_path'), '/customers/projects/abc/issues/?view=board#task');
});
test('existing native session and backend failure do not initiate OIDC', async () => {
  for (const status of [200, 500]) assert.deepEqual((await browser('/customers', status)).redirects, []);
});
test('SPA session expiry redirects with its original next_path', async () => {
  const { window, redirects } = await browser('/customers', 200);
  window.fetch = async () => ({ status: 401 });
  window.history.pushState(null, '', '/?next_path=%2Fcustomers%2Fprojects%2Fabc');
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(new URL(redirects[0], 'https://plane.example.org').searchParams.get('next_path'), '/customers/projects/abc');
});
test('password fallback and non-web surfaces remain available', async () => {
  for (const path of ['/?local_login=1','/god-mode/','/auth/oidc/callback/','/spaces/','/api/users/me/']) assert.deepEqual((await browser(path)).redirects, []);
});
test('external and backslash redirects are rejected', async () => {
  for (const next of ['https://evil.example','//evil.example','/\\evil.example']) {
    const { redirects } = await browser('/?next_path=' + encodeURIComponent(next));
    assert.equal(new URL(redirects[0], 'https://plane.example.org').searchParams.get('next_path'), '/');
  }
});
