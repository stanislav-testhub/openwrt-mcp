// Drives the Overview include (files/www/luci-static/resources/view/status/include/15_openwrt-mcp.js)
// against a stub of the LuCI and DOM primitives it uses and a fake rpcd. Run by TestLuciOverviewSmoke.
import fs from 'node:fs';
import assert from 'node:assert/strict';

const src = fs.readFileSync(process.argv[2], 'utf8');

function el(tag, attrs, children) {
	const n = { tag, attrs: {}, children: [], listeners: {}, disabled: false };
	n.appendChild = c => { n.children.push(c); return c; };
	n.replaceChildren = (...c) => { n.children = c.flat(Infinity); };
	n.querySelectorAll = sel => {
		const out = [];
		const walk = x => { if (typeof x === 'string') return; if (x.tag === sel) out.push(x); x.children.forEach(walk); };
		n.children.forEach(walk);
		return out;
	};
	for (const [k, v] of Object.entries(attrs || {})) {
		if (v === null || v === undefined) continue;
		if (typeof v === 'function') n.listeners[k] = v; else n.attrs[k] = v;
	}
	const add = c => { if (Array.isArray(c)) c.forEach(add); else if (c !== undefined && c !== null && c !== '') n.children.push(c); };
	add(children);
	return n;
}
function E(tag, attrs, children) {
	if (attrs !== undefined && (typeof attrs !== 'object' || Array.isArray(attrs) || attrs.tag)) { children = attrs; attrs = {}; }
	return el(tag, attrs, children);
}
const text = n => typeof n === 'string' ? n : (n.children || []).map(text).join(' ');
const walk = (n, f) => { if (typeof n === 'string') return; f(n); n.children.forEach(c => walk(c, f)); };
const find = (n, pred) => { const out = []; walk(n, x => { if (pred(x)) out.push(x); }); return out; };
const byAct = (n, act) => find(n, x => x.attrs['data-act'] === act);

const calls = [];
let state, writable = true, decideReply = null, statusFails = false;
const handlers = {
	status: () => { if (statusFails) throw new Error('rpcd said no'); return state.st; },
	tools: () => state.tools,
	decide: p => { calls.push(p); return decideReply ? decideReply(p) : { id: p[0], state: 'allowed' }; },
	access: () => writable,
};
const rpc = { declare: o => (...args) => { try { return Promise.resolve(handlers[o.method](args)); } catch (e) { return Promise.reject(e); } } };
const notes = [], modals = [];
const ui = { addNotification: (t, n) => notes.push(text(n)), showModal: (t, c) => modals.push(c), hideModal: () => { modals.length = 0; } };
const baseclass = { extend: o => o };
String.prototype.format = function(...a) { let i = 0; return this.replace(/%[sd]/g, () => String(a[i++])); };
const inc = new Function('baseclass', 'rpc', 'ui', 'E', 'L', '_', src)(
	baseclass, rpc, ui, E, { url: p => '/cgi-bin/luci/' + p }, s => s);

const iso = ms => new Date(Date.now() + ms).toISOString();
function fresh() {
	calls.length = 0; notes.length = 0; modals.length = 0; writable = true; decideReply = null; statusFails = false;
	state = {
		st: { pending: [], requests: [
			{ id: 'aaaa1111', client: 'claude-code', tool: 'uci_apply', scope: 'wireless.radio1.disabled', state: 'open',
				created: iso(-41e3), expires: iso(500e3) },
			{ id: 'bbbb2222', client: 'claude-code', tool: 'exec', scope: 'sh', state: 'open', created: iso(-5e3), expires: iso(500e3) },
			{ id: 'cccc3333', client: 'claude-code', tool: 'logread', scope: '*', state: 'allowed', created: iso(-99e3), expires: iso(500e3) },
		] },
		tools: { groups: [
			{ id: 'configuration', title: 'Configuration', tools: [ { name: 'uci_apply', title: 'Change configuration (auto-rollback)', badge: 'write' } ] },
			{ id: 'raw', title: 'Raw access', tools: [ { name: 'exec', title: 'Run a command (no shell)', badge: 'shell' } ] },
		] },
	};
}
const draw = async () => inc.render(await inc.load());
const flush = () => new Promise(r => setTimeout(r, 0));
const card = (root, id) => find(root, x => x.attrs['data-request'] === id)[0];

// 1. open requests are shown with what the daemon derived; answered ones are not
fresh();
{
	const root = await draw();
	assert.equal(find(root, x => x.attrs['data-request']).length, 2);
	const t = text(root);
	assert.match(t, /claude-code asks for: Change configuration \(auto-rollback\)/);
	assert.match(t, /wireless\.radio1\.disabled/);
	assert.match(t, /power of a root shell/);
	assert.doesNotMatch(t, /cccc3333|logread/);
	assert.equal(byAct(card(root, 'aaaa1111'), 'open')[0].attrs.href, '/cgi-bin/luci/admin/services/openwrt-mcp');
}

// 2. nothing to answer: the include renders nothing, so LuCI hides it
fresh();
{
	state.st.requests = state.st.requests.map(r => ({ ...r, state: 'denied' }));
	assert.equal(await draw(), null);
	state.st.requests = [];
	assert.equal(await draw(), null);
}

// 3. a rollback awaiting confirmation alone is enough to show it
fresh();
{
	state.st.requests = [];
	state.st.pending = [ { token: 't', client: 'claude-code', configs: [ 'wireless', 'firewall' ], deadline: iso(60e3) } ];
	const t = text(await draw());
	assert.match(t, /Change to wireless, firewall by claude-code awaits confirmation/);
}

// 4. Allow: narrowest breadth, one hour; the row then reports it
fresh();
{
	const root = await draw();
	const c = card(root, 'aaaa1111');
	byAct(c, 'allow')[0].listeners.click();
	await flush();
	assert.deepEqual(calls, [ [ 'aaaa1111', 'allow', 'exact', '1h', false ] ]);
	assert.match(text(c), /Allowed for 1 hour/);
	assert.equal(byAct(c, 'allow').length, 0, 'the buttons are gone once answered');
}

// 5. Deny
fresh();
{
	const root = await draw();
	byAct(card(root, 'aaaa1111'), 'deny')[0].listeners.click();
	await flush();
	assert.deepEqual(calls, [ [ 'aaaa1111', 'deny', 'exact', '1h', false ] ]);
	assert.match(text(card(root, 'aaaa1111')), /Denied/);
}

// 6. a root-shell request asks again, then retries with confirm
fresh();
{
	decideReply = p => p[4] ? { id: p[0], state: 'allowed' } : { error: 'this grant lets claude-code run sh', code: 'needs_confirm' };
	const root = await draw();
	byAct(card(root, 'bbbb2222'), 'allow')[0].listeners.click();
	await flush();
	assert.equal(calls.length, 1);
	assert.equal(modals.length, 1);
	find({ tag: 'x', attrs: {}, children: modals[0] }, x => x.tag === 'button').pop().listeners.click();
	await flush();
	assert.equal(calls.length, 2);
	assert.equal(calls[1][4], true);
}

// 7. a refusal reaches the owner and leaves the buttons usable
fresh();
{
	decideReply = () => ({ error: 'request aaaa1111 is already allowed' });
	const root = await draw();
	const c = card(root, 'aaaa1111');
	byAct(c, 'allow')[0].listeners.click();
	await flush();
	assert.deepEqual(notes, [ 'request aaaa1111 is already allowed' ]);
	assert.ok(byAct(c, 'allow').every(b => !b.disabled));
}

// 8. a LuCI account with only the read ACL sees the request and can only open the page
fresh();
{
	writable = false;
	const root = await draw();
	const acts = find(root, x => x.attrs['data-act']).map(a => a.attrs['data-act']);
	assert.deepEqual([ ...new Set(acts) ], [ 'open' ]);
}

// 9. a daemon or rpcd that fails must not break Overview: the include just hides
fresh();
{
	statusFails = true;
	assert.equal(await draw(), null);
}
console.log('ok');
