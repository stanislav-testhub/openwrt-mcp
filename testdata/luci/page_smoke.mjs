// Drives the LuCI page (files/www/luci-static/resources/view/openwrt-mcp/status.js) against a
// stub of the few LuCI and DOM primitives it uses, and a fake rpcd. Run by TestLuciPageSmoke.
import fs from 'node:fs';
import assert from 'node:assert/strict';

const src = fs.readFileSync(process.argv[2], 'utf8');

function add(n, c) {
	if (c === undefined || c === null || c === '') return;
	if (Array.isArray(c)) c.forEach(x => add(n, x));
	else n.children.push(c);
}
function el(tag, attrs, children) {
	const n = { tag, attrs: {}, children: [], style: {}, listeners: {}, value: '' };
	n.appendChild = c => { n.children.push(c); return c; };
	n.replaceChildren = (...c) => { n.children = c.flat(Infinity); };
	n.addEventListener = (ev, fn) => { n.listeners[ev] = fn; };
	n.getAttribute = k => n.attrs[k];
	n.querySelectorAll = () => [];
	for (const [k, v] of Object.entries(attrs || {})) {
		if (v === null || v === undefined) continue;
		if (typeof v === 'function') n.listeners[k] = v;
		else { n.attrs[k] = v; if (k === 'value') n.value = v; }
	}
	add(n, children);
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

// ---- fake rpcd: records every write call by method name and its positional arguments
const calls = [];
let state, writable = true, decideReply = null;
const handlers = {
	status: () => state.st,
	tools: () => state.tools,
	settings: () => state.settings,
	decide: p => { calls.push(['decide', p]); return decideReply ? decideReply(p) : { id: p[0], state: 'allowed' }; },
	grant: p => { calls.push(['grant', p]); return { blocks: 1 }; },
	grant_preset: p => { calls.push(['grant_preset', p]); return { blocks: 3 }; },
	revoke: p => { calls.push(['revoke', p]); return { removed: 1 }; },
	set_settings: p => { calls.push(['set_settings', p]); return state.settings; },
	access: () => writable,
};
const rpc = { declare: o => (...args) => Promise.resolve(handlers[o.method](args)) };
const notes = [], modals = [];
const ui = {
	addNotification: (t, n) => notes.push(text(n)),
	showModal: (t, c) => modals.push(c),
	hideModal: () => { modals.length = 0; },
};
const view = { extend: o => o };
const win = { setInterval: () => 1, clearInterval() {} };
const doc = { body: { contains: () => true } };
String.prototype.format = function(...a) { let i = 0; return this.replace(/%[sd]/g, () => String(a[i++])); };
const page = new Function('view', 'rpc', 'ui', 'poll', 'E', '_', 'window', 'document', src)(
	view, rpc, ui, { add() {} }, E, s => s, win, doc);

const now = Date.now();
const iso = ms => new Date(now + ms).toISOString();
const tool = (name, title, badge, extra = {}) => ({ name, title, badge, readonly: false, ...extra });
function fresh() {
	calls.length = 0; notes.length = 0; modals.length = 0; writable = true; decideReply = null;
	state = {
		st: {
			version: '1.6.0', listen: ':8730', socket: '/var/run/x.sock', running: true, pending: [],
			clients: [ { name: 'claude-code', policies: 1 } ],
			policies: [ { index: 0, client: 'claude-code', tools: [ 'uci_apply' ], scopes: [ 'wireless.*' ], max_per_min: 60,
				expires: iso(3600e3), expired: false, enabled: true } ],
			audit: [ { time: '2026-10-15T10:00:00Z', client: 'claude-code', tool: 'uci_apply', outcome: 'DENIED', error: 'no grant' } ],
			requests: [
				{ id: 'aaaa1111', client: 'claude-code', tool: 'uci_apply', scope: 'wireless.radio1.disabled', family: 'wireless.*',
					args: 'set wireless.radio1.disabled=1', state: 'open', created: iso(-41e3), expires: iso(500e3) },
				{ id: 'bbbb2222', client: 'claude-code', tool: 'exec', scope: 'sh', family: 'sh', args: '', state: 'open',
					created: iso(-5e3), expires: iso(500e3) },
				{ id: 'cccc3333', client: 'claude-code', tool: 'logread', scope: '*', family: '*', args: '', state: 'allowed',
					created: iso(-99e3), expires: iso(500e3) },
			],
		},
		tools: { groups: [
			{ id: 'configuration', title: 'Configuration', tools: [ tool('uci_get', 'Read configuration', 'read'),
				tool('uci_apply', 'Change configuration (auto-rollback)', 'write', { notes: [ 'rollback' ] }) ] },
			{ id: 'raw', title: 'Raw access', tools: [ tool('exec', 'Run a command (no shell)', 'shell'),
				tool('mfa_unlock', 'Unlock MFA-gated tools', 'write', { ungated: true, why: 'needs no grant' }) ] },
		] },
		settings: { request_wait: 60, request_ttl: 600, wait_max: 300, ttl_min: 60, ttl_max: 3600, mfa_clients: [ 'claude-code' ] },
	};
}
const load = async () => { const d = await page.load(); return { d, root: page.render(d) }; };
const flush = () => new Promise(r => setTimeout(r, 0));
const card = (root, id) => find(root, x => x.attrs['data-request'] === id)[0];

// 1. open requests sit above the tabs, in full, with the facts the daemon derived
fresh();
{
	const { root } = await load();
	const box = root.children[0];
	const t = text(box);
	assert.match(t, /claude-code asks for: Change configuration \(auto-rollback\)/);
	assert.match(t, /wireless\.radio1\.disabled/);
	assert.match(t, /set wireless\.radio1\.disabled=1/);
	assert.match(t, /rollback armed/);
	assert.match(t, /root shell/);
	assert.match(t, /Allow all 2 from claude-code/);
	assert.equal(find(box, x => x.attrs['data-request']).length, 2, 'only open requests get a card');
	assert.doesNotMatch(t, /cccc3333/);
	const tabs = text(root.children[1]);
	for (const name of [ 'Overview', 'Permissions', 'Activity', 'Settings' ]) assert.ok(tabs.includes(name), name);
}

// 2. Allow sends the narrowest breadth and one hour
fresh();
{
	const { root } = await load();
	byAct(card(root, 'aaaa1111'), 'allow')[0].listeners.click();
	await flush();
	assert.deepEqual(calls[0], [ 'decide', [ 'aaaa1111', 'allow', 'exact', '1h', false ] ]);
}

// 3. widening and a longer duration are carried to the call
fresh();
{
	const { root } = await load();
	const c = card(root, 'aaaa1111');
	const [ dur, breadth ] = find(c, x => x.tag === 'select');
	assert.ok(find(breadth, x => x.tag === 'option').some(o => text(o).includes('wireless.*')), 'family option offered');
	dur.value = '8h'; dur.listeners.change();
	breadth.value = 'family'; breadth.listeners.change();
	byAct(c, 'allow')[0].listeners.click();
	await flush();
	assert.deepEqual(calls[0][1], [ 'aaaa1111', 'allow', 'family', '8h', false ]);
}

// 4. a root-shell request asks again before it is written, and retries with confirm
fresh();
{
	decideReply = p => p[4] ? { id: p[0], state: 'allowed' } : { error: 'this grant lets claude-code run sh', code: 'needs_confirm' };
	const { root } = await load();
	byAct(card(root, 'bbbb2222'), 'allow')[0].listeners.click();
	await flush();
	assert.equal(calls.length, 1);
	assert.equal(modals.length, 1, 'a confirmation is shown');
	find({ tag: 'x', attrs: {}, children: modals[0] }, x => x.tag === 'button').pop().listeners.click();
	await flush();
	assert.equal(calls.length, 2);
	assert.equal(calls[1][1][4], true);
}

// 5. Deny
fresh();
{
	const { root } = await load();
	byAct(card(root, 'aaaa1111'), 'deny')[0].listeners.click();
	await flush();
	assert.equal(calls[0][1][1], 'deny');
}

// 6. a read-only LuCI account sees requests and no controls at all
fresh();
{
	writable = false;
	const { root } = await load();
	assert.match(text(root.children[0]), /can see requests but not answer them/);
	assert.deepEqual(find(root, x => x.attrs['data-act']).map(a => a.attrs['data-act']), [], 'no buttons without the write ACL');
}

// 7. the permissions tab: groups from the registry, n of m granted, revoke by block index
fresh();
{
	const { root } = await load();
	const t = text(root);
	assert.match(t, /Configuration — 1 of 2 granted/);
	assert.match(t, /Raw access — 0 of 2 granted/);
	assert.match(t, /needs no grant/);
	byAct(root, 'revoke')[0].listeners.click();
	await flush();
	assert.deepEqual(calls[0], [ 'revoke', [ 'claude-code', 0, false ] ]);
	const ungated = find(root, x => x.tag === 'tr' && text(x).includes('mfa_unlock'))[0];
	assert.equal(byAct(ungated, 'grant').length, 0, 'an ungated tool offers no grant');
	const execRow = find(root, x => x.tag === 'tr' && text(x).includes('Run a command'))[0];
	find(execRow, x => x.tag === 'input')[0].value = 'uptime';
	byAct(execRow, 'grant')[0].listeners.click();
	await flush();
	assert.deepEqual(calls[1], [ 'grant', [ 'claude-code', 'exec', 'uptime', '1h', false ] ]);
	byAct(root, 'preset-readonly')[0].listeners.click();
	await flush();
	assert.deepEqual(calls[2], [ 'grant_preset', [ 'claude-code', 'readonly', '1h' ] ]);
}

// 8. settings round trip, and the second factor is shown but not changed here
fresh();
{
	const { root } = await load();
	const inputs = find(root, x => x.tag === 'input' && x.attrs.type === 'number');
	inputs[0].value = '30'; inputs[1].value = '300';
	byAct(root, 'save-settings')[0].listeners.click();
	await flush();
	assert.deepEqual(calls[0], [ 'set_settings', [ 30, 300 ] ]);
	assert.match(text(root), /Enrolled for: claude-code/);
}

// 9. a refusal from the plugin reaches the owner
fresh();
{
	decideReply = () => ({ error: 'request aaaa1111 is already allowed' });
	const { root } = await load();
	byAct(card(root, 'aaaa1111'), 'allow')[0].listeners.click();
	await flush();
	assert.deepEqual(notes, [ 'request aaaa1111 is already allowed' ]);
}

// 10. a pending rollback is shown above the tabs
fresh();
{
	state.st.pending = [ { token: 't', client: 'claude-code', configs: [ 'wireless' ], deadline: iso(60e3) } ];
	const { root } = await load();
	assert.match(text(root.children[0]), /Change to wireless by claude-code awaits confirmation/);
}

// 11. nothing pending: the area is empty, not a heading
fresh();
{
	state.st.requests = [];
	const { root } = await load();
	assert.equal(text(root.children[0]).trim(), '');
}

// 12. an expired or disabled grant is not a grant, and Revoke every grant names the client
fresh();
{
	state.st.policies.push(
		{ index: 1, client: 'claude-code', tools: [ 'uci_get' ], scopes: [ '*' ], expires: iso(-1e3), expired: true, enabled: true },
		{ index: 2, client: 'claude-code', tools: [ '*' ], scopes: [ '*' ], expired: false, enabled: false });
	const { root } = await load();
	assert.match(text(root), /Configuration — 1 of 2 granted/);
	assert.match(text(root), /Raw access — 0 of 2 granted/);
	byAct(root, 'revoke-all')[0].listeners.click();
	await flush();
	assert.deepEqual(calls[0], [ 'revoke', [ 'claude-code', null, true ] ]);
}

// 13. Allow all answers each open request of the client at its narrowest breadth
fresh();
{
	const { root } = await load();
	byAct(root, 'allow-all')[0].listeners.click();
	await flush(); await flush(); await flush();
	assert.deepEqual(calls.map(c => c[1].slice(1, 4).join('/')), [ 'allow/exact/1h', 'allow/exact/1h' ]);
}
console.log('ok');
