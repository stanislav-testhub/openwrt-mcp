// Drives the Overview include (files/www/luci-static/resources/view/status/include/15_openwrt-mcp.js)
// against a stub of the LuCI and DOM primitives it uses and a fake rpcd. Run by TestLuciOverviewSmoke.
import fs from 'node:fs';
import assert from 'node:assert/strict';

const src = fs.readFileSync(process.argv[2], 'utf8');

// LuCI's E() flattens one level only: an array inside the children array is printed as text.
function el(tag, attrs, children) {
	const n = { tag, attrs: {}, children: [], listeners: {}, disabled: false, checked: false };
	n.appendChild = c => { n.children.push(c); return c; };
	n.replaceChildren = (...c) => { n.children = c.flat(Infinity); };
	n.addEventListener = (ev, fn) => { n.listeners[ev] = fn; };
	n.querySelectorAll = sel => {
		const out = [];
		const walk = x => { if (typeof x === 'string') return; if (x.tag === sel) out.push(x); x.children.forEach(walk); };
		n.children.forEach(walk);
		return out;
	};
	for (const [k, v] of Object.entries(attrs || {})) {
		if (v === null || v === undefined) continue;
		if (typeof v === 'function') n.listeners[k] = v; else { n.attrs[k] = v; if (k === 'disabled') n.disabled = true; }
	}
	const add = (c, nested) => { if (Array.isArray(c)) { if (nested) n.children.push('[object HTMLElement]'); else c.forEach(x => add(x, true)); } else if (c !== undefined && c !== null && c !== '') n.children.push(c); };
	add(children);
	return n;
}
function E(tag, attrs, children) {
	if (attrs !== undefined && (typeof attrs !== 'object' || Array.isArray(attrs) || attrs.tag)) { children = attrs; attrs = {}; }
	return el(tag, attrs, children);
}
const text = n => typeof n === 'string' ? n : (n.tag === 'style' ? '' : (n.children || []).map(text).join(' ').replace(/\s+/g, ' '));
const walk = (n, f) => { if (typeof n === 'string') return; f(n); n.children.forEach(c => walk(c, f)); };
const find = (n, pred) => { const out = []; walk(n, x => { if (pred(x)) out.push(x); }); return out; };
const byAct = (n, act) => find(n, x => x.attrs['data-act'] === act);

const calls = [];
let state, writable = true, decideReply = null, statusFails = false;
const handlers = {
	status: () => { if (statusFails) throw new Error('rpcd said no'); return state.st; },
	tools: () => state.tools,
	end_permit_all: p => { calls.push([ 'end', p ]); return { removed: 1 }; },
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
		st: { pending: [], permit_all: [], requests: [
			{ id: 'aaaa1111', client: 'claude-code', tool: 'uci_apply', scope: 'wireless.radio1.disabled', args: 'set wireless.radio1.disabled=1',
				state: 'open', created: iso(-41e3), expires: iso(500e3) },
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

// 1. open requests are shown in the owner's words; answered ones are not
fresh();
{
	const root = await draw();
	assert.equal(find(root, x => x.attrs['data-request']).length, 2);
	const t = text(root);
	assert.match(t, /MCP Server · 2 requests waiting/);
	assert.match(t, /Claude Code wants to turn off Wi-Fi radio 1/);
	assert.match(t, /Changes things/);
	assert.match(t, /Claude Code wants to run a command as root Full control/);
	assert.doesNotMatch(t, /wireless\.radio1|uci_apply|cccc3333|logread|\[object|\d{4}-\d\d-\d\dT/, 'no machine text');
	assert.equal(byAct(root, 'open')[0].attrs.href, '/cgi-bin/luci/admin/services/openwrt-mcp');
	assert.match(text(byAct(root, 'open')[0]), /Open MCP Server/);
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
	assert.match(t, /A change to wireless, firewall by Claude Code is waiting for confirmation\. It undoes itself in \d+ s\./);
}

// 4. one request says "1 request", and Allow is the narrowest breadth for the shortest time
fresh();
{
	state.st.requests = state.st.requests.slice(0, 1);
	const root = await draw();
	assert.match(text(root), /MCP Server · 1 request waiting/);
	const c = card(root, 'aaaa1111');
	assert.match(byAct(c, 'allow')[0].attrs.class, /cbi-button-action/);
	byAct(c, 'allow')[0].listeners.click();
	await flush();
	assert.deepEqual(calls, [ [ 'aaaa1111', 'allow', 'exact', '15m', false ] ]);
	assert.match(text(c), /Allowed for 15 minutes/);
	assert.equal(byAct(c, 'allow').length, 0, 'the buttons are gone once answered');
}

// 5. Deny, with a gap before it so it is never next to the primary button
fresh();
{
	const root = await draw();
	const deny = byAct(card(root, 'aaaa1111'), 'deny')[0];
	assert.match(deny.attrs.class, /cbi-button-negative mcp-sep/);
	deny.listeners.click();
	await flush();
	assert.deepEqual(calls, [ [ 'aaaa1111', 'deny', 'exact', '15m', false ] ]);
	assert.match(text(card(root, 'aaaa1111')), /Denied/);
}

// 6. a root command cannot be allowed from here: it needs the page's second confirmation
fresh();
{
	const root = await draw();
	const c = card(root, 'bbbb2222');
	assert.equal(byAct(c, 'allow').length, 0);
	assert.equal(byAct(c, 'deny').length, 1);
}

// 7. a request the daemon says needs confirming asks first, then retries with confirm
fresh();
{
	decideReply = p => p[4] ? { id: p[0], state: 'allowed' } : { error: 'this grant lets claude-code run sh', code: 'needs_confirm' };
	const root = await draw();
	byAct(card(root, 'aaaa1111'), 'allow')[0].listeners.click();
	await flush();
	assert.equal(calls.length, 1);
	assert.equal(modals.length, 1);
	const m = { tag: 'x', attrs: {}, children: modals[0] };
	const [ ack ] = find(m, x => x.tag === 'input');
	const go = byAct(m, 'confirm-shell')[0];
	assert.ok(go.disabled, 'disabled until ticked');
	ack.checked = true; ack.listeners.change();
	go.listeners.click();
	await flush();
	assert.equal(calls.length, 2);
	assert.equal(calls[1][4], true);
}

// 8. a refusal reaches the owner and leaves the buttons usable
fresh();
{
	decideReply = () => ({ error: 'request aaaa1111 is already allowed' });
	const root = await draw();
	const c = card(root, 'aaaa1111');
	byAct(c, 'allow')[0].listeners.click();
	await flush();
	assert.equal(notes.length, 1);
	assert.match(notes[0], /request aaaa1111 is already allowed/);
	assert.ok(byAct(c, 'allow').every(b => !b.disabled));
}

// 9. a LuCI account with only the read ACL sees the request and can only open the page
fresh();
{
	writable = false;
	const root = await draw();
	const acts = find(root, x => x.attrs['data-act']).map(a => a.attrs['data-act']);
	assert.deepEqual([ ...new Set(acts) ], [ 'open' ]);
}

// 10. a daemon or rpcd that fails must not break Overview: the include just hides
fresh();
{
	statusFails = true;
	assert.equal(await draw(), null);
}

// 11. a running Permit all alone shows the include, loudly, with End now
fresh();
{
	state.st.requests = [];
	state.st.permit_all = [ { client: 'claude-code', expires: iso(23 * 60e3) } ];
	const root = await draw();
	assert.match(text(root), /Full access is on for Claude Code · (22|23) min left/);
	const b = find(root, x => x.attrs['data-permit-all'])[0];
	assert.match(b.attrs.class, /alert-message error/);
	assert.equal(b.attrs.role, 'alert');
	const end = byAct(root, 'end-permit-all')[0];
	end.listeners.click({ target: end });
	await flush();
	assert.deepEqual(calls, [ [ 'end', [ 'claude-code' ] ] ]);
	assert.match(text(root), /Ended/);
}

// 12. no end date is said as such, and a read-only account gets the banner without the button
fresh();
{
	state.st.requests = [];
	state.st.permit_all = [ { client: 'claude-code', expires: '' } ];
	writable = false;
	const root = await draw();
	assert.match(text(root), /Full access is on for Claude Code · until you remove it/);
	assert.equal(byAct(root, 'end-permit-all').length, 0);
}

// 13. at most three requests are listed; the rest are counted
fresh();
{
	for (let i = 0; i < 4; i++)
		state.st.requests.push({ id: 'ext' + i, client: 'claude-code', tool: 'pkg_change', scope: '*', state: 'open', created: iso(-i * 1000), expires: iso(500e3) });
	const root = await draw();
	assert.equal(find(root, x => x.attrs['data-request']).length, 3);
	assert.match(text(root), /MCP Server · 6 requests waiting/);
	assert.match(text(root), /and 3 more/);
}
console.log('ok');
