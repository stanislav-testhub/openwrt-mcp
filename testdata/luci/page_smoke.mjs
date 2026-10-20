// Drives the LuCI page (files/www/luci-static/resources/view/openwrt-mcp/status.js) against a
// stub of the few LuCI and DOM primitives it uses, and a fake rpcd. Run by TestLuciPageSmoke.
import fs from 'node:fs';
import assert from 'node:assert/strict';

const src = fs.readFileSync(process.argv[2], 'utf8');

// LuCI's E() flattens one level only: an array inside the children array is printed as text.
function add(n, c, nested) {
	if (c === undefined || c === null || c === '') return;
	if (Array.isArray(c)) {
		if (nested) n.children.push('[object HTMLElement]');
		else c.forEach(x => add(n, x, true));
	} else n.children.push(c);
}
function el(tag, attrs, children) {
	const n = { tag, attrs: {}, children: [], style: {}, listeners: {}, value: '', checked: false, disabled: false, indeterminate: false };
	n.appendChild = c => { n.children.push(c); return c; };
	n.replaceChildren = (...c) => { n.children = c.flat(Infinity).filter(x => x !== ''); };
	n.addEventListener = (ev, fn) => { n.listeners[ev] = fn; };
	n.setAttribute = (k, v) => { n.attrs[k] = v; };
	n.getAttribute = k => n.attrs[k];
	n.querySelectorAll = () => [];
	Object.defineProperty(n, 'textContent', { set: v => { n.children = v === '' ? [] : [ v ]; }, get: () => text(n) });
	for (const [k, v] of Object.entries(attrs || {})) {
		if (v === null || v === undefined) continue;
		if (typeof v === 'function') n.listeners[k] = v;
		else { n.attrs[k] = v; if (k === 'value') n.value = v; if (k === 'disabled') n.disabled = true; }
	}
	add(n, children);
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
const flat = t => t.replace(/\s+/g, ' ');

// ---- fake rpcd: records every write call by method name and its positional arguments
const calls = [];
let state, writable = true, decideReply = null, statusFails = false;
const iso = ms => new Date(Date.now() + ms).toISOString();
const handlers = {
	status: () => { if (statusFails) throw new Error('rpcd said no'); return state.st; },
	tools: () => state.tools,
	settings: () => state.settings,
	decide: p => {
		calls.push(['decide', p]);
		if (decideReply) return decideReply(p);
		const r = state.st.requests.find(x => x.id === p[0]);
		r.state = p[1] === 'allow' ? 'allowed' : 'denied';
		if (p[1] === 'allow')
			state.st.policies.push({ index: state.st.policies.filter(x => x.client === r.client).length, client: r.client, tools: [ r.tool ],
				scopes: [ r.scope ], expires: iso(900e3), expired: false, enabled: true });
		return { id: p[0], state: r.state };
	},
	grant: p => { calls.push(['grant', p]); return { blocks: 1 }; },
	grant_preset: p => { calls.push(['grant_preset', p]); return { blocks: 3 }; },
	revoke: p => { calls.push(['revoke', p]); return { removed: 1 }; },
	revoke_tools: p => { calls.push(['revoke_tools', p]); return { removed: 1 }; },
	permit_all: p => { calls.push(['permit_all', p]); return { client: p[0] }; },
	end_permit_all: p => { calls.push(['end_permit_all', p]); return { removed: 1 }; },
	set_channel: p => { calls.push(['set_channel', p]); return state.settings; },
	pair: p => { calls.push(['pair', p]); return { client: p[0] }; },
	set_settings: p => { calls.push(['set_settings', p]); return state.settings; },
	access: () => writable,
};
const rpc = { declare: o => (...args) => { try { return Promise.resolve(handlers[o.method](args)); } catch (e) { return Promise.reject(e); } } };
const notes = [], modals = [];
const ui = {
	// Like LuCI, hands back the banner so the page can take it down again.
	addNotification: (t, n) => {
		const msg = text(n);
		notes.push(msg);
		return { parentNode: { removeChild: () => { notes.splice(notes.indexOf(msg), 1); } } };
	},
	showModal: (t, c) => modals.push(c),
	hideModal: () => { modals.length = 0; },
};
const view = { extend: o => o };
const win = { setInterval: () => 1, clearInterval() {} };
const doc = { body: { contains: () => true } };
String.prototype.format = function(...a) { let i = 0; return this.replace(/%[sd]/g, () => String(a[i++])); };
const page = new Function('view', 'rpc', 'ui', 'poll', 'E', '_', 'L', 'window', 'document', src)(
	view, rpc, ui, { add() {} }, E, s => s, { url: p => '/cgi-bin/luci/' + p }, win, doc);

const tool = (name, title, badge, extra = {}) => ({ name, title, badge, readonly: false, ...extra });
const READ = [ 'system_status', 'logread', 'network_clients', 'firewall_show', 'service_list', 'net_diag', 'pkg_query', 'pkg_config_diff',
	'wg_list_clients', 'uci_get', 'ubus_call', 'sysupgrade', 'ubus_list' ];
const WRITE = [ 'uci_apply', 'uci_confirm', 'uci_rollback', 'pkg_change', 'pkg_config_resolve', 'wg_new_client', 'wg_remove_client',
	'service_control', 'mfa_unlock', 'exec' ];
const UNSCOPED = [ 'logread', 'network_clients', 'firewall_show', 'pkg_query', 'pkg_config_diff', 'uci_confirm', 'uci_rollback', 'ubus_list', 'mfa_unlock' ];
function registry() {
	const t = n => tool(n, 'Registry title of ' + n, n === 'exec' || n === 'ubus_call' ? 'shell' : (READ.includes(n) ? 'read' : 'write'), {
		readonly: READ.includes(n), ungated: n === 'ubus_list' || n === 'mfa_unlock', unscoped: UNSCOPED.includes(n), scope_hint: UNSCOPED.includes(n) ? undefined : 'HINT-' + n, notes: n === 'uci_apply' ? [ 'rollback' ] : [] });
	return { groups: [ { id: 'all', title: 'All', tools: READ.concat(WRITE).map(t) } ] };
}
// What `allow claude-code @readonly 1h` writes.
function lookOnly(client, expires) {
	const mk = (index, tools, scopes) => ({ index, client, tools, scopes, max_per_min: 60, expires, expired: false, enabled: true });
	return [
		mk(0, [ 'system_status', 'logread', 'network_clients', 'firewall_show', 'service_list', 'pkg_query', 'pkg_config_diff', 'wg_list_clients', 'uci_get' ], [ '*' ]),
		mk(1, [ 'ubus_call' ], [ 'system.board', 'system.info', 'network.interface.dump' ]),
		mk(2, [ 'net_diag' ], [ '*' ]),
		mk(3, [ 'sysupgrade' ], [ 'list', 'test', 'check' ]),
	];
}
function fresh() {
	calls.length = 0; notes.length = 0; modals.length = 0; writable = true; decideReply = null; statusFails = false;
	state = {
		st: {
			version: '1.6.0', listen: ':8730', socket: '/var/run/x.sock', running: true, pending: [], permit_all: [],
			clients: [ { name: 'claude-code', policies: 4 } ],
			policies: lookOnly('claude-code', iso(3600e3)),
			audit: [
				{ time: iso(-3600e3), client: 'claude-code', tool: 'uci_apply', scope: 'wireless.radio1.disabled', outcome: 'DENIED', error: 'no grant' },
				{ time: iso(-1800e3), client: 'claude-code', tool: 'logread', outcome: 'OK' },
				{ time: iso(-900e3), client: '<luci>', tool: 'grant_preset', outcome: 'OK', summary: '@readonly for 1h, 4 policy block(s)' },
			],
			requests: [
				{ id: 'aaaa1111', client: 'claude-code', tool: 'uci_apply', scope: 'wireless.radio1.disabled', family: 'wireless.*',
					args: 'set wireless.radio1.disabled=1', state: 'open', created: iso(-41e3), expires: iso(500e3) },
				{ id: 'bbbb2222', client: 'claude-code', tool: 'exec', scope: 'sh', family: 'sh', args: '', state: 'open',
					created: iso(-5e3), expires: iso(500e3) },
				{ id: 'cccc3333', client: 'claude-code', tool: 'logread', scope: '*', family: '*', args: '', state: 'allowed',
					created: iso(-99e3), expires: iso(500e3) },
			],
		},
		tools: registry(),
		settings: { request_wait: 60, request_ttl: 600, wait_max: 300, ttl_min: 60, ttl_max: 3600, mfa_clients: [ 'claude-code' ],
			channels: [ { name: 'pair', title: 'Pair from LuCI', enabled: false,
				harm: 'Anyone who can log in to LuCI with write access can add a key that reaches the router over SSH.' } ] },
	};
}
const load = async () => { const d = await page.load(); return { d, root: page.render(d) }; };
const flush = async () => { for (let i = 0; i < 6; i++) await new Promise(r => setTimeout(r, 0)); };
const card = (root, id) => find(root, x => x.attrs['data-request'] === id)[0];
// A tab's pane is a child of the page root: 0 style, 1 description, 2 banner, 3 error, 4 tabs, then the panes in order.
const pane = (root, name) => root.children[5 + [ 'overview', 'permissions', 'activity', 'settings', 'clients' ].indexOf(name)];
const abilityRow = (root, id) => find(pane(root, 'permissions'), x => x.attrs['data-ability-row'] === id)[0];
const noMachineText = t => {
	assert.doesNotMatch(t, /\d{4}-\d\d-\d\dT\d\d:/, 'an ISO timestamp is shown');
	assert.doesNotMatch(t, /\[object/, 'a nested array was printed as text');
	assert.doesNotMatch(t, /never expires|until \d{4}/, 'machine wording');
};

// 1. Overview: the waiting requests come first, in the owner's words, oldest first
fresh();
{
	const { root } = await load();
	const ov = pane(root, 'overview');
	const t = text(ov);
	assert.match(t, /Waiting for you \(2\)/);
	assert.ok(t.indexOf('Waiting for you') < t.indexOf('Assistants (1)'), 'requests above the assistants');
	assert.match(t, /Claude Code wants to turn off Wi-Fi radio 1/);
	assert.match(t, /Why it matters: Devices on that radio will disconnect\./);
	assert.match(t, /Changes things/);
	assert.match(t, /Undoes itself after 60 s unless confirmed\./);
	assert.match(t, /waiting \d+ s/);
	assert.match(t, /closes in \d+ min/);
	assert.equal(find(ov, x => x.attrs['data-request']).length, 2, 'only open requests get a card');
	assert.doesNotMatch(t, /cccc3333/);
	assert.doesNotMatch(t, /wireless\.radio1\.disabled|uci_apply|set wireless/, 'the technical facts are behind Show details');
	noMachineText(t);
	const order = find(ov, x => x.attrs['data-request']).map(x => x.attrs['data-request']);
	assert.deepEqual(order, [ 'aaaa1111', 'bbbb2222' ], 'oldest first');
	assert.match(text(root.children[4]), /Overview 2 waiting/);
	for (const name of [ 'Permissions', 'Activity', 'Settings' ]) assert.ok(text(root.children[4]).includes(name), name);
	assert.ok(!text(root.children[4]).includes('Clients'), 'no Clients tab while pairing is off');
}

// 2. Each assistant has one card with a plain summary; the connection and the last time it was seen are written out
fresh();
{
	const { root } = await load();
	assert.doesNotMatch(text(pane(root, 'overview')), /Pausing/, 'there is no Pause button to promise');
	const [ c ] = find(pane(root, 'overview'), x => x.attrs['data-assistant']);
	const t = text(c);
	assert.match(t, /Claude Code claude-code/);
	assert.match(t, /Connects over HTTP/, 'an assistant with a token connects over HTTP');
	assert.match(t, /last seen \d+ min ago/);
	assert.match(t, /Can look at Status & logs, Network & Wi-Fi, Software and VPN\./);
	assert.match(t, /Cannot run commands\./);
	assert.match(t, /Looks only .* (1 h|59 min|60 min) left/);
	assert.doesNotMatch(t, /Changes things|Full control/, 'a read-only grant of a tool that can do more is still Looks only');
	assert.doesNotMatch(t, /Can change/);
	noMachineText(t);
	const acts = find(c, x => x.tag === 'button').map(b => b.attrs['data-act']);
	assert.deepEqual(acts, [ 'change-permissions', 'remove-access' ], 'Remove access comes last');
	assert.match(find(c, x => x.attrs['data-act'] === 'remove-access')[0].attrs.class, /cbi-button-negative/);
	assert.match(find(c, x => x.attrs['data-act'] === 'remove-access')[0].attrs.class, /mcp-sep/, 'a gap before the destructive button');
}

// 3. Allow for 15 minutes is the narrow, primary answer; the card then collapses to one line with Undo
fresh();
{
	const { root } = await load();
	const c = card(root, 'aaaa1111');
	const quick = byAct(c, 'allow-once')[0];
	assert.match(quick.attrs.class, /cbi-button-action/, 'the narrowest choice is the primary button');
	quick.listeners.click();
	await flush();
	assert.deepEqual(calls[0], [ 'decide', [ 'aaaa1111', 'allow', 'exact', '15m', false ] ]);
	assert.equal(card(root, 'aaaa1111'), undefined, 'the answered card is gone');
	const line = find(pane(root, 'overview'), x => x.attrs['data-answered'] === 'aaaa1111')[0];
	assert.match(text(line), /Allowed for 15 minutes · Claude Code asked to turn off Wi-Fi radio 1/);
	byAct(line, 'undo')[0].listeners.click();
	await flush();
	assert.deepEqual(calls[1], [ 'revoke', [ 'claude-code', 4, false ] ], 'Undo removes the block the answer wrote');
	assert.equal(find(pane(root, 'overview'), x => x.attrs['data-answered']).length, 0);
}

// 4. The wider choices: this and similar changes, for eight hours
fresh();
{
	const { root } = await load();
	byAct(card(root, 'aaaa1111'), 'menu')[0].listeners.click();
	let c = card(root, 'aaaa1111');
	const t = text(c);
	assert.match(t, /Only this change/);
	assert.match(t, /This and similar Wi-Fi changes/);
	assert.match(t, /Everything an Operator can do/);
	const [ fam ] = find(c, x => x.attrs['data-breadth'] === 'family');
	fam.checked = true; fam.listeners.change();
	c = card(root, 'aaaa1111');
	const dur = find(c, x => x.tag === 'select')[0];
	dur.value = '8h'; dur.listeners.change();
	c = card(root, 'aaaa1111');
	assert.match(text(byAct(c, 'allow')[0]), /Allow for 8 hours/);
	byAct(c, 'allow')[0].listeners.click();
	await flush();
	assert.deepEqual(calls[0], [ 'decide', [ 'aaaa1111', 'allow', 'family', '8h', false ] ]);
}

// 5. A Full control request: red, Deny first, no wider choices, and a second confirmation before anything is written
fresh();
{
	const { root } = await load();
	const c = card(root, 'bbbb2222');
	assert.match(c.attrs.class, /mcp-req-full/);
	assert.match(text(c), /Claude Code wants to run a command as root/);
	assert.match(text(c), /A root command has no limits/);
	assert.match(text(c), /Full control/);
	assert.equal(byAct(c, 'menu').length, 0, 'no wider choices on a root command');
	assert.equal(byAct(c, 'allow-once').length, 0);
	const acts = find(c, x => x.tag === 'button').map(b => b.attrs['data-act']);
	assert.equal(acts[0], 'deny', 'Deny comes first');
	assert.doesNotMatch(byAct(c, 'allow-full')[0].attrs.class, /cbi-button-action|cbi-button-negative/, 'not the primary button');
	byAct(c, 'allow-full')[0].listeners.click();
	await flush();
	assert.equal(calls.length, 0, 'nothing is written by the first click');
	let c2 = card(root, 'bbbb2222');
	const go = byAct(c2, 'confirm-full')[0];
	assert.ok(go.disabled, 'disabled until the box is ticked');
	const [ box ] = find(c2, x => x.attrs.type === 'checkbox');
	box.checked = true; box.listeners.change();
	assert.equal(go.disabled, false);
	go.listeners.click();
	await flush();
	assert.deepEqual(calls[0], [ 'decide', [ 'bbbb2222', 'allow', 'exact', '15m', true ] ]);
}

// 6. Deny
fresh();
{
	const { root } = await load();
	byAct(card(root, 'aaaa1111'), 'deny')[0].listeners.click();
	await flush();
	assert.deepEqual(calls[0], [ 'decide', [ 'aaaa1111', 'deny', undefined, undefined, false ] ]);
	assert.match(text(find(pane(root, 'overview'), x => x.attrs['data-answered'])[0]), /Denied · Claude Code asked to turn off Wi-Fi radio 1/);
}

// 7. The daemon's own second confirmation still works if the card did not ask first
fresh();
{
	decideReply = p => p[4] ? { id: p[0], state: 'allowed' } : { error: 'this grant lets claude-code run sh', code: 'needs_confirm' };
	const { root } = await load();
	byAct(card(root, 'aaaa1111'), 'allow-once')[0].listeners.click();
	await flush();
	assert.equal(calls.length, 1);
	assert.equal(modals.length, 1, 'a confirmation is shown');
	const [ ack ] = find({ tag: 'x', attrs: {}, children: modals[0] }, x => x.attrs.type === 'checkbox');
	const go = find({ tag: 'x', attrs: {}, children: modals[0] }, x => x.attrs['data-act'] === 'confirm-shell')[0];
	assert.ok(go.disabled);
	ack.checked = true; ack.listeners.change();
	go.listeners.click();
	await flush();
	assert.equal(calls[1][1][4], true);
}

// 8. A refusal from the plugin reaches the owner
fresh();
{
	decideReply = () => ({ error: 'request aaaa1111 is already allowed' });
	const { root } = await load();
	byAct(card(root, 'aaaa1111'), 'allow-once')[0].listeners.click();
	await flush();
	assert.equal(notes.length, 1);
	assert.match(notes[0], /request aaaa1111 is already allowed/);
}

// 9. A request nobody answered in time is shown as refused
fresh();
{
	state.st.requests.push({ id: 'dddd4444', client: 'claude-code', tool: 'pkg_change', scope: '*', family: '*', args: '', state: 'expired',
		created: iso(-700e3), expires: iso(-60e3) });
	const { root } = await load();
	assert.match(text(find(pane(root, 'overview'), x => x.attrs['data-expired'] === 'dddd4444')[0]),
		/Claude Code asked to install or remove software\. Nobody answered in time, so it was refused\./);
}

// 10. A read-only LuCI account sees everything and can press nothing
fresh();
{
	writable = false;
	const { root } = await load();
	const all = text(root);
	assert.match(all, /You can see this page but not change anything\. Ask the router’s administrator/);
	assert.deepEqual(find(root, x => x.attrs['data-act'] && ![ 'details', 'raw', 'older', 'clear-filters', 'retry' ].includes(x.attrs['data-act'])).map(a => a.attrs['data-act']), [],
		'no buttons without the write ACL');
	assert.deepEqual(find(root, x => x.attrs.type === 'checkbox' && !x.disabled && !x.attrs.disabled && x.attrs['data-ability']), [],
		'no switches without the write ACL');
	assert.match(all, /Claude Code wants to turn off Wi-Fi radio 1/, 'the requests are still shown');
}

// 11. Permissions: one line per ability, in plain words, grouped; never a tool id as the main text
fresh();
{
	const { root } = await load();
	const p = pane(root, 'permissions');
	const t = text(p);
	assert.match(t, /What may Claude Code do\?/);
	assert.match(t, /What Claude Code can do now/);
	assert.match(t, /Status & logs · 5 of 5 on/);
	assert.match(t, /Network & Wi-Fi · 3 of 4 on/);
	assert.match(t, /Full control · 1 of 2 on/);
	noMachineText(t);
	const [ main ] = find(p, x => x.tag === 'table');
	assert.doesNotMatch(text(main), /uci_apply|system_status|logread|ubus_call/, 'no tool id in the ability list');
	assert.equal(find(main, x => x.attrs['data-ability-row']).length, 20, '20 abilities');
	assert.match(text(abilityRow(root, 'system_status')), /Router status Looks only .* On for (1 h|59 min|60 min)/);
	assert.match(text(abilityRow(root, 'uci_apply')), /Change router settings Changes things .* Off/);
	assert.match(text(abilityRow(root, 'ubus_list')), /Always on/);
	assert.equal(find(abilityRow(root, 'ubus_list'), x => x.tag === 'input').length, 0, 'an ability that needs no grant has no switch');
	assert.match(text(abilityRow(root, 'ubus_call')), /Limited to: Read-only router and network status/);
	assert.match(text(abilityRow(root, 'sysupgrade')), /Limited to: Check and test updates/);
	assert.match(text(abilityRow(root, 'exec')), /Off/);
	// the same three columns in every row, so the groups line up
	const cols = find(main, x => x.tag === 'tr' && x.attrs['data-ability-row']).map(r => r.children.map(c => c.attrs.class).join('|'));
	assert.equal(new Set(cols).size, 1, 'every row has the same column roles');
	assert.match(cols[0], /mcp-status.*mcp-allowed/);
}

// 12. Which of the three big choices the grants amount to
fresh();
{
	const { root } = await load();
	const radios = find(pane(root, 'permissions'), x => x.attrs.type === 'radio');
	assert.deepEqual(radios.map(r => r.attrs['data-choice']), [ 'look', 'change', 'nothing' ]);
	assert.deepEqual(radios.map(r => r.checked), [ true, false, false ]);
	assert.match(text(pane(root, 'permissions')), /Claude Code will be able to look for 1 hour\./);
	fresh();
	state.st.policies.push({ index: 4, client: 'claude-code', tools: [ 'logread' ], scopes: [ '*' ], expires: iso(3600e3), expired: false, enabled: true });
	state.st.policies.splice(0, 4);
	const r2 = (await load()).root;
	assert.deepEqual(find(pane(r2, 'permissions'), x => x.attrs.type === 'radio').map(r => r.checked), [ false, false, false ]);
	assert.match(text(pane(r2, 'permissions')), /Custom: set below/);
	fresh();
	state.st.policies = [];
	const r3 = (await load()).root;
	assert.deepEqual(find(pane(r3, 'permissions'), x => x.attrs.type === 'radio').map(r => r.checked), [ false, false, true ], 'nothing granted is Nothing');
}

// 13. Apply replaces what the assistant had, so a smaller choice really takes abilities away
fresh();
{
	const { root } = await load();
	const pick = c => { const [ r ] = find(pane(root, 'permissions'), x => x.attrs['data-choice'] === c); r.checked = true; r.listeners.change(); };
	pick('change');
	assert.match(text(pane(root, 'permissions')), /look and change for 1 hour/);
	const dur = find(pane(root, 'permissions'), x => x.attrs.id === 'mcp-duration')[0];
	dur.value = '8h'; dur.listeners.change();
	byAct(pane(root, 'permissions'), 'apply')[0].listeners.click();
	await flush();
	assert.deepEqual(calls, [ [ 'revoke', [ 'claude-code', null, true ] ], [ 'grant_preset', [ 'claude-code', 'operator', '8h' ] ] ]);
	calls.length = 0;
	pick('look');
	byAct(pane(root, 'permissions'), 'apply')[0].listeners.click();
	await flush();
	assert.deepEqual(calls[1], [ 'grant_preset', [ 'claude-code', 'readonly', '8h' ] ]);
	calls.length = 0;
	pick('nothing');
	assert.ok(find(pane(root, 'permissions'), x => x.attrs.id === 'mcp-duration')[0].disabled, 'no duration for Nothing');
	byAct(pane(root, 'permissions'), 'apply')[0].listeners.click();
	await flush();
	assert.deepEqual(calls, [ [ 'revoke', [ 'claude-code', null, true ] ] ]);
}

// 14. A switch only edits a draft; Apply then revokes or grants just the abilities that differ, tool by tool
fresh();
{
	const { root } = await load();
	const sw = id => find(abilityRow(root, id), x => x.tag === 'input')[0];
	const apply = () => byAct(pane(root, 'permissions'), 'apply')[0];
	const logread = sw('logread');
	assert.equal(logread.checked, true);
	logread.checked = false; logread.listeners.change();
	await flush();
	assert.deepEqual(calls, [], 'nothing is written by a tick');
	assert.match(text(abilityRow(root, 'logread')), /Turns off when you press Apply/);
	assert.match(text(pane(root, 'permissions')), /Nothing is saved until you press Apply/);
	const ua = sw('uci_apply');
	assert.equal(ua.checked, false);
	ua.checked = true; ua.listeners.change();
	assert.equal(sw('uci_apply').checked, true, 'the draft survives the redraw');
	assert.equal(sw('logread').checked, false);
	assert.deepEqual(find(pane(root, 'permissions'), x => x.attrs.type === 'radio').map(r => r.checked), [ false, false, false ], 'a hand edit is no preset');
	apply().listeners.click();
	await flush();
	assert.deepEqual(calls.map(c => c[0] + ':' + (c[0] === 'grant' ? c[1][1] + '/' + c[1][2] + '/' + c[1][3] : c[1][1])),
		[ 'revoke_tools:logread', 'grant:uci_apply/*/1h', 'grant:uci_confirm/*/1h', 'grant:uci_rollback/*/1h' ]);
}

// 15. Only some tools of an ability granted: Partly on, an indeterminate box, and Apply fills in the missing tools
fresh();
{
	state.st.policies = [ { index: 0, client: 'claude-code', tools: [ 'uci_apply' ], scopes: [ '*' ], expires: iso(3600e3), expired: false, enabled: true } ];
	const { root } = await load();
	const row = () => abilityRow(root, 'uci_apply');
	assert.match(text(row()), /Partly on/);
	const [ box ] = find(row(), x => x.tag === 'input');
	assert.equal(box.indeterminate, true);
	box.checked = true; box.listeners.change();
	await flush();
	assert.equal(calls.length, 0);
	byAct(pane(root, 'permissions'), 'apply')[0].listeners.click();
	await flush();
	assert.deepEqual(calls.map(c => c[1][1]), [ 'uci_confirm', 'uci_rollback' ]);
}

// 16. The root-command switch asks first; cancelling leaves it off, confirming only ticks it, Apply writes it
fresh();
{
	const { root } = await load();
	const box = () => find(abilityRow(root, 'exec'), x => x.tag === 'input')[0];
	box().checked = true; box().listeners.change();
	await flush();
	assert.equal(calls.length, 0);
	assert.equal(modals.length, 1);
	assert.equal(box().checked, false, 'not ticked until confirmed');
	let m = { tag: 'x', attrs: {}, children: modals[0] };
	assert.match(text(m), /no limits/i);
	find(m, x => x.attrs['data-act'] === 'cancel-shell')[0].listeners.click();
	assert.equal(box().checked, false, 'cancel leaves it off');
	assert.doesNotMatch(text(abilityRow(root, 'exec')), /Apply/);
	modals.length = 0;
	box().checked = true; box().listeners.change();
	m = { tag: 'x', attrs: {}, children: modals[0] };
	const [ ack ] = find(m, x => x.attrs.type === 'checkbox');
	const go = find(m, x => x.attrs['data-act'] === 'confirm-shell')[0];
	assert.ok(go.disabled);
	ack.checked = true; ack.listeners.change();
	go.listeners.click();
	await flush();
	assert.equal(calls.length, 0, 'confirming only ticks the switch');
	assert.equal(box().checked, true);
	byAct(pane(root, 'permissions'), 'apply')[0].listeners.click();
	await flush();
	assert.deepEqual(calls, [ [ 'grant', [ 'claude-code', 'exec', '*', '1h', true ] ] ]);
}

// 16b. Picking a preset shows its abilities in the switches before anything is saved
fresh();
{
	const { root } = await load();
	const sw = id => find(abilityRow(root, id), x => x.tag === 'input')[0];
	const [ r ] = find(pane(root, 'permissions'), x => x.attrs['data-choice'] === 'nothing');
	r.checked = true; r.listeners.change();
	assert.equal(calls.length, 0);
	assert.equal(sw('logread').checked, false);
	assert.match(text(abilityRow(root, 'logread')), /Turns off when you press Apply/);
	const [ r2 ] = find(pane(root, 'permissions'), x => x.attrs['data-choice'] === 'change');
	r2.checked = true; r2.listeners.change();
	assert.equal(sw('uci_apply').checked, true);
	assert.equal(sw('exec').checked, false);
	assert.equal(calls.length, 0);
}

// 17. Duplicate grants are one line; a never-ending grant beats a dated one; Advanced says how many were merged
fresh();
{
	state.st.policies.push({ index: 4, client: 'claude-code', tools: [ 'logread' ], scopes: [ '*' ], expires: '', expired: false, enabled: true },
		{ index: 5, client: 'claude-code', tools: [ 'logread' ], scopes: [ '*' ], expires: iso(60e3), expired: false, enabled: true });
	const { root } = await load();
	assert.equal(find(pane(root, 'permissions'), x => x.attrs['data-ability-row'] === 'logread').length, 1);
	assert.match(text(abilityRow(root, 'logread')), /On until you remove it/);
	const adv = find(pane(root, 'permissions'), x => x.attrs['data-tool-row'] === 'logread');
	assert.equal(adv.length, 1);
	assert.match(text(adv[0]), /3 grants merged/);
	assert.doesNotMatch(text(abilityRow(root, 'logread')), /grants merged/, 'the merge count is for Advanced only');
}

// 18. Advanced is closed to begin with; its rows name the tool, show what it is limited to and edit or revoke only that tool
fresh();
{
	const { root } = await load();
	const [ adv ] = find(pane(root, 'permissions'), x => x.tag === 'details');
	assert.ok(!('open' in adv.attrs), 'collapsed by default');
	assert.match(text(adv), /Advanced: limits per tool/);
	const row = find(adv, x => x.attrs['data-tool-row'] === 'ubus_call')[0];
	assert.match(text(row), /Read-only router and network status/);
	assert.match(text(row), /ubus_call/, 'the technical id is secondary text here');
	byAct(find(adv, x => x.attrs['data-tool-row'] === 'logread')[0], 'adv-revoke')[0].listeners.click();
	await flush();
	assert.deepEqual(calls, [ [ 'revoke_tools', [ 'claude-code', [ 'logread' ] ] ] ]);
	calls.length = 0;
	byAct(find(adv, x => x.attrs['data-tool-row'] === 'uci_apply')[0], 'adv-grant')[0].listeners.click();
	const edit = find(pane(root, 'permissions'), x => x.attrs['data-edit-row'] === 'uci_apply')[0];
	assert.ok(edit, 'the editor opens inline');
	const [ scope, dur ] = find(edit, x => x.tag === 'select');
	assert.ok(find(scope, x => x.tag === 'option').some(o => /Wi-Fi settings/.test(text(o))));
	scope.value = 'wireless.*'; scope.listeners.change();
	dur.value = '8h';
	byAct(edit, 'adv-save')[0].listeners.click();
	await flush();
	assert.deepEqual(calls, [ [ 'grant', [ 'claude-code', 'uci_apply', 'wireless.*', '8h', false, false ] ] ]);
}

// 19. Editing an existing limit replaces it
fresh();
{
	const { root } = await load();
	const [ adv ] = find(pane(root, 'permissions'), x => x.tag === 'details');
	byAct(find(adv, x => x.attrs['data-tool-row'] === 'net_diag')[0], 'adv-edit')[0].listeners.click();
	const edit = find(pane(root, 'permissions'), x => x.attrs['data-edit-row'] === 'net_diag')[0];
	find(edit, x => x.tag === 'select')[0].value = '__custom'; find(edit, x => x.tag === 'select')[0].listeners.change();
	find(edit, x => x.attrs['data-edit'] === 'custom')[0].value = 'ping';
	byAct(edit, 'adv-save')[0].listeners.click();
	await flush();
	assert.deepEqual(calls.map(c => c[0]), [ 'grant' ], 'one call, so a refused edit cannot leave the tool without its grant');
	assert.deepEqual(calls[0][1], [ 'claude-code', 'net_diag', 'ping', '1h', false, true ]);
}

// 19a. A tool with several limits keeps them in the editor; saving sends them space-separated
fresh();
{
	state.st.policies.push({ index: 9, client: 'claude-code', tools: [ 'net_diag' ], scopes: [ 'ping', 'dns' ], expires: iso(3600e3), expired: false, enabled: true });
	state.st.policies = state.st.policies.filter(p => !(p.tools.length === 1 && p.tools[0] === 'net_diag' && p.scopes[0] === '*'));
	const { root } = await load();
	const [ adv ] = find(pane(root, 'permissions'), x => x.tag === 'details');
	byAct(find(adv, x => x.attrs['data-tool-row'] === 'net_diag')[0], 'adv-edit')[0].listeners.click();
	const edit = find(pane(root, 'permissions'), x => x.attrs['data-edit-row'] === 'net_diag')[0];
	const custom = find(edit, x => x.attrs['data-edit'] === 'custom')[0];
	assert.equal(custom.value, 'ping dns', 'both limits are shown, not one');
	custom.value = '  ping   dns  traceroute ';
	byAct(edit, 'adv-save')[0].listeners.click();
	await flush();
	assert.deepEqual(calls[0][1], [ 'claude-code', 'net_diag', 'ping dns traceroute', '1h', false, true ]);
}

// 19c. The custom field says what a limit on this tool looks like, and only while Custom is chosen
fresh();
{
	const { root } = await load();
	const [ adv ] = find(pane(root, 'permissions'), x => x.tag === 'details');
	byAct(find(adv, x => x.attrs['data-tool-row'] === 'net_diag')[0], 'adv-edit')[0].listeners.click();
	const edit = find(pane(root, 'permissions'), x => x.attrs['data-edit-row'] === 'net_diag')[0];
	const hint = find(edit, x => x.attrs['data-edit'] === 'hint')[0];
	assert.match(hint.textContent, /HINT-net_diag/);
	assert.equal(hint.style.display, 'none', 'hidden until Custom is chosen');
	const sel = find(edit, x => x.tag === 'select')[0];
	sel.value = '__custom'; sel.listeners.change();
	assert.equal(hint.style.display, '');
}

// 19b. A blank or multi-name custom limit is refused before anything is sent
fresh();
{
	const { root } = await load();
	const [ adv ] = find(pane(root, 'permissions'), x => x.tag === 'details');
	byAct(find(adv, x => x.attrs['data-tool-row'] === 'net_diag')[0], 'adv-edit')[0].listeners.click();
	const edit = find(pane(root, 'permissions'), x => x.attrs['data-edit-row'] === 'net_diag')[0];
	const sel = find(edit, x => x.tag === 'select')[0];
	sel.value = '__custom'; sel.listeners.change();
	const custom = find(edit, x => x.attrs['data-edit'] === 'custom')[0];
	for (const [ v, want ] of [ [ '', /Type the limit/ ], [ '   ', /Type the limit/ ], [ 'wgua, tailscale', /commas/ ], [ 'wgua,tailscale,wg0', /commas/ ], [ "wgua'", /quote/ ] ]) {
		custom.value = v;
		byAct(edit, 'adv-save')[0].listeners.click();
		await flush();
		assert.deepEqual(calls, [], 'nothing is sent for ' + JSON.stringify(v));
		assert.equal(notes.length, 1, 'one banner, not a pile');
		assert.match(notes[0], want);
	}
}

// 19c. A tool with nothing to limit by offers no custom limit
fresh();
{
	const { root } = await load();
	const [ adv ] = find(pane(root, 'permissions'), x => x.tag === 'details');
	byAct(find(adv, x => x.attrs['data-tool-row'] === 'logread')[0], 'adv-edit')[0].listeners.click();
	const edit = find(pane(root, 'permissions'), x => x.attrs['data-edit-row'] === 'logread')[0];
	assert.deepEqual(find(find(edit, x => x.tag === 'select')[0], x => x.tag === 'option').map(o => o.attrs.value).slice(0, 1), [ '*' ]);
	assert.ok(!find(edit, x => x.tag === 'option').some(o => o.attrs.value === '__custom'), 'no Custom for an unscoped tool');
}

// 20. A scope with no plain name is shown as a custom limit with its raw text beside it
fresh();
{
	state.st.policies = [ { index: 0, client: 'claude-code', tools: [ 'uci_get' ], scopes: [ 'rpcd.something' ], expires: iso(3600e3), expired: false, enabled: true } ];
	const { root } = await load();
	assert.match(text(abilityRow(root, 'uci_get')), /Limited to: Custom limit rpcd\.something/);
}

// 21. Permit all: last on Permissions, inert until the box is ticked AND the name is typed, 24 h at most, no "until removed"
fresh();
{
	const { root } = await load();
	const p = pane(root, 'permissions');
	const sec = find(p, x => x.attrs['data-section'] === 'permit-all')[0];
	assert.ok(sec, 'the section is there');
	assert.match(sec.attrs.class, /mcp-danger/);
	assert.match(text(sec), /Not recommended/);
	assert.match(text(sec), /Still on while it runs: blocked actions stay blocked/);
	assert.equal(p.children[p.children.length - 1], sec, 'it comes after everything else');
	assert.deepEqual(find(sec, x => x.tag === 'option').map(o => o.attrs.value), [ '1h', '8h', '24h' ]);
	const [ box ] = find(sec, x => x.attrs.type === 'checkbox');
	const [ typed ] = find(sec, x => x.attrs.type === 'text');
	const go = byAct(sec, 'permit-all')[0];
	assert.match(go.attrs.class, /cbi-button-negative important/);
	assert.match(text(go), /Permit all for 1 hour/);
	assert.ok(go.disabled, 'starts disabled');
	const ready = () => { box.listeners.change(); typed.listeners.input(); return !go.disabled; };
	box.checked = true; typed.value = 'claude';
	assert.equal(ready(), false, 'a wrong name keeps it off');
	assert.match(text(sec), /That doesn’t match\. Type claude-code exactly\./);
	box.checked = false; typed.value = 'claude-code';
	assert.equal(ready(), false, 'an unticked box keeps it off');
	box.checked = true;
	assert.equal(ready(), true);
	go.listeners.click();
	await flush();
	assert.deepEqual(calls, [ [ 'permit_all', [ 'claude-code', '1h', true ] ] ]);
}

// 22. A running Permit all: a red banner above the tabs on every tab with a countdown and End now; the panel shows it too
fresh();
{
	state.st.permit_all = [ { client: 'claude-code', expires: iso(47 * 60e3) } ];
	const { root } = await load();
	const banner = find(root.children[2], x => x.attrs['data-permit-all'])[0];
	assert.ok(banner, 'banner above the tabs');
	assert.match(banner.attrs.class, /alert-message error/);
	assert.equal(banner.attrs.role, 'alert');
	assert.match(root.children[2].attrs.class, /mcp-sticky/);
	assert.match(text(banner), /Permit all is on\. Claude Code can do anything on this router for (46|47) min more \( until /);
	const panel = find(pane(root, 'permissions'), x => x.attrs['data-section'] === 'permit-all')[0];
	assert.match(text(panel), /When it ends, Claude Code goes back to what it had before\./);
	assert.equal(find(panel, x => x.attrs.type === 'checkbox').length, 0, 'the form is replaced by the running panel');
	byAct(banner, 'end-permit-all')[0].listeners.click();
	await flush();
	assert.deepEqual(calls, [ [ 'end_permit_all', [ 'claude-code' ] ] ]);
}

// 23. A read-only account sees the banner and no way to start or end it
fresh();
{
	writable = false;
	state.st.permit_all = [ { client: 'claude-code', expires: iso(3600e3) } ];
	const { root } = await load();
	assert.match(text(root.children[2]), /Permit all is on/);
	assert.equal(byAct(root, 'end-permit-all').length, 0);
	assert.equal(find(root, x => x.attrs['data-section'] === 'permit-all' && find(x, y => y.attrs.type === 'checkbox').length).length, 0);
}

// 24. Remove access asks first, then removes every grant of that assistant
fresh();
{
	const { root } = await load();
	byAct(pane(root, 'overview'), 'remove-access')[0].listeners.click();
	assert.equal(modals.length, 1);
	assert.match(text({ tag: 'x', attrs: {}, children: modals[0] }), /Remove all access for Claude Code\? It can still connect, but can only ask\. This can’t be undone\./);
	assert.equal(calls.length, 0);
	find({ tag: 'x', attrs: {}, children: modals[0] }, x => x.attrs['data-act'] === 'confirm-remove')[0].listeners.click();
	await flush();
	assert.deepEqual(calls, [ [ 'revoke', [ 'claude-code', null, true ] ] ]);
}

// 25. Change permissions on a card opens Permissions with that assistant picked
fresh();
{
	state.st.clients.push({ name: 'laptop', policies: 0 });
	const { root } = await load();
	byAct(find(pane(root, 'overview'), x => x.attrs['data-assistant'] === 'laptop')[0], 'change-permissions')[0].listeners.click();
	const picker = find(pane(root, 'permissions'), x => x.attrs.id === 'openwrt-mcp-client')[0];
	assert.equal(picker.value, 'laptop');
	assert.match(text(pane(root, 'permissions')), /What may Laptop do\?/);
}

// 26a. The service's own records read as sentences, not as "asked to use 201crequest201d"
fresh();
{
	state.st.audit.push(
		{ time: iso(-60e3), client: 'claude-code', tool: 'request', scope: 'firewall.@defaults[0].input', outcome: 'OK', summary: 'open 719edba8: uci_get on firewall.@defaults[0].input' },
		{ time: iso(-50e3), client: 'claude-code', tool: 'decide', outcome: 'OK', summary: '719edba8 allowed by luci' },
		{ time: iso(-40e3), client: 'claude-code', tool: 'expire', outcome: 'OK', summary: '1b9f9e01 expired unanswered' },
		{ time: iso(-30e3), client: 'claude-code', tool: 'session', outcome: 'OK', summary: 'stdio session opened via ssh' });
	const { root } = await load();
	const a = pane(root, 'activity');
	const t = text(a);
	assert.match(t, /Claude Code asked to read the firewall settings · held for your answer/);
	assert.match(t, /A request from Claude Code was allowed by luci/);
	assert.match(t, /A request from Claude Code expired unanswered/);
	assert.match(t, /stdio session opened via ssh/);
	assert.doesNotMatch(t, /use 201c(request|decide|expire|session)201d/);
	const row = find(a, x => x.attrs['data-activity'])[0];
	assert.ok(find(row, x => x.attrs['class'] === 'mcp-what').length, 'text and Show raw share one flex wrapper');
}

// 26. Activity: sentences, not log lines; raw text on request; filters; older entries on demand
fresh();
{
	const { root } = await load();
	const a = pane(root, 'activity');
	const t = text(a);
	noMachineText(t);
	assert.match(t, /Claude Code tried to change router settings · not allowed/);
	assert.match(t, /Claude Code asked to read the system log · done/);
	assert.match(t, /You gave an assistant a set of abilities/);
	assert.match(t, /Claude Code asked to turn off Wi-Fi radio 1 · waiting for you/);
	assert.match(t, /Today/);
	assert.doesNotMatch(t, /DENIED|no grant/, 'raw words are behind Show raw');
	byAct(a, 'raw')[0].listeners.click();
	assert.match(text(a), /"client":"claude-code"/);
	const kind = find(a, x => x.attrs.id === 'mcp-f-kind')[0];
	kind.value = 'refused'; kind.listeners.change();
	assert.equal(find(a, x => x.attrs['data-activity']).length, 1);
	kind.value = ''; kind.listeners.change();
	const q = find(a, x => x.attrs.id === 'mcp-search')[0];
	q.value = 'zzz'; q.listeners.input();
	assert.match(text(a), /No activity matches these filters\./);
	byAct(a, 'clear-filters')[0].listeners.click();
	assert.ok(find(pane(root, 'activity'), x => x.attrs['data-activity']).length >= 4);
}
fresh();
{
	for (let i = 0; i < 40; i++) state.st.audit.push({ time: iso(-i * 1000), client: 'claude-code', tool: 'logread', outcome: 'OK' });
	const { root } = await load();
	const a = pane(root, 'activity');
	assert.equal(find(a, x => x.attrs['data-activity']).length, 25);
	assert.match(text(a), /Showing 25 of \d+/);
	byAct(a, 'older')[0].listeners.click();
	assert.ok(find(pane(root, 'activity'), x => x.attrs['data-activity']).length > 25);
}

// 27. Settings in the owner's words, saved with the same two numbers as before
fresh();
{
	const { root } = await load();
	const s = pane(root, 'settings');
	const t = text(s);
	assert.match(t, /Ask me before refusing/);
	assert.doesNotMatch(t, /sends no request/, '0 still opens a request, the call is just refused at once');
	assert.match(t, /0 refuses at once but still sends you the request/);
	assert.match(t, /Keep a request open for/);
	assert.match(t, /How requests reach you/);
	assert.match(t, /This page .* Always on/);
	assert.match(t, /2-step confirmation .* Set up for Claude Code .* openwrt-mcp mfa/);
	assert.match(t, /Add assistants from this page/);
	assert.match(t, /Risk: Anyone who can log in to LuCI with write access/);
	const ttl = find(s, x => x.attrs.id === 'mcp-ttl')[0];
	assert.deepEqual(find(ttl, x => x.tag === 'option').map(o => o.attrs.value), [ '60', '300', '600', '1800', '3600' ], 'only what the daemon accepts');
	assert.equal(ttl.value, '600');
	const wait = find(s, x => x.attrs.id === 'mcp-wait')[0];
	wait.value = '30'; ttl.value = '300';
	const actions = find(s, x => /cbi-page-actions/.test(x.attrs.class || ''))[0];
	assert.deepEqual(find(actions, x => x.tag === 'button').map(b => b.attrs['data-act']), [ 'reset-settings', 'save-settings' ], 'Reset then Save');
	byAct(s, 'save-settings')[0].listeners.click();
	await flush();
	assert.deepEqual(calls, [ [ 'set_settings', [ 30, 300 ] ] ]);
	assert.match(notes.join(' '), /Saved/);
}

// 27b. Ticking a switch keeps the unsaved number and select; banners replace each other
fresh();
{
	const { root } = await load();
	let s = pane(root, 'settings');
	find(s, x => x.attrs.id === 'mcp-wait')[0].value = '45';
	find(s, x => x.attrs.id === 'mcp-wait')[0].listeners.input();
	find(s, x => x.attrs.id === 'mcp-ttl')[0].value = '300';
	find(s, x => x.attrs.id === 'mcp-ttl')[0].listeners.change();
	state.settings.channels[0].enabled = true;
	find(s, x => x.attrs['data-channel'] === 'pair')[0].checked = true;
	find(s, x => x.attrs['data-channel'] === 'pair')[0].listeners.change();
	await flush();
	s = pane(root, 'settings');
	assert.equal(find(s, x => x.attrs.id === 'mcp-wait')[0].value, '45', 'the typed number survives the redraw');
	assert.equal(find(s, x => x.attrs.id === 'mcp-ttl')[0].value, '300', 'the chosen time survives the redraw');
	assert.match(text(s), /apply when you press Save/);
	byAct(s, 'save-settings')[0].listeners.click();
	await flush();
	byAct(pane(root, 'settings'), 'save-settings')[0].listeners.click();
	await flush();
	assert.equal(notes.filter(n => /Saved/.test(n)).length, 1, 'old Saved banners are taken down');
}

// 27c. The Activity line names the switch and its new state
fresh();
{
	state.st.audit.push({ time: iso(-60e3), client: '<luci>', tool: 'set_channel', scope: 'push', outcome: 'OK', summary: 'push_hook=1' },
		{ time: iso(-30e3), client: '<luci>', tool: 'set_channel', scope: 'chat', outcome: 'OK', summary: 'chat_approve=0' });
	const { root } = await load();
	const t = text(pane(root, 'activity'));
	assert.match(t, /You turned on “Run my own script when a request arrives”/);
	assert.match(t, /You turned off “Answer in the assistant’s chat”/);
}

// 27d. The open tab survives a reload; a stored tab that no longer exists falls back to Overview
fresh();
{
	const store = {};
	win.sessionStorage = { getItem: k => store[k] ?? null, setItem: (k, v) => { store[k] = v; } };
	try {
		let { root } = await load();
		find(root, x => x.tag === 'a' && /Settings/.test(text(x)))[0].listeners.click({ preventDefault() {} });
		assert.equal(store['openwrt-mcp.tab'], 'settings');
		({ root } = await load());
		assert.match(text(find(root, x => /cbi-tab(?!-)/.test(x.attrs.class || ''))[0]), /Settings/, 'Settings is the open tab after the reload');
		store['openwrt-mcp.tab'] = 'clients'; // pairing is off, so there is no such tab
		({ root } = await load());
		assert.match(text(find(root, x => /cbi-tab(?!-)/.test(x.attrs.class || ''))[0]), /Overview/);
	} finally { delete win.sessionStorage; }
}

// 27e. Ticking a switch sets the boxes in place: the Settings pane is not rebuilt, so nothing flashes or moves
fresh();
{
	const { root } = await load();
	const settings = pane(root, 'settings');
	let rebuilt = false;
	const rebuild = settings.replaceChildren;
	settings.replaceChildren = function(...a) { rebuilt = true; return rebuild.apply(this, a); };
	const [ sw ] = find(settings, x => x.attrs['data-channel'] === 'pair');
	state.settings.channels[0].enabled = true; // what the router will report after the call
	sw.checked = true; sw.listeners.change();
	await flush();
	assert.equal(rebuilt, false, 'a switch tick must not rebuild the pane');
	assert.equal(find(settings, x => x.attrs['data-channel'] === 'pair')[0], sw, 'the same box stays in the page');
	assert.ok(find(root, x => x.tag === 'a' && /Clients/.test(text(x))).length, 'the Clients tab still appears');
}

// 27f. Other settings changed with the tick: the pane is rebuilt and the scroll position is put back
fresh();
{
	const { root } = await load();
	const scrolled = [];
	const settings = pane(root, 'settings');
	let jumped = false;
	// The page "jumps" to the top only when the Settings pane is rebuilt.
	const rebuild = settings.replaceChildren;
	settings.replaceChildren = function(...a) { jumped = true; return rebuild.apply(this, a); };
	Object.defineProperty(win, 'pageYOffset', { configurable: true, get: () => (jumped ? 0 : 300) });
	win.scrollTo = (x, y) => scrolled.push([ x, y ]);
	const [ sw ] = find(settings, x => x.attrs['data-channel'] === 'pair');
	state.settings.request_ttl = 120;
	sw.checked = true; sw.listeners.change();
	await flush();
	delete win.pageYOffset; delete win.scrollTo;
	assert.ok(jumped, 'the Settings pane was not redrawn, so this test proves nothing');
	assert.deepEqual(scrolled, [ [ 0, 300 ] ], 'the Settings redraw must restore the scroll position');
}

// 27g. Turning pairing on adds a tab and the tab bar wraps to a second line: the ticked box is kept where it was
fresh();
{
	const { root } = await load();
	const tabbar = find(root, x => x.attrs.class === 'cbi-tabmenu')[0];
	let wrapped = false;
	const rebuild = tabbar.replaceChildren;
	tabbar.replaceChildren = function(...a) { wrapped = true; return rebuild.apply(this, a); };
	const [ sw ] = find(pane(root, 'settings'), x => x.attrs['data-channel'] === 'pair');
	const scrolledBy = [];
	win.scrollBy = (x, y) => scrolledBy.push([ x, y ]);
	doc.activeElement = null;
	doc.getElementById = id => (id === sw.attrs.id ? { getBoundingClientRect: () => ({ top: wrapped ? 744 : 700 }) } : null);
	state.settings.channels[0].enabled = true;
	sw.checked = true; sw.listeners.change();
	await flush();
	delete win.scrollBy; delete doc.getElementById; delete doc.activeElement;
	assert.deepEqual(scrolledBy, [ [ 0, 44 ] ], 'the page scrolls by what the tab bar grew, so the box stays put');
}

// 28. The pairing channel is off: no Clients tab; switching it on is one call. On: the tab shows the key form.
fresh();
{
	const { root } = await load();
	const [ sw ] = find(pane(root, 'settings'), x => x.attrs['data-channel'] === 'pair');
	assert.equal(sw.checked, false);
	sw.checked = true; sw.listeners.change();
	await flush();
	assert.deepEqual(calls, [ [ 'set_channel', [ 'pair', true ] ] ]);
}
fresh();
{
	state.settings.channels[0].enabled = true;
	const { root } = await load();
	assert.ok(text(root.children[4]).includes('Clients'));
	const c = pane(root, 'clients');
	assert.match(text(c), /reaches the router over SSH/);
	find(c, x => x.attrs.id === 'openwrt-mcp-pair-name')[0].value = 'laptop';
	find(c, x => x.attrs.id === 'openwrt-mcp-pair-key')[0].value = 'ssh-ed25519 AAAAexample laptop';
	byAct(c, 'pair')[0].listeners.click();
	await flush();
	assert.deepEqual(calls, [ [ 'pair', [ 'laptop', 'ssh-ed25519 AAAAexample laptop', 'readonly', '7d' ] ] ]);
	assert.match(notes.join(' '), /Paired laptop/);
}
fresh();
{
	writable = false;
	state.settings.channels[0].enabled = true;
	const { root } = await load();
	assert.equal(byAct(pane(root, 'clients'), 'pair').length, 0);
	assert.ok(find(pane(root, 'settings'), x => x.attrs['data-channel'] === 'pair')[0].disabled || 'disabled' in find(pane(root, 'settings'), x => x.attrs['data-channel'] === 'pair')[0].attrs);
}

// 29. A rollback waiting for confirmation, and nothing waiting at all
fresh();
{
	state.st.pending = [ { token: 't', client: 'claude-code', configs: [ 'wireless' ], deadline: iso(60e3) } ];
	const { root } = await load();
	assert.match(text(pane(root, 'overview')), /A change to wireless by Claude Code is waiting for confirmation\. It undoes itself in \d+ s/);
}
fresh();
{
	state.st.requests = [];
	const { root } = await load();
	assert.doesNotMatch(text(pane(root, 'overview')), /Waiting for you/);
}

// 30. No assistant yet: an explanation instead of an empty table
fresh();
{
	state.st.clients = []; state.st.policies = []; state.st.audit = []; state.st.requests = [];
	const { root } = await load();
	assert.match(text(pane(root, 'overview')), /No assistants yet/);
	assert.match(text(pane(root, 'overview')), /No assistant has connected to this router\./);
	assert.match(text(pane(root, 'permissions')), /No assistants yet/);
}

// 31. The service is down: one clear message with Try again, and the page is not a stack trace
fresh();
{
	statusFails = true;
	const { root } = await load();
	const err = find(root, x => x.attrs['data-error'])[0];
	assert.ok(err);
	assert.match(text(err), /Can’t reach the MCP service\. It may be stopped or still starting\./);
	assert.deepEqual(find(err, x => x.attrs['data-act']).map(b => b.attrs['data-act']), [ 'retry' ]);
	assert.match(find(err, x => x.tag === 'a')[0].attrs.href, /admin\/system\/startup/);
	assert.doesNotMatch(text(root), /\[object/);
	statusFails = false;
	byAct(err, 'retry')[0].listeners.click();
	await flush();
	assert.equal(find(root, x => x.attrs['data-error']).length, 0, 'the message goes away once the service answers');
	assert.match(text(pane(root, 'overview')), /Assistants \(1\)/);
}

// 32. A tool the page does not know still gets a row, so a new server tool cannot be hidden
fresh();
{
	state.tools.groups[0].tools.push(tool('new_thing', 'Do a new thing', 'write'));
	const { root } = await load();
	assert.match(text(abilityRow(root, 'new_thing')), /Do a new thing/);
	assert.match(text(pane(root, 'permissions')), /Other · 0 of 1 on/);
}

// 33. Every string a screen shows is plain: no ISO time, glob, tool id or JSON key as primary text, on any tab
fresh();
{
	state.st.policies.push({ index: 4, client: 'claude-code', tools: [ 'uci_apply', 'uci_confirm', 'uci_rollback' ], scopes: [ 'wireless.*' ],
		expires: iso(7200e3), expired: false, enabled: true });
	const { root } = await load();
	for (const name of [ 'overview', 'activity', 'settings' ]) {
		const t = text(pane(root, name));
		noMachineText(t);
		assert.doesNotMatch(t, /\b(uci_apply|uci_get|system_status|pkg_change|wg_new_client|service_control)\b/, name + ' shows a tool id');
		assert.doesNotMatch(t, /wireless\.\*|network\.interface\.\*/, name + ' shows a scope glob');
	}
	const [ main ] = find(pane(root, 'permissions'), x => x.tag === 'table');
	assert.doesNotMatch(text(main), /\b(uci_apply|uci_get|system_status|pkg_change)\b|wireless\.\*/);
	assert.match(text(abilityRow(root, 'uci_apply')), /Limited to: Wi-Fi settings/);
}
console.log('ok');
