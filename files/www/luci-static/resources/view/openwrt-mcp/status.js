'use strict';
'require view';
'require rpc';
'require ui';
'require poll';

// Services -> MCP Server (docs/luci-approvals.md, 8.4). Everything goes through the openwrt-mcp
// rpcd plugin; nothing here runs a program. Reading is the read ACL group and every change is the
// write group, enforced by rpcd. The page hides the buttons a user cannot use, but that is
// presentation: a forged call without the write ACL is refused by rpcd itself.
//
// The owner sees abilities, not tool ids: ABILITY_GROUPS names the 20 things an assistant can be
// allowed to do and says which registry tools make each one up. A tool the registry has and this
// table lacks still gets a row (group "Other"), so the page cannot hide a tool the server added.
// Colours, fonts and control heights come from the theme; the CSS below is layout and the three
// risk badges.

// The open tab is remembered per browser tab, so a reload stays on the same page.
var TAB_KEY = 'openwrt-mcp.tab';
var callStatus = rpc.declare({ object: 'openwrt-mcp', method: 'status', params: [ 'audit' ], expect: { '': {} } });
var callTools = rpc.declare({ object: 'openwrt-mcp', method: 'tools', expect: { '': {} } });
var callSettings = rpc.declare({ object: 'openwrt-mcp', method: 'settings', expect: { '': {} } });
var callDecide = rpc.declare({ object: 'openwrt-mcp', method: 'decide',
	params: [ 'id', 'decision', 'breadth', 'duration', 'confirm' ], expect: { '': {} } });
var callGrant = rpc.declare({ object: 'openwrt-mcp', method: 'grant',
	params: [ 'client', 'tool', 'scope', 'duration', 'confirm', 'replace' ], expect: { '': {} } });
var callGrantPreset = rpc.declare({ object: 'openwrt-mcp', method: 'grant_preset',
	params: [ 'client', 'preset', 'duration' ], expect: { '': {} } });
var callRevoke = rpc.declare({ object: 'openwrt-mcp', method: 'revoke',
	params: [ 'client', 'index', 'all' ], expect: { '': {} } });
var callRevokeTools = rpc.declare({ object: 'openwrt-mcp', method: 'revoke_tools',
	params: [ 'client', 'tools' ], expect: { '': {} } });
var callPermitAll = rpc.declare({ object: 'openwrt-mcp', method: 'permit_all',
	params: [ 'client', 'duration', 'confirm' ], expect: { '': {} } });
var callEndPermitAll = rpc.declare({ object: 'openwrt-mcp', method: 'end_permit_all',
	params: [ 'client' ], expect: { '': {} } });
var callSetChannel = rpc.declare({ object: 'openwrt-mcp', method: 'set_channel',
	params: [ 'channel', 'enabled' ], expect: { '': {} } });
var callPair = rpc.declare({ object: 'openwrt-mcp', method: 'pair',
	params: [ 'client', 'pubkey', 'preset', 'duration' ], expect: { '': {} } });
var callSetSettings = rpc.declare({ object: 'openwrt-mcp', method: 'set_settings',
	params: [ 'request_wait', 'request_ttl' ], expect: { '': {} } });
var callAccess = rpc.declare({ object: 'session', method: 'access',
	params: [ 'scope', 'object', 'function' ], expect: { 'access': true } });

var AUDIT_LINES = 200;
var ACTIVITY_PAGE = 25;
var ONCE = '15m'; // the shortest grant a request card can write; there is no single-use grant

var DURATIONS = [ [ '1h', _('1 hour') ], [ '8h', _('8 hours') ], [ '1d', _('1 day') ], [ 'never', _('until I remove it') ] ];
var PERMIT_ALL_DURATIONS = [ [ '1h', _('1 hour') ], [ '8h', _('8 hours') ], [ '24h', _('24 hours') ] ];
var DURATION_WORDS = { '15m': _('15 minutes'), '1h': _('1 hour'), '8h': _('8 hours'), '1d': _('1 day'), '7d': _('7 days'), 'never': _('until you remove it') };

var CSS = [
	'.mcp-risk{display:inline-block;box-sizing:border-box;height:auto;min-height:0;margin:2px 0;padding:2px 8px;border-radius:3px;font-size:75%;line-height:1.4;font-weight:600;letter-spacing:.04em;text-transform:uppercase;vertical-align:middle;white-space:nowrap}',
	'.mcp-risk-look{background:#1d6b38;color:#fff}',
	'.mcp-risk-change{background:#f0c23b;color:#2b2000}',
	'.mcp-risk-full{background:#b3261e;color:#fff}',
	'.mcp-row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}',
	'.mcp-row .mcp-sep{margin-left:16px}',
	'.mcp-head{display:flex;justify-content:space-between;gap:8px;flex-wrap:wrap;align-items:baseline}',
	'.mcp-head h4,.mcp-head h3{margin:0}',
	'.mcp-sticky{position:sticky;top:0;z-index:50}',
	'.mcp-card{margin:8px 0;padding:8px 16px}',
	'.mcp-card.cbi-section-node{border:1px solid rgba(128,128,128,.35);border-radius:4px}',
	'.mcp-card.mcp-req{border-left:4px solid #f0c23b}',
	'.mcp-card.mcp-req-full{border-left-color:#b3261e}',
	'.mcp-card p,.mcp-card .mcp-line{margin:4px 0;max-width:70ch}',
	'.mcp-card .mcp-actions{margin-top:8px}',
	'.mcp-card code,.mcp code{word-break:break-all;white-space:normal}',
	'.mcp-choices{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;border:0;padding:0;margin:8px 0}',
	'.mcp-choices legend{font-weight:600;margin-bottom:4px}',
	'.mcp-choice{display:block;border:1px solid rgba(128,128,128,.5);border-radius:4px;padding:8px 12px;cursor:pointer}',
	'.mcp-choice-on{border-width:2px;padding:7px 11px}',
	'.mcp-choice p{margin:4px 0 0;max-width:70ch}',
	'.mcp-table .mcp-status{width:14em}',
	'.mcp-table .mcp-allowed{width:9em;text-align:right}',
	'.mcp-table .mcp-actions-col{width:12em;text-align:right}',
	'.mcp-table .mcp-group th{text-align:left}',
	'.mcp-table td p,.mcp-table td .mcp-line{margin:2px 0;max-width:70ch}',
	'.mcp-menu{border:1px solid rgba(128,128,128,.5);border-radius:4px;padding:8px 12px;margin-top:8px;max-width:70ch}',
	'.mcp-menu label{display:block;margin:4px 0}',
	'.mcp-menu .mcp-sub{display:block;margin-left:24px;font-size:90%;opacity:.8}',
	'.mcp-danger{border:2px solid #b3261e;border-radius:4px;padding:8px 16px;margin-top:24px}',
	'.mcp-filters{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:8px 0}',
	'.mcp-raw code{display:block}',
	'.mcp-dim{opacity:.8}',
	'.mcp-pending{font-style:italic}',
	'@media (max-width:600px){',
	'.mcp-choices{grid-template-columns:1fr}',
	'.mcp-card .mcp-actions button,.mcp-card .mcp-actions .mcp-sep{flex:1 1 100%;margin-left:0}',
	'.mcp-row button,.mcp-row select,.mcp-row input[type=text]{min-height:40px}',
	'.mcp-table .mcp-status,.mcp-table .mcp-allowed,.mcp-table .mcp-actions-col{width:auto;text-align:left}',
	'.mcp .mcp-table,.mcp .mcp-table tbody{display:block;width:100%;border:0}',
	'.mcp .mcp-table tr.table-titles{display:none}',
	'.mcp .mcp-table tr.tr{display:block;margin:8px 0;padding:4px 12px;border:1px solid rgba(128,128,128,.35);border-radius:6px}',
	'.mcp .mcp-table td.td{display:block;width:auto;min-height:0;padding:6px 0;border:0;text-align:left}',
	'.mcp .mcp-table td.td::before{display:block;content:attr(data-title);margin-bottom:2px;font-size:75%;letter-spacing:.05em;text-transform:uppercase;opacity:.7}',
	'.mcp .mcp-table td.td:empty{display:none}',
	'.mcp .mcp-table tr.mcp-group{margin:16px 0 0;padding:0;border:0}',
	'.mcp .mcp-table tr.mcp-group th.th{display:block;padding:4px 0;border:0;font-size:105%}',
	'}'
].join('\n');

// ---------------------------------------------------------------- the words

var RISK = { look: _('Looks only'), change: _('Changes things'), full: _('Full control') };
var RISK_OF_BADGE = { read: 'look', write: 'change', shell: 'full' };

function ab(name, sentence, tools, risk) {
	return { id: tools[0], name: name, sentence: sentence, tools: tools, risk: risk };
}

var ABILITY_GROUPS = [
	{ id: 'status', title: _('Status & logs'), items: [
		ab(_('Router status'), _('Model, uptime, memory and load.'), [ 'system_status' ], 'look'),
		ab(_('System log'), _('Read the router’s log messages.'), [ 'logread' ], 'look'),
		ab(_('Running services'), _('See which services are running.'), [ 'service_list' ], 'look'),
		ab(_('Connection tests'), _('Ping, trace a route or look up a name.'), [ 'net_diag' ], 'look'),
		ab(_('List of router parts'), _('Names only. Harmless, so always allowed.'), [ 'ubus_list' ], 'look') ] },
	{ id: 'network', title: _('Network & Wi-Fi'), items: [
		ab(_('Connected devices'), _('Names and addresses of devices on your network.'), [ 'network_clients' ], 'look'),
		ab(_('Firewall rules'), _('See what the firewall lets in and out.'), [ 'firewall_show' ], 'look'),
		ab(_('Read router settings'), _('Network, Wi-Fi, DHCP and firewall settings. Passwords stay hidden.'), [ 'uci_get' ], 'look'),
		ab(_('Change router settings'), _('Wi-Fi, network, firewall, DHCP. Undoes itself after 60 s unless confirmed.'),
			[ 'uci_apply', 'uci_confirm', 'uci_rollback' ], 'change') ] },
	{ id: 'software', title: _('Software'), items: [
		ab(_('Installed software'), _('See what is installed and what can be updated.'), [ 'pkg_query' ], 'look'),
		ab(_('Settings after an update'), _('Compare your settings with new defaults after an update.'), [ 'pkg_config_diff' ], 'look'),
		ab(_('Install or remove software'), _('Install, remove or update programs, and settle their settings after an update.'),
			[ 'pkg_change', 'pkg_config_resolve' ], 'change') ] },
	{ id: 'vpn', title: _('VPN'), items: [
		ab(_('VPN devices'), _('See which devices may connect over WireGuard.'), [ 'wg_list_clients' ], 'look'),
		ab(_('Add a VPN device'), _('Shows the new device’s private key to the assistant.'), [ 'wg_new_client' ], 'change'),
		ab(_('Remove a VPN device'), _('That device can no longer connect.'), [ 'wg_remove_client' ], 'change') ] },
	{ id: 'system', title: _('System'), items: [
		ab(_('Start, stop or restart services'), _('Stopping a service can cut off Wi-Fi or the internet until it starts again.'), [ 'service_control' ], 'change'),
		ab(_('Firmware check and backups'), _('Check for and test updates, make backups. Never installs firmware.'), [ 'sysupgrade' ], 'change'),
		ab(_('Unlock with your second factor'), _('Lets you approve protected abilities with your code. Always allowed.'), [ 'mfa_unlock' ], 'none') ] },
	{ id: 'full', title: _('Full control'), items: [
		ab(_('Read router internals'), _('Call the router’s internal services directly. Usually limited to read-only status.'), [ 'ubus_call' ], 'full'),
		ab(_('Run any command as root'), _('No limits. Turning this on asks you to confirm twice.'), [ 'exec' ], 'full') ] }
];

// The tools the Operator preset adds to Look only (presets.go). The registry flags what Look only
// holds (`readonly`); the extra tools are named here.
var OPERATOR_EXTRA = [ 'uci_apply', 'uci_confirm', 'uci_rollback', 'service_control', 'pkg_change', 'pkg_config_resolve',
	'wg_new_client', 'wg_remove_client' ];

var UNGATED = { ubus_list: true, mfa_unlock: true };

// What the Look only preset lets ubus_call read (presets.go readonlyUbus).
var READONLY_UBUS = [ 'system.board', 'system.info', 'network.interface.dump', 'network.interface.*.status', 'network.device.status',
	'network.wireless.status', 'iwinfo.devices', 'iwinfo.info', 'iwinfo.assoclist', 'iwinfo.freqlist', 'iwinfo.txpowerlist',
	'iwinfo.countrylist', 'iwinfo.survey', 'hostapd.*.get_clients', 'hostapd.*.get_status', 'luci-rpc.getDHCPLeases',
	'luci-rpc.getHostHints', 'luci-rpc.getNetworkDevices', 'luci-rpc.getWirelessDevices', 'luci-rpc.getBoardJSON', 'service.list',
	'rc.list', 'dnsmasq.metrics', 'uci.configs', 'uci.changes', 'log.read' ];

var VERBS = {
	system_status: _('look at the router status'), logread: _('read the system log'), service_list: _('see which services are running'),
	net_diag: _('run a connection test'), ubus_list: _('list the router’s internal parts'), network_clients: _('see the devices on your network'),
	firewall_show: _('see the firewall rules'), uci_get: _('read the router settings'), uci_apply: _('change router settings'),
	uci_confirm: _('confirm a settings change'), uci_rollback: _('undo a settings change'), pkg_query: _('see the installed software'),
	pkg_config_diff: _('compare your settings with new defaults'), pkg_change: _('install or remove software'),
	pkg_config_resolve: _('settle settings after a software update'), wg_list_clients: _('see the VPN devices'),
	wg_new_client: _('add a VPN device'), wg_remove_client: _('remove a VPN device'), service_control: _('start, stop or restart a service'),
	sysupgrade: _('check for firmware updates or make a backup'), mfa_unlock: _('unlock protected abilities with your code'),
	ubus_call: _('call an internal router service'), exec: _('run a command as root')
};

var AREAS = {
	wireless: { name: _('Wi-Fi settings'), noun: _('Wi-Fi settings'), short: _('Wi-Fi'), why: _('Devices may disconnect while Wi-Fi restarts.') },
	network: { name: _('Network settings'), noun: _('network settings'), short: _('network'), why: _('A mistake can cut you off; it undoes itself after 60 s.') },
	firewall: { name: _('Firewall settings'), noun: _('firewall settings'), short: _('firewall'), why: _('Can open or close access from the internet.') },
	dhcp: { name: _('Address and name settings (DHCP, DNS)'), noun: _('address and name settings (DHCP, DNS)'), short: _('address and name'), why: _('Devices may get new addresses.') }
};

function displayName(id) {
	return String(id).split(/[-_.]+/).filter(Boolean).map(function(w) {
		return w.charAt(0).toUpperCase() + w.slice(1);
	}).join(' ');
}

function readOnlyScope(scope) {
	return READONLY_UBUS.indexOf(scope) >= 0;
}

// The plain name and the "why it matters" line for one scope of one tool; null when there is none.
function bundleFor(tool, scope) {
	if (scope === '*' || scope === '')
		return { name: _('Everything this tool can touch'), why: _('No limit inside this tool.') };
	if (tool === 'ubus_call' && readOnlyScope(scope))
		return { name: _('Read-only router and network status'), why: _('Reads only; changes nothing.') };
	if (tool === 'sysupgrade') {
		if (scope === 'backup')
			return { name: _('Make backups'), why: _('The backup contains your passwords.') };
		if ([ 'list', 'test', 'check' ].indexOf(scope) >= 0)
			return { name: _('Check and test updates'), why: _('Reads only; never installs.') };
		return null;
	}
	var radio = /^wireless\.radio(\d+)\.disabled$/.exec(scope);
	if (radio)
		return { name: _('Turn Wi-Fi radio %s on or off').format(radio[1]), why: _('Devices on that radio will disconnect.') };
	var area = AREAS[scope.split('.')[0]];
	return area && [ 'uci_get', 'uci_apply' ].indexOf(tool) >= 0 ? area : null;
}

// {names, custom}: the bundle names for a list of scopes, and the scopes with no plain name.
function describeScopes(tool, scopes) {
	var names = [], custom = [];
	(scopes && scopes.length ? scopes : [ '*' ]).forEach(function(s) {
		var b = bundleFor(tool, s);
		if (!b)
			custom.push(s);
		else if (names.indexOf(b.name) < 0)
			names.push(b.name);
	});
	return { names: names, custom: custom };
}

function limitNodes(tool, scopes) {
	var d = describeScopes(tool, scopes);
	var out = [ d.names.join(', ') ];
	if (d.custom.length)
		out = out.filter(Boolean).concat([ _('Custom limit') + ' ', E('code', {}, d.custom.join(' ')) ]);
	return out.filter(Boolean);
}

function isFullControl(r) {
	return r.tool === 'exec' || (r.tool === 'ubus_call' && !readOnlyScope(r.scope));
}

// "turn off Wi-Fi radio 1", "change Wi-Fi settings": the sentence a request card is titled with.
function requestAction(r) {
	var scope = r.scope || '*';
	var radio = /^wireless\.radio(\d+)\.disabled$/.exec(scope);
	if (r.tool === 'uci_apply' && radio) {
		var set = /disabled=(\d)/.exec(r.args || '');
		if (set)
			return (set[1] === '1' ? _('turn off Wi-Fi radio %s') : _('turn on Wi-Fi radio %s')).format(radio[1]);
		return _('turn Wi-Fi radio %s on or off').format(radio[1]);
	}
	var area = AREAS[scope.split('.')[0]];
	if (r.tool === 'uci_apply' && area)
		return _('change the %s').format(area.noun);
	if (r.tool === 'uci_get' && area)
		return _('read the %s').format(area.noun);
	if (r.tool === 'sysupgrade' && scope === 'backup')
		return _('make a backup of the router settings');
	if (r.tool === 'sysupgrade' && bundleFor('sysupgrade', scope))
		return _('check for firmware updates');
	return VERBS[r.tool] || _('use “%s”').format(r.tool);
}

function requestWhy(r, abilityOf) {
	if (r.tool === 'exec')
		return _('It runs with no limits.');
	if (r.tool === 'ubus_call' && !readOnlyScope(r.scope))
		return _('It can call any internal service of the router, with no limits.');
	var b = bundleFor(r.tool, r.scope || '*');
	if (b && (r.scope || '*') !== '*')
		return b.why;
	var a = abilityOf[r.tool];
	return a ? a.sentence : _('It is not on the usual list of abilities.');
}

// ---------------------------------------------------------------- time

function secsUntil(iso) {
	return Math.round((Date.parse(iso) - Date.now()) / 1000);
}

function span(s) {
	s = Math.max(0, s);
	if (s < 90)
		return _('%d s').format(s);
	var m = Math.round(s / 60);
	if (m < 60)
		return _('%d min').format(m);
	var h = Math.floor(m / 60), mm = m % 60;
	if (h < 24)
		return mm ? _('%d h %d min').format(h, mm) : _('%d h').format(h);
	return _('%d d').format(Math.round(h / 24));
}

function hhmm(d) {
	return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function untilWhen(iso) {
	var d = new Date(iso);
	if (d.toDateString() === new Date().toDateString())
		return _('until %s today').format(hhmm(d));
	return _('until %s %s').format(d.toLocaleDateString([], { weekday: 'short' }), hhmm(d));
}

// Each phrase is rewritten once a second without redrawing the card, so a selection the owner is
// making is not lost. A time more than a day away is an absolute time, not a long countdown.
var PHRASES = {
	onfor: function(iso) {
		var s = secsUntil(iso);
		return s > 86400 ? _('On %s').format(untilWhen(iso)) : (s <= 0 ? _('Ended') : _('On for %s').format(span(s)));
	},
	more: function(iso) {
		var s = secsUntil(iso);
		return s > 86400 ? untilWhen(iso) : _('for %s more').format(span(s));
	},
	left: function(iso) {
		var s = secsUntil(iso);
		return s > 86400 ? untilWhen(iso) : _('%s left').format(span(s));
	},
	ago: function(iso) { return _('%s ago').format(span(-secsUntil(iso))); },
	waiting: function(iso) { return _('waiting %s').format(span(-secsUntil(iso))); },
	closes: function(iso) { return secsUntil(iso) <= 0 ? _('closing now') : _('closes in %s').format(span(secsUntil(iso))); },
	count: function(iso) { return span(secsUntil(iso)); }
};

// The tooltip is the absolute local time: when it ends, or when it happened.
function clock(kind, iso) {
	var past = kind === 'ago' || kind === 'waiting';
	return E('span', { 'data-clock': kind, 'data-ts': iso, 'title': past ? new Date(iso).toLocaleString() : untilWhen(iso) },
		PHRASES[kind](iso));
}

function tick(root) {
	if (!root.querySelectorAll)
		return;
	root.querySelectorAll('[data-clock]').forEach(function(n) {
		n.textContent = PHRASES[n.getAttribute('data-clock')](n.getAttribute('data-ts'));
	});
}

function dayLabel(d) {
	var days = Math.round((new Date(new Date().toDateString()) - new Date(d.toDateString())) / 86400000);
	if (days === 0)
		return _('Today');
	if (days === 1)
		return _('Yesterday');
	return d.toLocaleDateString([], { weekday: 'short', day: 'numeric', month: 'short' });
}

// ---------------------------------------------------------------- small pieces

// The ubus reply is an object that carries `error` when the plugin refused. A refusal is shown to
// the user; a transport failure (rpcd said no, the plugin is missing) rejects.
function check(res) {
	if (res && res.error) {
		var e = new Error(res.error);
		e.code = res.code;
		throw e;
	}
	return res;
}

// One banner at a time: a new message replaces the last one this page showed.
var lastNote = null;
function notify(message, kind) {
	if (lastNote && lastNote.parentNode)
		lastNote.parentNode.removeChild(lastNote);
	lastNote = ui.addNotification(null, E('p', {}, message), kind);
}

function fail(err) {
	notify(_('Couldn’t save: %s. Nothing was changed.').format(String((err && err.message) || err)), 'danger');
}

function badge(risk) {
	if (!RISK[risk])
		return '';
	return E('span', { 'class': 'mcp-risk mcp-risk-' + risk }, RISK[risk]);
}

function btn(kind, act, label, click, extra) {
	var a = { 'class': 'cbi-button' + (kind ? ' cbi-button-' + kind : ''), 'type': 'button', 'data-act': act, 'click': click };
	Object.keys(extra || {}).forEach(function(k) { a[k] = extra[k]; });
	return E('button', a, label);
}

function selectOf(options, value, change, attrs) {
	var a = { 'class': 'cbi-input-select' };
	Object.keys(attrs || {}).forEach(function(k) { a[k] = attrs[k]; });
	var sel = E('select', a, options.map(function(o) {
		return E('option', { 'value': o[0] }, o[1]);
	}));
	sel.value = value;
	if (change)
		sel.addEventListener('change', function() { change(sel.value); });
	return sel;
}

// A cbi-value row: label left, control right, optional helper line under the control.
function row(title, control, descr, forId) {
	var field = [].concat(control);
	if (descr)
		field.push(E('div', { 'class': 'cbi-value-description' }, descr));
	return E('div', { 'class': 'cbi-value' }, [
		E('label', { 'class': 'cbi-value-title', 'for': forId || null }, title),
		E('div', { 'class': 'cbi-value-field' }, field)
	]);
}

function section(title, descr, children) {
	var c = [];
	if (title)
		c.push(E('h3', {}, title));
	if (descr)
		c.push(E('div', { 'class': 'cbi-section-descr' }, descr));
	return E('div', { 'class': 'cbi-section' }, c.concat(children || []));
}

function notice(kind, text, extra) {
	return E('div', { 'class': 'alert-message ' + kind, 'role': kind === 'error' ? 'alert' : 'status' }, [ E('p', {}, text) ].concat(extra || []));
}

function table(cols, bodyRows) {
	var head = E('tr', { 'class': 'tr table-titles' }, cols.map(function(c) {
		return E('th', { 'class': 'th' + (c[1] ? ' ' + c[1] : '') }, c[0]);
	}));
	return E('table', { 'class': 'table mcp-table' }, [ head ].concat(bodyRows));
}

function cell(title, cls, children) {
	return E('td', { 'class': 'td' + (cls ? ' ' + cls : ''), 'data-title': title }, children);
}

function joinAnd(items) {
	if (items.length < 2)
		return items.join('');
	return _('%s and %s').format(items.slice(0, -1).join(', '), items[items.length - 1]);
}

// ---------------------------------------------------------------- state

function toolIndex(groups) {
	var by = {};
	(groups || []).forEach(function(g) {
		g.tools.forEach(function(t) { by[t.name] = t; });
	});
	return by;
}

function knownClients(st) {
	var seen = {}, out = [];
	var add = function(n) { if (n && !seen[n] && n.charAt(0) !== '<') { seen[n] = true; out.push(n); } };
	(st.clients || []).forEach(function(c) { add(c.name); });
	(st.policies || []).forEach(function(p) { add(p.client); });
	(st.requests || []).forEach(function(r) { add(r.client); });
	(st.audit || []).forEach(function(a) { add(a.client); });
	return out.sort();
}

function openRequests(st) {
	return (st.requests || []).filter(function(r) { return r.state === 'open'; })
		.sort(function(a, b) { return Date.parse(a.created) - Date.parse(b.created); });
}

function policyKey(p) {
	return [ p.tools.join(','), p.scopes.join(' '), p.expires || '' ].join('|');
}

// ---------------------------------------------------------------- the page

return view.extend({
	load: function() {
		return Promise.all([
			callStatus(AUDIT_LINES), callTools(), callSettings(),
			callAccess('ubus', 'openwrt-mcp', 'decide').catch(function() { return true; })
		]).then(function(r) {
			return { st: check(r[0]), tools: check(r[1]), settings: check(r[2]), writable: r[3] !== false };
		}).catch(function(e) {
			return { error: String((e && e.message) || e) };
		});
	},

	render: function(data) {
		var ui_ = { tab: savedTab() || 'overview', client: null, req: {}, answered: [], adv: false, editing: null, choice: null, duration: '1h',
			pa: { box: false, name: '', duration: '1h' }, filter: { client: '', kind: '', text: '' }, shown: ACTIVITY_PAGE,
			raw: {}, sig: {}, draft: null, settingsDraft: null };
		if (!data.tools) {
			data.st = { clients: [], policies: [], requests: [], audit: [], pending: [], permit_all: [] };
			data.tools = { groups: [] };
			data.settings = { channels: [], request_wait: 0, request_ttl: 0, wait_max: 600, ttl_min: 60, ttl_max: 86400 };
			ui_.error = data.error;
		}
		var panes = {
			overview: E('div'), permissions: E('div'), activity: E('div'), settings: E('div'), clients: E('div')
		};
		var allTitles = [ [ 'overview', _('Overview') ], [ 'permissions', _('Permissions') ],
			[ 'activity', _('Activity') ], [ 'settings', _('Settings') ], [ 'clients', _('Clients') ] ];
		var tabbar = E('ul', { 'class': 'cbi-tabmenu' });
		var bannerBox = E('div', { 'class': 'mcp-sticky', 'id': 'openwrt-mcp-banner' });
		var errorBox = E('div', { 'id': 'openwrt-mcp-error' });
		var root = E('div', { 'id': 'openwrt-mcp-page', 'class': 'mcp' }, [
			E('style', {}, CSS),
			E('div', { 'class': 'cbi-section-descr' },
				_('Lets AI assistants look at this router and, if you allow it, change it. You decide what each one may do and for how long.')),
			bannerBox, errorBox, tabbar ]);
		allTitles.forEach(function(t) { root.appendChild(panes[t[0]]); });

		var byName = {}, abilityOf = {}, groups = [];

		function indexTools() {
			byName = toolIndex(data.tools.groups);
			abilityOf = {};
			var placed = {};
			groups = ABILITY_GROUPS.map(function(g) {
				return { id: g.id, title: g.title, items: g.items.map(function(a) {
					a.tools.forEach(function(t) { placed[t] = true; abilityOf[t] = a; });
					return a;
				}) };
			});
			var other = [];
			Object.keys(byName).forEach(function(n) {
				if (placed[n])
					return;
				var t = byName[n], a = ab(t.title || n, '', [ n ], t.ungated ? 'none' : (RISK_OF_BADGE[t.badge] || 'change'));
				abilityOf[n] = a;
				other.push(a);
			});
			if (other.length)
				groups.push({ id: 'other', title: _('Other'), items: other });
		}

		function isUngated(tool) {
			return byName[tool] ? !!byName[tool].ungated : !!UNGATED[tool];
		}

		function channelOn(name) {
			return ((data.settings.channels || []).filter(function(c) { return c.name === name; })[0] || {}).enabled === true;
		}

		function savedTab() {
			try { return window.sessionStorage.getItem(TAB_KEY); } catch (e) { return null; }
		}

		function goTab(name) {
			ui_.tab = name;
			try { window.sessionStorage.setItem(TAB_KEY, name); } catch (e) { /* storage blocked: the tab is just not remembered */ }
			showTab();
		}

		function showTab() {
			var titles = allTitles.filter(function(t) { return t[0] !== 'clients' || channelOn('pair'); });
			if (!titles.some(function(t) { return t[0] === ui_.tab; }))
				ui_.tab = 'overview';
			var waiting = openRequests(data.st).length;
			tabbar.replaceChildren.apply(tabbar, titles.map(function(t) {
				var label = [ t[1] ];
				if (t[0] === 'overview' && waiting)
					label.push(' ', E('span', { 'class': 'label' }, _('%d waiting').format(waiting)));
				return E('li', { 'class': 'cbi-tab' + (t[0] === ui_.tab ? '' : '-disabled') }, [
					E('a', { 'href': '#', 'click': function(ev) { ev.preventDefault(); goTab(t[0]); } }, label)
				]);
			}));
			allTitles.forEach(function(t) { panes[t[0]].style.display = t[0] === ui_.tab ? '' : 'none'; });
		}

		function refresh() {
			return Promise.all([ callStatus(AUDIT_LINES), callSettings() ]).then(function(r) {
				data.st = check(r[0]);
				data.settings = check(r[1]);
				ui_.error = null;
				draw();
			}).catch(function(e) {
				ui_.error = String((e && e.message) || e);
				drawError();
			});
		}

		// An owner action and what follows it: the page re-reads and shows what is now true.
		function run(promise, done) {
			return promise.then(check).then(function(res) {
				if (done)
					done(res);
				return refresh();
			}).catch(function(e) {
				fail(e);
				return refresh();
			});
		}

		function confirmShell(message, retry) {
			var ack = E('input', { 'type': 'checkbox', 'id': 'openwrt-mcp-shell-ack' });
			var go = btn('negative important', 'confirm-shell', _('Allow'), function() { ui.hideModal(); retry(); }, { 'disabled': '' });
			ack.addEventListener('change', function() { go.disabled = !ack.checked; });
			ui.showModal(_('Full control'), [
				E('p', {}, _('A root command has no limits. It can change or break anything on the router, read every password and key, and is not undone automatically. Only allow it if you know what it does.')),
				E('p', {}, message),
				E('p', {}, E('label', {}, [ ack, ' ', _('I understand this gives a root shell and can’t be undone automatically.') ])),
				E('div', { 'class': 'right' }, [ btn('', 'cancel-shell', _('Cancel'), ui.hideModal), ' ', go ])
			]);
		}

		function clientPolicies(client) {
			return (data.st.policies || []).filter(function(p) { return p.client === client; });
		}

		function livePolicies(client) {
			return clientPolicies(client).filter(function(p) { return p.enabled && !p.expired; });
		}

		function permitAllOf(client) {
			return (data.st.permit_all || []).filter(function(a) { return a.client === client; })[0] || null;
		}

		// One line per (client, tool): all live grants of the tool merged. The longest time wins and
		// no expiry beats any date; the scopes are the union, with `*` swallowing the rest.
		function mergedGrant(client, tool) {
			var blocks = livePolicies(client).filter(function(p) { return p.tools.indexOf(tool) >= 0 || p.tools.indexOf('*') >= 0; });
			if (!blocks.length)
				return null;
			var never = blocks.some(function(p) { return !p.expires; });
			var latest = blocks.reduce(function(m, p) { return p.expires && (!m || Date.parse(p.expires) > Date.parse(m)) ? p.expires : m; }, null);
			var scopes = [];
			blocks.forEach(function(p) { (p.scopes && p.scopes.length ? p.scopes : [ '*' ]).forEach(function(s) { if (scopes.indexOf(s) < 0) scopes.push(s); }); });
			if (scopes.indexOf('*') >= 0)
				scopes = [ '*' ];
			return { expires: never ? '' : latest, scopes: scopes, blocks: blocks.length };
		}

		// on / partly / off / always for one ability, with when the whole ability stops.
		function abilityState(client, a) {
			var need = a.tools.filter(function(t) { return !isUngated(t); });
			if (!need.length)
				return { state: 'always' };
			var merged = need.map(function(t) { return mergedGrant(client, t); }).filter(Boolean);
			if (!merged.length)
				return { state: 'off' };
			if (merged.length < need.length)
				return { state: 'partly' };
			var never = merged.every(function(m) { return !m.expires; });
			var first = merged.filter(function(m) { return m.expires; }).sort(function(x, y) { return Date.parse(x.expires) - Date.parse(y.expires); })[0];
			var scopes = [];
			merged.forEach(function(m) { m.scopes.forEach(function(s) { if (scopes.indexOf(s) < 0) scopes.push(s); }); });
			return { state: 'on', expires: never ? '' : first.expires, scopes: scopes };
		}

		// ---- requests

		function decide(r, decision, breadth, duration, confirm) {
			var before = clientPolicies(r.client).map(policyKey);
			return callDecide(r.id, decision, breadth, duration, confirm || false).then(check).then(function() {
				var rec = { id: r.id, client: r.client, decision: decision, duration: duration, action: requestAction(r), added: [], at: Date.now() };
				ui_.answered.push(rec);
				return refresh().then(function() {
					rec.added = clientPolicies(r.client).map(policyKey).filter(function(k) { return before.indexOf(k) < 0; });
					drawOverview(true);
				});
			}).catch(function(e) {
				if (e.code === 'needs_confirm')
					return confirmShell(e.message, function() { decide(r, decision, breadth, duration, true); });
				fail(e);
				return refresh();
			});
		}

		function undo(rec) {
			var idx = clientPolicies(rec.client).filter(function(p) { return rec.added.indexOf(policyKey(p)) >= 0; })
				.map(function(p) { return p.index; }).sort(function(a, b) { return b - a; });
			ui_.answered = ui_.answered.filter(function(x) { return x !== rec; });
			return idx.reduce(function(p, i) {
				return p.then(function() { return callRevoke(rec.client, i, false).then(check); });
			}, Promise.resolve()).then(refresh).catch(function(e) { fail(e); return refresh(); });
		}

		function reqState(r) {
			return ui_.req[r.id] = ui_.req[r.id] || { breadth: 'exact', duration: '1h', menu: false, details: false, confirm: false, ack: false };
		}

		function redrawRequests() {
			drawOverview(true);
		}

		function breadthChoices(r) {
			var area = AREAS[(r.scope || '').split('.')[0]];
			var out = [ [ 'exact', _('Only this change'), _('“%s” won’t ask again.').format(requestAction(r)) ] ];
			if (r.family && r.family !== r.scope)
				out.push([ 'family', area ? _('This and similar %s changes').format(area.short) : _('This and similar changes'),
					area ? _('Any %s, for example names and passwords.').format(area.noun) : _('Every request for this ability in this area.') ]);
			else if (r.scope && r.scope !== '*')
				out.push([ 'tool', _('This ability, any limit'), _('No limit inside “%s”.').format(requestAction(r)) ]);
			out.push([ 'operator', _('Everything an Operator can do'), _('Change settings, software, VPN and services.') ]);
			return out;
		}

		function requestCard(r) {
			var full = isFullControl(r), name = displayName(r.client);
			var tool = byName[r.tool] || {};
			var st = reqState(r);
			var risk = full ? 'full' : (RISK_OF_BADGE[tool.badge] || (abilityOf[r.tool] || {}).risk || 'change');
			var why = [ _('Why it matters: %s').format(requestWhy(r, abilityOf)), ' ', badge(risk) ];
			if ((tool.notes || []).indexOf('rollback') >= 0)
				why.push(' ', E('em', {}, _('Undoes itself after 60 s unless confirmed.')));
			var kids = [
				E('div', { 'class': 'mcp-head' }, [
					E('h4', {}, _('%s wants to %s').format(name, requestAction(r))),
					E('span', { 'class': 'mcp-dim' }, [ clock('waiting', r.created), ' · ', clock('closes', r.expires) ])
				]),
				E('div', { 'class': 'mcp-line' }, why)
			];
			if (full)
				kids.push(E('p', {}, E('strong', {}, _('A root command has no limits. It can change or break anything on the router, read every password and key, and is not undone automatically. Only allow it if you know what it does.'))));

			var actions = E('div', { 'class': 'mcp-row mcp-actions' });
			if (data.writable) {
				var deny = btn('negative', 'deny', _('Deny'), function() { decide(r, 'deny'); }, { 'class': 'cbi-button cbi-button-negative mcp-sep' });
				if (full) {
					actions.appendChild(btn('negative', 'deny', _('Deny'), function() { decide(r, 'deny'); }));
					actions.appendChild(btn('', 'allow-full', _('Allow for 15 minutes…'), function() {
						st.confirm = true;
						redrawRequests();
					}, { 'class': 'cbi-button mcp-sep' }));
				} else {
					actions.appendChild(btn('action', 'allow-once', _('Allow for 15 minutes'), function() { decide(r, 'allow', 'exact', ONCE); }));
					actions.appendChild(btn('', 'allow', _('Allow for %s').format(DURATION_WORDS[st.duration]), function() {
						decide(r, 'allow', st.breadth, st.duration);
					}));
					actions.appendChild(btn('', 'menu', '▾', function() {
						st.menu = !st.menu;
						redrawRequests();
					}, { 'aria-expanded': st.menu ? 'true' : 'false', 'aria-label': _('More ways to allow') }));
					actions.appendChild(deny);
				}
			}
			actions.appendChild(btn('', 'details', st.details ? _('Hide details') : _('Show details'), function() {
				st.details = !st.details;
				redrawRequests();
			}));
			kids.push(actions);

			if (data.writable && !full && st.menu) {
				var name_ = 'mcp-breadth-' + r.id;
				kids.push(E('div', { 'class': 'mcp-menu', 'role': 'group', 'aria-label': _('How wide the permission is') }, breadthChoices(r).map(function(c) {
					var radio = E('input', { 'type': 'radio', 'name': name_, 'value': c[0], 'data-breadth': c[0],
						'checked': st.breadth === c[0] ? '' : null });
					radio.checked = st.breadth === c[0];
					radio.addEventListener('change', function() { st.breadth = c[0]; redrawRequests(); });
					return E('label', {}, [ radio, ' ', c[1], E('span', { 'class': 'mcp-sub' }, c[2]) ]);
				}).concat([
					E('div', { 'class': 'mcp-row' }, [
						E('label', { 'for': 'mcp-dur-' + r.id }, _('For')),
						selectOf(DURATIONS.slice(0, 3), st.duration, function(v) { st.duration = v; redrawRequests(); }, { 'id': 'mcp-dur-' + r.id })
					])
				])));
			}
			if (data.writable && full && st.confirm) {
				var ack = E('input', { 'type': 'checkbox', 'id': 'mcp-ack-' + r.id });
				ack.checked = st.ack;
				var go = btn('negative important', 'confirm-full', _('Allow for 15 minutes'), function() {
					decide(r, 'allow', 'exact', ONCE, true);
				});
				go.disabled = !st.ack;
				ack.addEventListener('change', function() { st.ack = ack.checked; go.disabled = !ack.checked; });
				kids.push(E('div', { 'class': 'mcp-menu' }, [
					E('label', {}, [ ack, ' ', _('I understand this gives %s a root shell for 15 minutes and can’t be undone automatically.').format(name) ]),
					E('div', { 'class': 'mcp-row' }, [ go, btn('', 'cancel-full', _('Cancel'), function() {
						st.confirm = false; st.ack = false;
						redrawRequests();
					}) ])
				]));
			}
			if (st.details)
				kids.push(E('div', { 'class': 'mcp-line mcp-raw' }, [
					E('code', {}, [ _('Tool'), ' ', r.tool ].join(' ')),
					E('code', {}, [ _('Limit'), ' ', r.scope || '*' ].join(' ')),
					r.args ? E('code', {}, [ _('Arguments'), ' ', r.args ].join(' ')) : '',
					E('code', {}, [ _('Request'), ' ', r.id ].join(' '))
				]));
			return E('div', { 'class': 'cbi-section-node mcp-card mcp-req ' + (full ? 'mcp-req-full' : 'mcp-req-change'), 'data-request': r.id }, kids);
		}

		function answeredLine(rec) {
			var text = rec.decision === 'allow' ?
				_('Allowed for %s · %s asked to %s').format(DURATION_WORDS[rec.duration] || rec.duration, displayName(rec.client), rec.action) :
				_('Denied · %s asked to %s').format(displayName(rec.client), rec.action);
			var kids = [ E('span', {}, text) ];
			if (rec.decision === 'allow' && rec.added.length && data.writable)
				kids.push(' ', btn('', 'undo', _('Undo'), function() { undo(rec); }));
			return E('div', { 'class': 'alert-message notice mcp-card', 'role': 'status', 'data-answered': rec.id }, kids);
		}

		function expiredLine(r) {
			return E('div', { 'class': 'alert-message notice mcp-card', 'role': 'status', 'data-expired': r.id },
				_('%s asked to %s. Nobody answered in time, so it was refused.').format(displayName(r.client), requestAction(r)));
		}

		function permitAllBanner(a) {
			var who = displayName(a.client);
			var lead = a.expires ?
				[ _('Permit all is on. %s can do anything on this router ').format(who), clock('more', a.expires), ' (', untilWhen(a.expires), '). ' ] :
				[ _('Permit all is on. %s can do anything on this router with no end. ').format(who) ];
			if (data.writable)
				lead.push(btn('negative', 'end-permit-all', _('End now'), function() { endPermitAll(a.client); }));
			return E('div', { 'class': 'alert-message error', 'role': 'alert', 'data-permit-all': a.client }, [ E('strong', {}, lead) ]);
		}

		function endPermitAll(client) {
			return run(callEndPermitAll(client));
		}

		function drawBanner() {
			var sig = JSON.stringify([ data.st.permit_all, data.writable ]);
			if (sig === ui_.sig.banner)
				return;
			ui_.sig.banner = sig;
			bannerBox.replaceChildren.apply(bannerBox, (data.st.permit_all || []).map(permitAllBanner));
		}

		// Requests asked a while ago and never answered: shown as one refused line for ten minutes.
		function expiredRecently() {
			var now = Date.now();
			return (data.st.requests || []).filter(function(r) {
				return r.state === 'expired' && now - Date.parse(r.expires) < 10 * 60e3 && !ui_.answered.some(function(x) { return x.id === r.id; });
			}).slice(-3);
		}

		// ---- overview

		function lastSeen() {
			var seen = {};
			(data.st.audit || []).forEach(function(a) { seen[a.client] = a.time; });
			return seen;
		}

		// An ability granted only for what reads (a read-only ubus list, the update checks of sysupgrade)
		// is "Looks only" on the assistant's card, whatever the ability is called in the list of abilities.
		function effectiveRisk(a, s) {
			if (a.risk === 'look' || a.risk === 'none' || s.state !== 'on')
				return a.risk;
			var tool = a.tools[0];
			var reads = s.scopes.every(function(sc) { return (tool === 'ubus_call' && readOnlyScope(sc)) || (tool === 'sysupgrade' && [ 'list', 'test', 'check' ].indexOf(sc) >= 0); });
			return reads && (tool === 'ubus_call' || tool === 'sysupgrade') ? 'look' : a.risk;
		}

		function summaryOf(client) {
			var on = { look: [], change: [], full: [] }, times = { look: [], change: [], full: [] };
			var areasOf = { look: [], change: [] };
			groups.forEach(function(g) {
				g.items.forEach(function(a) {
					var s = abilityState(client, a);
					if (s.state !== 'on' && s.state !== 'partly')
						return;
					var risk = effectiveRisk(a, s);
					if (!on[risk])
						return;
					on[risk].push(a);
					if (s.state === 'on')
						times[risk].push(s.expires);
					if (risk === a.risk && areasOf[risk] && areasOf[risk].indexOf(g.title) < 0)
						areasOf[risk].push(g.title);
				});
			});
			function endOf(list) {
				if (!list.length || list.some(function(x) { return !x; }))
					return '';
				return list.sort(function(x, y) { return Date.parse(y) - Date.parse(x); })[0];
			}
			var parts = [];
			if (on.look.length)
				parts.push(E('span', {}, _('Can look at %s. ').format(joinAnd(areasOf.look))));
			if (on.change.length) {
				var e = endOf(times.change);
				parts.push(E('span', {}, e ? [ _('Can change %s ').format(joinAnd(areasOf.change)), clock('more', e), '. ' ] :
					_('Can change %s until you remove it. ').format(joinAnd(areasOf.change))));
			}
			var shell = abilityState(client, abilityOf.exec || ab('', '', [ 'exec' ], 'full'));
			if (shell.state === 'on')
				parts.push(E('span', {}, shell.expires ? [ _('Can run any command as root '), clock('more', shell.expires), '. ' ] :
					_('Can run any command as root until you remove it. ')));
			else
				parts.push(E('span', {}, _('Cannot run commands.')));
			if (!on.look.length && !on.change.length && shell.state !== 'on')
				return { text: [ E('span', {}, _('Can’t do anything yet; it can only ask. ')) ].concat(parts), on: on, times: times };
			return { text: parts, on: on, times: times };
		}

		function riskLine(risk, list, times) {
			if (!list.length)
				return '';
			var names = list.slice(0, 3).map(function(a) { return a.name; });
			var more = list.length > 3 ? _('and %d more').format(list.length - 3) : '';
			var longest = times.some(function(x) { return !x; }) ? '' : times.slice().sort(function(x, y) { return Date.parse(y) - Date.parse(x); })[0];
			var when = !times.length ? '' : (longest ? clock('left', longest) : _('until you remove it'));
			return E('div', { 'class': 'mcp-line' }, [ badge(risk), ' ', names.join(', ') + (more ? ' ' + more : ''), when ? ' · ' : '', when ].filter(function(x) { return x !== ''; }));
		}

		function removeAccess(client) {
			ui.showModal(_('Remove access'), [
				E('p', {}, _('Remove all access for %s? It can still connect, but can only ask. This can’t be undone.').format(displayName(client))),
				E('div', { 'class': 'right' }, [
					btn('', 'cancel-remove', _('Cancel'), ui.hideModal), ' ',
					btn('negative', 'confirm-remove', _('Remove access'), function() {
						ui.hideModal();
						run(callRevoke(client, null, true));
					})
				])
			]);
		}

		function assistantCard(c, seen, tokens) {
			var mine = clientPolicies(c);
			var live = livePolicies(c);
			var paused = mine.length > 0 && !mine.some(function(p) { return p.enabled && !p.expired; }) && mine.some(function(p) { return !p.expired; });
			var waiting = openRequests(data.st).filter(function(r) { return r.client === c; }).length;
			var sum = summaryOf(c);
			var status = paused ? _('Paused') : (seen[c] || waiting ? _('Active') : _('Never connected'));
			var conn = [ tokens[c] ? _('Connects over HTTP') : _('Connects over SSH') ];
			if (seen[c])
				conn.push(' · ', _('last seen '), clock('ago', seen[c]));
			if (waiting)
				conn.push(' · ', _('%d requests waiting').format(waiting));
			var kids = [
				E('div', { 'class': 'mcp-head' }, [
					E('h4', {}, [ displayName(c), ' ', E('code', {}, c) ]),
					E('span', { 'class': 'label' }, status)
				]),
				E('div', { 'class': 'mcp-line mcp-dim' }, conn),
				E('div', { 'class': 'mcp-line' }, paused ?
					_('Paused: it keeps %d permissions but can’t use them until you resume.').format(live.length || mine.length) : sum.text)
			];
			if (!paused)
				kids.push(riskLine('look', sum.on.look, sum.times.look), riskLine('change', sum.on.change, sum.times.change),
					riskLine('full', sum.on.full, sum.times.full));
			var acts = E('div', { 'class': 'mcp-row mcp-actions' });
			if (data.writable)
				acts.appendChild(btn('action', 'change-permissions', _('Change permissions'), function() { ui_.client = c; goTab('permissions'); drawPermissions(); }));
			// TODO: Pause all access / Resume have no rpcd method yet; a grant can only be removed.
			if (data.writable && mine.length)
				acts.appendChild(btn('negative', 'remove-access', _('Remove access'), function() { removeAccess(c); }, { 'class': 'cbi-button cbi-button-negative mcp-sep' }));
			kids.push(acts);
			return E('div', { 'class': 'cbi-section-node mcp-card', 'data-assistant': c }, kids.filter(function(k) { return k !== ''; }));
		}

		// Redrawn when the facts change or the owner opens a menu on a card; a poll that finds nothing new
		// leaves the cards alone, so a half-made choice is not lost.
		// A redraw swaps whole panes; put the page back where the owner was, so a tap does not jump to the top.
		function keepScroll(fn) {
			var y = window.pageYOffset;
			fn();
			if (typeof window.scrollTo === 'function' && window.pageYOffset !== y)
				window.scrollTo(0, y);
		}

		function drawOverview(force) {
			keepScroll(function() { drawOverviewNow(force); });
		}

		function drawOverviewNow(force) {
			var st = data.st, seen = lastSeen(), tokens = {};
			ui_.answered = ui_.answered.filter(function(x) { return Date.now() - x.at < 10 * 60e3; }).slice(-5);
			var open = openRequests(st), pend = st.pending || [], recent = expiredRecently();
			var sig = JSON.stringify([ open, recent, pend, st.clients, st.policies, seen, st.permit_all, data.writable, ui_.answered, ui_.error ]);
			if (!force && sig === ui_.sig.overview)
				return;
			ui_.sig.overview = sig;
			showTab();
			(st.clients || []).forEach(function(c) { tokens[c.name] = true; });
			var nodes = [];
			if (open.length || ui_.answered.length || recent.length || pend.length) {
				var waitKids = open.map(requestCard).concat(ui_.answered.map(answeredLine), recent.map(expiredLine));
				pend.forEach(function(p) {
					waitKids.push(E('div', { 'class': 'alert-message warning mcp-card' }, [
						E('span', {}, _('A change to %s by %s is waiting for confirmation. It undoes itself in ').format(p.configs.join(', '), displayName(p.client))),
						clock('count', p.deadline), '.'
					]));
				});
				nodes.push(section(_('Waiting for you (%d)').format(open.length),
					_('An assistant asked to do something it isn’t allowed to do yet. Nothing happens until you answer.'), waitKids));
			}
			var clients = knownClients(st);
			var cards = clients.map(function(c) { return assistantCard(c, seen, tokens); });
			nodes.push(section(_('Assistants (%d)').format(clients.length),
				_('Each assistant can only do what you allowed. Pausing keeps its permissions for later; removing deletes them.'),
				clients.length ? cards : [ E('div', { 'class': 'mcp-card' }, [
					E('h4', {}, _('No assistants yet')),
					E('p', {}, _('No assistant has connected to this router. Follow your assistant’s setup guide; it shows up here after its first connection. Nothing is waiting for you.'))
				]) ]));
			if (data.writable === false)
				nodes.unshift(notice('notice', _('You can see this page but not change anything. Ask the router’s administrator if you need to change permissions.')));
			panes.overview.replaceChildren.apply(panes.overview, nodes);
		}

		// ---- permissions

		function granted(client) {
			var out = {};
			livePolicies(client).forEach(function(p) { p.tools.forEach(function(t) { out[t] = true; }); });
			return out;
		}

		// Which of the three big choices the current grants amount to, by the set of tools alone.
		function presetTools(choice) {
			var look = Object.keys(byName).filter(function(t) { return byName[t].readonly && !isUngated(t); });
			if (choice === 'look')
				return look;
			return choice === 'change' ? look.concat(OPERATOR_EXTRA.filter(function(t) { return byName[t]; })) : [];
		}

		function currentChoice(client) {
			var g = Object.keys(granted(client)).filter(function(t) { return !isUngated(t); }).sort().join(',');
			if (!g)
				return 'nothing';
			if (g === presetTools('look').sort().join(','))
				return 'look';
			if (g === presetTools('change').sort().join(','))
				return 'change';
			return null;
		}

		// The switches are a draft until Apply: a preset fills them in so the owner sees what it means,
		// a hand edit changes one and the preset no longer describes the page.
		function gatedTools(a) {
			return a.tools.filter(function(t) { return !isUngated(t); });
		}

		function presetDraft(client, choice) {
			var set = presetTools(choice), on = {};
			groups.forEach(function(g) {
				g.items.forEach(function(a) {
					var need = gatedTools(a);
					if (need.length)
						on[a.id] = need.every(function(t) { return set.indexOf(t) >= 0; });
				});
			});
			return { client: client, preset: choice, on: on, manual: false, confirmed: false };
		}

		function handDraft(client) {
			if (ui_.draft && ui_.draft.client === client)
				return ui_.draft;
			var on = {};
			groups.forEach(function(g) {
				g.items.forEach(function(a) {
					if (gatedTools(a).length)
						on[a.id] = abilityState(client, a).state === 'on';
				});
			});
			return { client: client, preset: null, on: on, manual: true, confirmed: false };
		}

		function setSwitch(client, a, on, confirmed) {
			var d = handDraft(client);
			if (confirmed)
				d.confirmed = true;
			d.on[a.id] = on;
			d.manual = true;
			ui_.draft = d;
			ui_.choice = null;
			drawPermissions();
		}

		// Writes what the draft says: only the abilities that differ from what the assistant has now.
		function applyDraft(client, d, confirm) {
			if (!d.manual && d.preset)
				return applyChoice(client, d.preset, ui_.duration);
			var steps = [];
			groups.forEach(function(g) {
				g.items.forEach(function(a) {
					var need = gatedTools(a), want = d.on[a.id], state = abilityState(client, a).state;
					if (!need.length || want === undefined)
						return;
					if (!want && state !== 'off')
						steps.push(function() { return callRevokeTools(client, need); });
					else if (want && state !== 'on')
						need.filter(function(t) { return !mergedGrant(client, t); }).forEach(function(t) {
							steps.push(function() { return callGrant(client, t, '*', ui_.duration, confirm || d.confirmed); });
						});
				});
			});
			return steps.reduce(function(p, f) {
				return p.then(function() { return f().then(check); });
			}, Promise.resolve()).then(function() {
				ui_.draft = null;
				ui_.choice = null;
				return refresh();
			}).catch(function(e) {
				if (e.code === 'needs_confirm')
					return refresh().then(function() { confirmShell(e.message, function() { applyDraft(client, d, true); }); });
				fail(e);
				return refresh();
			});
		}

		// "Look only" and "Look and change" replace what the assistant had, so a smaller choice really
		// takes the extra abilities away; a preset on its own would only add.
		function applyChoice(client, choice, duration) {
			var steps = [];
			if (clientPolicies(client).length)
				steps.push(function() { return callRevoke(client, null, true); });
			if (choice !== 'nothing')
				steps.push(function() { return callGrantPreset(client, choice === 'look' ? 'readonly' : 'operator', duration); });
			return run(steps.reduce(function(p, f) {
				return p.then(function() { return f().then(check); });
			}, Promise.resolve()), function() { ui_.draft = null; ui_.choice = null; });
		}

		// Ticking a switch only changes the draft; the root command asks first, and a cancel leaves the box unticked.
		function switchAbility(client, a, box) {
			var on = box.checked;
			if (on && a.risk === 'full' && a.tools.indexOf('exec') >= 0) {
				box.checked = false;
				return confirmShell(_('Turning this on gives %s no limits at all.').format(displayName(client)), function() { setSwitch(client, a, true, true); });
			}
			setSwitch(client, a, on);
		}

		function abilityRow(client, a) {
			var s = abilityState(client, a);
			var status;
			if (s.state === 'always')
				status = _('Always on');
			else if (s.state === 'off')
				status = _('Off');
			else if (s.state === 'partly')
				status = _('Partly on');
			else
				status = s.expires ? clock('onfor', s.expires) : _('On until you remove it');
			var d = ui_.draft && ui_.draft.client === client ? ui_.draft : null;
			var drafted = d && d.on[a.id] !== undefined, wants = drafted ? d.on[a.id] : s.state === 'on';
			var statusKids = [ status ];
			if (drafted && wants !== (s.state === 'on'))
				statusKids.push(E('div', { 'class': 'mcp-line mcp-pending' }, wants ? _('Turns on when you press Apply') : _('Turns off when you press Apply')));
			if (s.state === 'on' && !(s.scopes.length === 1 && s.scopes[0] === '*')) {
				var tool = a.tools.filter(function(t) { return !isUngated(t); })[0];
				statusKids.push(E('div', { 'class': 'mcp-line mcp-dim' }, [ _('Limited to: ') ].concat(limitNodes(tool, s.scopes))));
			}
			var control = '';
			if (data.writable && s.state !== 'always') {
				var box = E('input', { 'type': 'checkbox', 'class': 'cbi-input-checkbox', 'data-ability': a.id, 'id': 'mcp-ab-' + a.id });
				box.checked = wants;
				box.indeterminate = !drafted && s.state === 'partly';
				box.addEventListener('change', function() { switchAbility(client, a, box); });
				control = E('label', {}, [ box, ' ', _('Allowed') ]);
			}
			return E('tr', { 'class': 'tr', 'data-ability-row': a.id }, [
				cell(_('Ability'), '', [ E('strong', {}, a.name), ' ', badge(a.risk), E('div', { 'class': 'mcp-line mcp-dim' }, a.sentence) ]),
				cell(_('Status'), 'mcp-status', statusKids),
				cell(_('Allowed'), 'mcp-allowed', control)
			]);
		}

		function drawAdvanced(client) {
			var rows = [];
			groups.forEach(function(g) {
				g.items.forEach(function(a) {
					a.tools.forEach(function(t) {
						var m = isUngated(t) ? null : mergedGrant(client, t);
						var tool = byName[t] || {};
						var limit = isUngated(t) ? _('Always on') : (m ? limitNodes(t, m.scopes) : _('Off'));
						var detail = m && !(m.scopes.length === 1 && m.scopes[0] === '*') ?
							E('details', {}, [ E('summary', {}, _('Show details')), E('code', {}, m.scopes.join(' ')) ]) : '';
						var time = !m ? '' : (m.expires ? clock('left', m.expires) : _('until you remove it'));
						var acts = [];
						if (data.writable && !isUngated(t)) {
							if (m) {
								acts.push(btn('', 'adv-edit', _('Edit'), function() { ui_.editing = t; drawPermissions(); }), ' ',
									btn('negative', 'adv-revoke', _('Revoke'), function() { run(callRevokeTools(client, [ t ])); }));
							} else
								acts.push(btn('action', 'adv-grant', _('Grant…'), function() { ui_.editing = t; drawPermissions(); }));
						}
						rows.push(E('tr', { 'class': 'tr', 'data-tool-row': t }, [
							cell(_('Tool'), '', [ E('strong', {}, tool.title || a.name), ' ', isUngated(t) ? '' : badge(RISK_OF_BADGE[tool.badge] || a.risk), E('div', { 'class': 'mcp-line' }, E('code', {}, t)) ]),
							cell(_('Limited to'), '', [].concat(limit, detail ? [ detail ] : [])),
							cell(_('Time left'), 'mcp-status', [ time, m && m.blocks > 1 ? E('div', { 'class': 'mcp-line mcp-dim' }, _('%d grants merged').format(m.blocks)) : '' ]),
							cell(_('Actions'), 'mcp-actions-col', acts)
						]));
						if (ui_.editing === t)
							rows.push(editRow(client, t, m));
					});
				});
			});
			return table([ [ _('Tool') ], [ _('Limited to') ], [ _('Time left'), 'mcp-status' ], [ _('Actions'), 'mcp-actions-col' ] ], rows);
		}

		function editRow(client, tool, m) {
			var uci = [ 'uci_get', 'uci_apply' ].indexOf(tool) >= 0;
			// A tool with nothing to limit by is on or off: a limit on it would never match.
			var unscoped = !!(byName[tool] && byName[tool].unscoped);
			var opts = [ [ '*', _('Everything this tool can touch') ] ];
			if (uci)
				Object.keys(AREAS).forEach(function(k) { opts.push([ k + '.*', AREAS[k].name ]); });
			if (!unscoped)
				opts.push([ '__custom', _('Custom…') ]);
			var cur = unscoped ? '*' : (m && m.scopes.length === 1 && opts.some(function(o) { return o[0] === m.scopes[0]; }) ? m.scopes[0] : (m ? '__custom' : '*'));
			var custom = E('input', { 'class': 'cbi-input-text', 'type': 'text', 'id': 'mcp-edit-custom', 'data-edit': 'custom',
				'value': m && cur === '__custom' ? m.scopes.join(' ') : '', 'aria-label': _('Technical scope') });
			custom.style.display = cur === '__custom' ? '' : 'none';
			var scope = selectOf(opts, cur, function(v) { custom.style.display = v === '__custom' ? '' : 'none'; }, { 'id': 'mcp-edit-scope' });
			var dur = selectOf(DURATIONS, ui_.duration, null, { 'id': 'mcp-edit-dur' });
			var save = btn('action', 'adv-save', _('Save'), function() {
				var s = scope.value === '__custom' ? custom.value.trim() : scope.value;
				if (scope.value === '__custom') {
					if (!s)
						return notify(_('Type the limit, or choose “Everything this tool can touch”. Nothing was changed.'), 'danger');
					if (/[\s,']/.test(s))
						return notify(_('A limit is one name, with no spaces, commas or quotes. Nothing was changed.'), 'danger');
				}
				var go = function(confirm) {
					// One call replaces the old grant after the new one passed every check, so a
					// refused edit leaves the old grant as it was.
					return callGrant(client, tool, s, dur.value, confirm, !!m).then(check).then(function() {
						ui_.editing = null;
						return refresh();
					}).catch(function(e) {
						if (e.code === 'needs_confirm')
							return confirmShell(e.message, function() { go(true); });
						fail(e);
						return refresh();
					});
				};
				go(false);
			});
			return E('tr', { 'class': 'tr', 'data-edit-row': tool }, [
				E('td', { 'class': 'td', 'colspan': 4 }, [ E('div', { 'class': 'mcp-row' }, [
					E('label', { 'for': 'mcp-edit-scope' }, _('Limited to')), scope, custom,
					E('label', { 'for': 'mcp-edit-dur' }, _('For')), dur,
					save, btn('', 'adv-cancel', _('Cancel'), function() { ui_.editing = null; drawPermissions(); })
				]) ])
			]);
		}

		function permitAllPanel(client) {
			var a = permitAllOf(client), who = displayName(client);
			if (a)
				return E('div', { 'class': 'mcp-danger', 'data-section': 'permit-all' }, [
					E('h3', {}, _('Permit all')),
					E('p', {}, a.expires ? [ _('Permit all is on. %s can do anything on this router ').format(who), clock('more', a.expires), ' (', untilWhen(a.expires), ').' ] :
						_('Permit all is on. %s can do anything on this router with no end.').format(who)),
					E('p', {}, _('When it ends, %s goes back to what it had before.').format(who)),
					data.writable ? btn('negative', 'end-permit-all', _('End now'), function() { endPermitAll(client); }) : ''
				]);
			var dur = selectOf(PERMIT_ALL_DURATIONS, ui_.pa.duration, function(v) { ui_.pa.duration = v; label.textContent = _('Permit all for %s').format(durWord(v)); }, { 'id': 'mcp-pa-dur' });
			var box = E('input', { 'type': 'checkbox', 'id': 'openwrt-mcp-pa-confirm' });
			box.checked = ui_.pa.box;
			var typed = E('input', { 'class': 'cbi-input-text', 'type': 'text', 'size': 20, 'id': 'openwrt-mcp-pa-name',
				'placeholder': client, 'value': ui_.pa.name });
			var hint = E('div', { 'class': 'cbi-value-description' }, '');
			var label = E('span', {}, _('Permit all for %s').format(durWord(ui_.pa.duration)));
			var go = E('button', { 'class': 'cbi-button cbi-button-negative important', 'type': 'button', 'data-act': 'permit-all', 'disabled': '', 'click': function() {
				run(callPermitAll(client, dur.value, true), function() { ui_.pa = { box: false, name: '', duration: dur.value }; });
			} }, label);
			function durWord(v) { return (PERMIT_ALL_DURATIONS.filter(function(d) { return d[0] === v; })[0] || [ v, v ])[1]; }
			function ready() {
				ui_.pa.box = box.checked;
				ui_.pa.name = typed.value;
				var exact = typed.value.trim() === client;
				go.disabled = !(box.checked && exact);
				hint.textContent = typed.value && !exact ? _('That doesn’t match. Type %s exactly.').format(client) : '';
			}
			box.addEventListener('change', ready);
			typed.addEventListener('input', ready);
			if (ui_.pa.box && ui_.pa.name.trim() === client)
				go.disabled = false;
			return E('div', { 'class': 'mcp-danger', 'data-section': 'permit-all' }, [
				E('h3', {}, _('Permit all')),
				E('p', {}, _('Not recommended. For the time you choose, %s can do anything root can: change or break Wi-Fi, firewall and network settings (and lock you out), read every password and key on the router, install or remove software, and run any program. Mistakes are not always reversible; only settings changes undo themselves. Prefer answering requests one by one.').format(who)),
				E('p', {}, _('Still on while it runs: blocked actions stay blocked, the activity log, automatic undo for settings, hidden passwords, and the speed limit.')),
				row(_('For'), dur, '', 'mcp-pa-dur'),
				row(_('Confirm'), E('label', {}, [ box, ' ', _('I understand this gives %s full control of this router').format(who) ])),
				row(_('Type %s to confirm').format(client), [ typed, hint ], '', 'openwrt-mcp-pa-name'),
				E('div', { 'class': 'mcp-row' }, [ go ])
			]);
		}

		function drawPermissions() {
			keepScroll(drawPermissionsNow);
		}

		function drawPermissionsNow() {
			var clients = knownClients(data.st);
			if (!ui_.client || clients.indexOf(ui_.client) < 0)
				ui_.client = clients[0] || '';
			var client = ui_.client;
			if (!clients.length) {
				panes.permissions.replaceChildren(section(_('Permissions'), '', [
					E('div', { 'class': 'mcp-card' }, [ E('h4', {}, _('No assistants yet')),
						E('p', {}, _('No assistant has connected to this router. Follow your assistant’s setup guide; it shows up here after its first connection. Nothing is waiting for you.')) ]) ]));
				return;
			}
			var seen = lastSeen()[client];
			var picker = selectOf(clients.map(function(c) { return [ c, displayName(c) ]; }), client, function(v) {
				ui_.client = v; ui_.choice = null; ui_.draft = null; ui_.editing = null; ui_.sig.permissions = null; drawPermissions();
			}, { 'id': 'openwrt-mcp-client' });
			var name = displayName(client);
			var nodes = [];
			if (data.writable === false)
				nodes.push(notice('notice', _('You can see this page but not change anything. Ask the router’s administrator if you need to change permissions.')));
			nodes.push(row(_('Assistant'), picker, [ E('code', {}, client), ' · ', _('last seen '), seen ? clock('ago', seen) : _('never') ], 'openwrt-mcp-client'));

			var cur = currentChoice(client);
			if (ui_.draft && ui_.draft.client !== client)
				ui_.draft = null;
			if (ui_.choice === null && !ui_.draft)
				ui_.choice = cur;
			var pa = permitAllOf(client);
			var choices = [
				[ 'look', _('Look only'), _('Read status, logs, connected devices and firewall rules. Changes nothing.') ],
				[ 'change', _('Look and change'), _('Everything above, plus change settings, services, software and VPN. Settings changes undo themselves if the router stops responding.') ],
				[ 'nothing', _('Nothing'), _('Removes every permission. %s can still connect, but can only ask.').format(name) ]
			];
			var dur = selectOf(DURATIONS, ui_.duration, function(v) { ui_.duration = v; showConsequence(); }, { 'id': 'mcp-duration' });
			var conseq = E('p', { 'class': 'mcp-line', 'role': 'status' }, '');
			var apply = btn('action', 'apply', _('Apply'), function() { return ui_.draft ? applyDraft(client, ui_.draft) : applyChoice(client, ui_.choice, ui_.duration); });
			function showConsequence() {
				var word = { look: _('look'), change: _('look and change') }[ui_.choice];
				var hand = ui_.draft && ui_.draft.manual;
				dur.disabled = ui_.choice === 'nothing' || (!ui_.choice && !hand);
				apply.disabled = (!ui_.draft && !ui_.choice) || !!pa;
				if (hand)
					conseq.textContent = _('You changed single abilities below. Nothing is saved until you press Apply.');
				else if (!ui_.choice)
					conseq.textContent = cur === null ? _('Custom: set below') : '';
				else if (ui_.choice === 'nothing')
					conseq.textContent = _('%s will have no permissions.').format(name);
				else if (ui_.duration === 'never')
					conseq.textContent = _('%s will be able to %s until you remove it.').format(name, word);
				else
					conseq.textContent = _('%s will be able to %s %s.').format(name, word, DURATION_WORDS[ui_.duration] ? _('for %s').format(DURATION_WORDS[ui_.duration]) : '');
			}
			var cards = choices.map(function(c) {
				var radio = E('input', { 'type': 'radio', 'name': 'mcp-choice', 'value': c[0], 'data-choice': c[0] });
				radio.checked = ui_.choice === c[0];
				if (!data.writable)
					radio.disabled = true;
				var lab = E('label', { 'class': 'mcp-choice' + (ui_.choice === c[0] ? ' mcp-choice-on' : '') }, [
					radio, ' ', E('strong', {}, c[1]), E('p', {}, c[2]) ]);
				radio.addEventListener('change', function() { ui_.choice = c[0]; ui_.draft = presetDraft(client, c[0]); drawPermissions(); });
				return lab;
			});
			nodes.push(E('div', { 'class': 'cbi-section' }, [
				E('fieldset', { 'class': 'mcp-choices' }, [ E('legend', {}, _('What may %s do?').format(name)) ].concat(cards)),
				E('div', { 'class': 'cbi-section-descr' }, _('Pick one. You can fine-tune single abilities below.')),
				data.writable ? E('div', { 'class': 'mcp-row' }, [ E('label', { 'for': 'mcp-duration' }, _('For')), dur, apply ]) : '',
				conseq
			]));
			showConsequence();

			var bodyRows = [];
			groups.forEach(function(g) {
				var on = g.items.filter(function(a) { var s = abilityState(client, a).state; return s === 'on' || s === 'always'; }).length;
				bodyRows.push(E('tr', { 'class': 'tr mcp-group' }, [ E('th', { 'class': 'th', 'colspan': 3 }, [
					g.title, ' · ', _('%d of %d on').format(on, g.items.length) ]) ]));
				g.items.forEach(function(a) { bodyRows.push(abilityRow(client, a)); });
			});
			nodes.push(section(_('What %s can do now').format(name),
				_('One row per ability. Switching one on uses the time chosen above. Grants that overlap are shown once, with the longest time left.'),
				[ table([ [ _('Ability') ], [ _('Status'), 'mcp-status' ], [ _('Allowed'), 'mcp-allowed' ] ], bodyRows) ]));

			var adv = E('details', { 'class': 'cbi-section', 'toggle': function(ev) { ui_.adv = ev.target.open; } }, [
				E('summary', {}, _('Advanced: limits per tool')),
				E('div', { 'class': 'cbi-section-descr' }, _('For experts. Limit a single tool to certain settings or commands, with its own time.')),
				drawAdvanced(client)
			]);
			if (ui_.adv)
				adv.setAttribute('open', '');
			nodes.push(adv);
			if (data.writable)
				nodes.push(permitAllPanel(client));
			panes.permissions.replaceChildren.apply(panes.permissions, nodes);
		}

		// ---- activity

		function auditKind(a) {
			if (a.client.charAt(0) === '<')
				return 'mine';
			if (!a.tool)
				return 'service';
			return a.outcome === 'OK' ? 'allowed' : 'refused';
		}

		var MINE = { decide: _('You answered a request'), grant: _('You gave an assistant access to one ability'), grant_preset: _('You gave an assistant a set of abilities'),
			revoke: _('You took access away from an assistant'), revoke_tools: _('You switched an ability off'), permit_all: _('You turned Permit all on'),
			end_permit_all: _('You turned Permit all off'), set_settings: _('You changed the request settings'), set_channel: _('You changed how requests reach you'),
			pair: _('You paired a new assistant') };

		function sentence(a) {
			var who = displayName(a.client);
			var verb = VERBS[a.tool] || (a.tool ? _('use “%s”').format(a.tool) : '');
			switch (auditKind(a)) {
			case 'mine':
				if (a.tool === 'set_channel' && CHANNEL_COPY[a.scope]) {
					var turnedOn = /=1$/.test(a.summary || '');
					return (turnedOn ? _('You turned on “%s”') : _('You turned off “%s”')).format(CHANNEL_COPY[a.scope][0]);
				}
				return MINE[a.tool] || _('You made a change');
			case 'service':
				return a.summary || a.error || _('The MCP service recorded an event');
			case 'allowed':
				return _('%s asked to %s · done').format(who, verb);
			}
			return a.outcome === 'DENIED' ? _('%s tried to %s · not allowed').format(who, verb) : _('%s tried to %s · it failed').format(who, verb);
		}

		var OUTCOME = { allowed: _('Allowed'), refused: _('Refused'), mine: _('Your change'), service: _('Service'), waiting: _('Waiting') };
		var OUTCOME_ICON = { allowed: '✓', refused: '✕', mine: '●', service: '○', waiting: '…' };

		function activityRows() {
			var rows = (data.st.audit || []).map(function(a) {
				return { time: a.time, client: a.client, kind: auditKind(a), text: sentence(a), raw: JSON.stringify(a) };
			});
			openRequests(data.st).forEach(function(r) {
				rows.push({ time: r.created, client: r.client, kind: 'waiting', text: _('%s asked to %s · waiting for you').format(displayName(r.client), requestAction(r)),
					raw: JSON.stringify(r) });
			});
			rows.sort(function(x, y) { return Date.parse(y.time) - Date.parse(x.time); });
			return rows;
		}

		function drawActivity() {
			var all = activityRows(), f = ui_.filter;
			var seen = {};
			all.forEach(function(a) { if (a.client.charAt(0) !== '<') seen[a.client] = true; });
			var clientOpts = [ [ '', _('All assistants') ] ].concat(Object.keys(seen).sort().map(function(c) { return [ c, displayName(c) ]; }));
			var kindOpts = [ [ '', _('Everything') ], [ 'allowed', _('Allowed') ], [ 'refused', _('Refused') ], [ 'waiting', _('Waiting for you') ],
				[ 'mine', _('Your changes') ], [ 'service', _('Connections and service') ] ];
			var body = E('div', { 'id': 'openwrt-mcp-activity-rows' });
			function fill() {
				var shown = all.filter(function(a) {
					return (!f.client || a.client === f.client) && (!f.kind || a.kind === f.kind) &&
						(!f.text || (a.text + ' ' + a.raw).toLowerCase().indexOf(f.text.toLowerCase()) >= 0);
				});
				var page = shown.slice(0, ui_.shown), trs = [], day = null;
				page.forEach(function(a, i) {
					var d = new Date(a.time), label = dayLabel(d);
					if (label !== day) {
						day = label;
						trs.push(E('tr', { 'class': 'tr mcp-group' }, [ E('th', { 'class': 'th', 'colspan': 3 }, label) ]));
					}
					var key = a.time + a.raw;
					trs.push(E('tr', { 'class': 'tr', 'data-activity': a.kind }, [
						cell(_('Time'), '', [ hhmm(d) ]),
						cell(_('What happened'), '', [ a.text, ' ', btn('', 'raw', ui_.raw[key] ? _('Hide raw') : _('Show raw'), function() {
							ui_.raw[key] = !ui_.raw[key];
							fill();
						}) ]),
						cell(_('Outcome'), 'mcp-status', [ OUTCOME_ICON[a.kind] + ' ' + OUTCOME[a.kind] ])
					]));
					if (ui_.raw[key])
						trs.push(E('tr', { 'class': 'tr mcp-raw' }, [ E('td', { 'class': 'td', 'colspan': 3 }, E('code', {}, a.raw)) ]));
				});
				if (!shown.length)
					body.replaceChildren(E('div', { 'class': 'mcp-card' }, [
						E('p', {}, _('No activity matches these filters.')),
						btn('', 'clear-filters', _('Clear filters'), function() { f.client = ''; f.kind = ''; f.text = ''; drawActivity(); }) ]));
				else
					body.replaceChildren(table([ [ _('Time') ], [ _('What happened') ], [ _('Outcome'), 'mcp-status' ] ], trs),
						E('p', { 'class': 'mcp-dim' }, _('Showing %d of %d').format(page.length, shown.length)),
						shown.length > page.length ? btn('', 'older', _('Show older'), function() { ui_.shown += ACTIVITY_PAGE; fill(); }) : '');
			}
			var text = E('input', { 'class': 'cbi-input-text', 'type': 'text', 'value': f.text, 'id': 'mcp-search',
				'placeholder': _('e.g. Wi-Fi, install, root') });
			text.addEventListener('input', function() { f.text = text.value; ui_.shown = ACTIVITY_PAGE; fill(); });
			panes.activity.replaceChildren(section(_('Activity'), _('Everything assistants did or asked for, newest first. Passwords and keys are never written here.'), [
				E('div', { 'class': 'mcp-filters' }, [
					E('label', { 'for': 'mcp-f-client' }, _('Assistant')), selectOf(clientOpts, f.client, function(v) { f.client = v; ui_.shown = ACTIVITY_PAGE; fill(); }, { 'id': 'mcp-f-client' }),
					E('label', { 'for': 'mcp-f-kind' }, _('Kind')), selectOf(kindOpts, f.kind, function(v) { f.kind = v; ui_.shown = ACTIVITY_PAGE; fill(); }, { 'id': 'mcp-f-kind' }),
					E('label', { 'for': 'mcp-search' }, _('Search')), text
				]), body ]));
			fill();
		}

		// ---- settings

		var CHANNEL_COPY = {
			chat: [ _('Answer in the assistant’s chat'), _('The assistant asks you in its own window and you answer there.') ],
			push: [ _('Run my own script when a request arrives'), _('Scripts in /etc/openwrt-mcp/hooks.d/ are started for each new request.') ],
			pair: [ _('Add assistants from this page'), _('Adds a Clients tab where you can paste an assistant’s public key.') ]
		};

		var TTL_CHOICES = [ [ 60, _('1 minute') ], [ 300, _('5 minutes') ], [ 600, _('10 minutes') ], [ 1800, _('30 minutes') ],
			[ 3600, _('1 hour') ], [ 21600, _('6 hours') ], [ 86400, _('1 day') ] ];

		function drawSettings() {
			var s = data.settings;
			// What was typed and not yet saved survives a redraw (ticking a switch redraws the page).
			var sd = ui_.settingsDraft || {};
			var wait = E('input', { 'class': 'cbi-input-text', 'type': 'number', 'min': 0, 'max': s.wait_max, 'value': sd.wait != null ? sd.wait : s.request_wait, 'id': 'mcp-wait',
				'style': 'width:6em' });
			wait.addEventListener('input', function() { ui_.settingsDraft = Object.assign({}, ui_.settingsDraft, { wait: wait.value }); });
			var opts = TTL_CHOICES.filter(function(c) { return c[0] >= s.ttl_min && c[0] <= s.ttl_max; });
			if (!opts.some(function(c) { return c[0] === s.request_ttl; }))
				opts.push([ s.request_ttl, span(s.request_ttl) ]);
			opts.sort(function(a, b) { return a[0] - b[0]; });
			var ttl = selectOf(opts.map(function(c) { return [ String(c[0]), c[1] ]; }), sd.ttl != null ? sd.ttl : String(s.request_ttl),
				function(v) { ui_.settingsDraft = Object.assign({}, ui_.settingsDraft, { ttl: v }); }, { 'id': 'mcp-ttl' });
			var channels = (s.channels || []).map(function(c) {
				var copy = CHANNEL_COPY[c.name] || [ _(c.title), '' ];
				var box = E('input', { 'type': 'checkbox', 'data-channel': c.name, 'id': 'mcp-ch-' + c.name, 'disabled': data.writable ? null : '' });
				box.checked = c.enabled;
				box.addEventListener('change', function() { run(callSetChannel(c.name, box.checked)); });
				return row(copy[0], E('label', {}, [ box, ' ', _('On') ]), [ copy[1] ? copy[1] + ' ' : '', E('strong', {}, _('Risk:')), ' ', _(c.harm) ], 'mcp-ch-' + c.name);
			});
			var mfa = s.mfa_clients || [];
			var actions = data.writable ? E('div', { 'class': 'cbi-page-actions' }, [
				btn('', 'reset-settings', _('Reset'), function() { ui_.settingsDraft = null; drawSettings(); }), ' ',
				btn('save', 'save-settings', _('Save'), function() {
					run(callSetSettings(parseInt(wait.value, 10), parseInt(ttl.value, 10)), function() {
						ui_.settingsDraft = null;
						notify(_('Saved. The daemon applies it to the next request.'), 'info');
					});
				}, { 'class': 'cbi-button cbi-button-save cbi-button-apply' })
			]) : E('p', { 'class': 'mcp-dim' }, _('You can see this page but not change anything. Ask the router’s administrator if you need to change permissions.'));
			panes.settings.replaceChildren(
				section(_('Requests'), _('These two settings apply when you press Save.'), [
					row(_('Ask me before refusing'), [ wait, ' ', _('seconds') ],
						_('When an assistant tries something it isn’t allowed to do, keep it waiting this long while you get a request. 0 refuses at once and sends no request. From 0 to %d.').format(s.wait_max), 'mcp-wait'),
					row(_('Keep a request open for'), ttl, _('A request nobody answers in time is refused.'), 'mcp-ttl')
				]),
				section(_('How requests reach you'), _('Each extra way is off until you turn it on, and ticking a box applies at once. The line under it says how it could be misused.'), [
					row(_('This page'), _('Always on'), _('Only people who can log in to this router see and answer requests here.')),
					row(_('Status overview'), _('Always on'), [ _('Waiting requests also show on Status › Overview. '), E('strong', {}, _('Risk:')), ' ',
						_('anyone logged in to the router can answer from there.') ])
				].concat(channels)),
				section(_('2-step confirmation'), '', [
					row(_('Status'), mfa.length ? _('Set up for %s').format(mfa.map(displayName).join(', ')) : _('Not set up'),
						[ _('Asks for a code from your phone before risky actions. Set it up on the router’s command line with '), E('code', {}, 'openwrt-mcp mfa'), '.' ])
				]),
				actions);
		}

		// ---- clients (pairing, only while the channel is on)

		function drawClients() {
			var pair = (data.settings.channels || []).filter(function(c) { return c.name === 'pair'; })[0] || {};
			var name = E('input', { 'class': 'cbi-input-text', 'type': 'text', 'size': 24, 'id': 'openwrt-mcp-pair-name',
				'placeholder': _('client name') });
			var key = E('textarea', { 'class': 'cbi-input-textarea', 'rows': 3, 'cols': 60, 'id': 'openwrt-mcp-pair-key',
				'placeholder': 'ssh-ed25519 AAAA...' });
			var preset = selectOf([ [ 'readonly', _('Look only') ], [ 'operator', _('Look and change') ], [ 'none', _('Nothing yet') ] ], 'readonly', null, { 'id': 'mcp-pair-preset' });
			var dur = selectOf(DURATIONS.concat([ [ '7d', _('7 days') ] ]), '7d', null, { 'id': 'mcp-pair-dur' });
			panes.clients.replaceChildren(section(_('Clients'), '', [
				notice('warning', _(pair.harm || '')),
				E('div', { 'class': 'cbi-section-descr' }, _('Paste the public key that “openwrt-mcp connect” prints. It is added to this router with the same locked-down line as “openwrt-mcp authorize-key”: the key can run the MCP bridge and nothing else.')),
				row(_('Assistant name'), name, '', 'openwrt-mcp-pair-name'),
				row(_('Public key'), key, '', 'openwrt-mcp-pair-key'),
				row(_('Starting access'), [ preset, ' ', _('for'), ' ', dur ], '', 'mcp-pair-preset'),
				data.writable ? E('div', { 'class': 'mcp-row' }, [ btn('negative', 'pair', _('Pair'), function() {
					callPair(name.value.trim(), key.value.trim(), preset.value, dur.value).then(check).then(function() {
						notify(_('Paired %s. Point its MCP client at ssh -T -i <that key> root@<router>.').format(name.value.trim()), 'info');
						name.value = ''; key.value = '';
						return refresh();
					}).catch(fail);
				}) ]) : E('p', { 'class': 'mcp-dim' }, _('You can see this page but not change anything. Ask the router’s administrator if you need to change permissions.'))
			]));
		}

		// ---- the frame

		function drawError() {
			if (!ui_.error) {
				errorBox.replaceChildren();
				return;
			}
			errorBox.replaceChildren(E('div', { 'class': 'alert-message error', 'role': 'alert', 'data-error': '1' }, [
				E('p', {}, _('Can’t reach the MCP service. It may be stopped or still starting. Your last change was not saved.')),
				E('div', { 'class': 'mcp-row' }, [
					btn('action', 'retry', _('Try again'), function() { refresh(); }),
					E('a', { 'class': 'cbi-button', 'href': L.url('admin/system/startup') }, _('Open System › Startup'))
				])
			]));
		}

		function draw() {
			indexTools();
			drawError();
			drawBanner();
			drawOverview();
			var key = function(k, v) { var s = JSON.stringify(v); if (ui_.sig[k] === s) return false; ui_.sig[k] = s; return true; };
			if (key('permissions', [ data.st.policies, data.st.clients, data.st.permit_all, data.writable, ui_.client, data.tools ])) drawPermissions();
			if (key('activity', [ data.st.audit, openRequests(data.st).length ])) drawActivity();
			if (key('settings', data.settings)) { drawSettings(); showTab(); }
			if (channelOn('pair') && key('clients', [ data.settings.channels, data.writable ])) drawClients();
			tick(root);
		}

		showTab();
		draw();
		poll.add(refresh, 5);
		var timer = window.setInterval(function() {
			if (!document.body.contains(root))
				return window.clearInterval(timer);
			tick(root);
		}, 1000);
		return root;
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
