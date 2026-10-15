'use strict';
'require baseclass';
'require rpc';
'require ui';

// Status -> Overview (docs/luci-approvals.md, 8.5; wording from the page redesign). Shown only while
// something needs the owner: an open request, a rollback waiting for confirmation, or a Permit all
// that is running. render() returns null otherwise, and LuCI hides an include that renders nothing.
// It uses the same rpcd methods as Services -> MCP Server; the buttons need the write ACL, which
// rpcd enforces. The page there has the full controls (breadth and duration); here Allow is the
// narrowest breadth for the shortest time, and a root command can only be answered on the page.
//
// The request sentence and the badge are the page's (view/openwrt-mcp/status.js); an include is one
// file with no shared module, so the few lines are repeated here. The tests pin both to the same words.

var callStatus = rpc.declare({ object: 'openwrt-mcp', method: 'status', params: [ 'audit' ], expect: { '': {} } });
var callTools = rpc.declare({ object: 'openwrt-mcp', method: 'tools', expect: { '': {} } });
var callDecide = rpc.declare({ object: 'openwrt-mcp', method: 'decide',
	params: [ 'id', 'decision', 'breadth', 'duration', 'confirm' ], expect: { '': {} } });
var callEndPermitAll = rpc.declare({ object: 'openwrt-mcp', method: 'end_permit_all',
	params: [ 'client' ], expect: { '': {} } });
var callAccess = rpc.declare({ object: 'session', method: 'access',
	params: [ 'scope', 'object', 'function' ], expect: { 'access': true } });

var CSS = [
	'.mcp-risk{display:inline-block;padding:1px 8px;border-radius:3px;font-size:85%;font-weight:600;white-space:nowrap}',
	'.mcp-risk-look{background:#1d6b38;color:#fff}',
	'.mcp-risk-change{background:#f0c23b;color:#2b2000}',
	'.mcp-risk-full{background:#b3261e;color:#fff}',
	'.mcp-wrow{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:8px 0}',
	'.mcp-wrow .mcp-wtext{flex:1 1 20em}',
	'.mcp-wrow .mcp-sep{margin-left:16px}',
	'@media (max-width:600px){.mcp-wrow button,.mcp-wrow a{flex:1 1 100%;min-height:40px}.mcp-wrow .mcp-sep{margin-left:0}}'
].join('\n');

var RISK = { look: _('Looks only'), change: _('Changes things'), full: _('Full control') };
var RISK_OF_BADGE = { read: 'look', write: 'change', shell: 'full' };

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
	wireless: _('Wi-Fi settings'), network: _('network settings'), firewall: _('firewall settings'),
	dhcp: _('address and name settings (DHCP, DNS)')
};

var READONLY_UBUS = [ 'system.board', 'system.info', 'network.interface.dump', 'network.interface.*.status', 'network.device.status',
	'network.wireless.status', 'iwinfo.devices', 'iwinfo.info', 'iwinfo.assoclist', 'iwinfo.freqlist', 'iwinfo.txpowerlist',
	'iwinfo.countrylist', 'iwinfo.survey', 'hostapd.*.get_clients', 'hostapd.*.get_status', 'luci-rpc.getDHCPLeases',
	'luci-rpc.getHostHints', 'luci-rpc.getNetworkDevices', 'luci-rpc.getWirelessDevices', 'luci-rpc.getBoardJSON', 'service.list',
	'rc.list', 'dnsmasq.metrics', 'uci.configs', 'uci.changes', 'log.read' ];

function check(res) {
	if (res && res.error) {
		var e = new Error(res.error);
		e.code = res.code;
		throw e;
	}
	return res;
}

function fail(err) {
	ui.addNotification(null, E('p', {}, _('Couldn’t save: %s. Nothing was changed.').format(String((err && err.message) || err))), 'danger');
}

function span(s) {
	s = Math.max(0, s);
	if (s < 90) return _('%d s').format(s);
	var m = Math.round(s / 60);
	if (m < 60) return _('%d min').format(m);
	var h = Math.floor(m / 60), mm = m % 60;
	if (h < 24) return mm ? _('%d h %d min').format(h, mm) : _('%d h').format(h);
	return _('%d d').format(Math.round(h / 24));
}

function untilWhen(iso) {
	var d = new Date(iso);
	var hm = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
	if (d.toDateString() === new Date().toDateString())
		return _('until %s today').format(hm);
	return _('until %s %s').format(d.toLocaleDateString([], { weekday: 'short' }), hm);
}

function left(iso) {
	var s = Math.round((Date.parse(iso) - Date.now()) / 1000);
	return s > 86400 ? untilWhen(iso) : _('%s left').format(span(s));
}

function displayName(id) {
	return String(id).split(/[-_.]+/).filter(Boolean).map(function(w) {
		return w.charAt(0).toUpperCase() + w.slice(1);
	}).join(' ');
}

function isFullControl(r) {
	return r.tool === 'exec' || (r.tool === 'ubus_call' && READONLY_UBUS.indexOf(r.scope) < 0);
}

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
		return _('change the %s').format(area);
	if (r.tool === 'uci_get' && area)
		return _('read the %s').format(area);
	if (r.tool === 'sysupgrade' && scope === 'backup')
		return _('make a backup of the router settings');
	if (r.tool === 'sysupgrade' && [ 'list', 'test', 'check' ].indexOf(scope) >= 0)
		return _('check for firmware updates');
	return VERBS[r.tool] || _('use “%s”').format(r.tool);
}

function toolIndex(groups) {
	var by = {};
	(groups || []).forEach(function(g) {
		g.tools.forEach(function(t) { by[t.name] = t; });
	});
	return by;
}

return baseclass.extend({
	title: _('MCP Server'),

	load: function() {
		return callStatus(0).then(check).then(function(st) {
			var open = (st.requests || []).filter(function(r) { return r.state === 'open'; });
			if (!open.length && !(st.pending || []).length && !(st.permit_all || []).length)
				return { st: st, open: open };
			return Promise.all([
				open.length ? callTools().then(check).catch(function() { return {}; }) : {},
				callAccess('ubus', 'openwrt-mcp', 'decide').catch(function() { return true; })
			]).then(function(r) {
				return { st: st, open: open, tools: toolIndex(r[0].groups), writable: r[1] !== false };
			});
		}).catch(function() { return null; });
	},

	render: function(data) {
		if (!data)
			return null;
		var pending = data.st.pending || [];
		var permitAll = data.st.permit_all || [];
		if (!data.open.length && !pending.length && !permitAll.length)
			return null;

		function confirmShell(message, retry) {
			var ack = E('input', { 'type': 'checkbox' });
			var go = E('button', { 'class': 'cbi-button cbi-button-negative important', 'type': 'button', 'data-act': 'confirm-shell', 'disabled': '',
				'click': function() { ui.hideModal(); retry(); } }, _('Allow'));
			ack.addEventListener('change', function() { go.disabled = !ack.checked; });
			ui.showModal(_('Full control'), [
				E('p', {}, _('A root command has no limits. It can change or break anything on the router, read every password and key, and is not undone automatically. Only allow it if you know what it does.')),
				E('p', {}, message),
				E('p', {}, E('label', {}, [ ack, ' ', _('I understand this gives a root shell and can’t be undone automatically.') ])),
				E('div', { 'class': 'right' }, [ E('button', { 'class': 'cbi-button', 'type': 'button', 'click': ui.hideModal }, _('Cancel')), ' ', go ])
			]);
		}

		// The line reports the outcome itself; the next poll drops it from the list.
		function decide(r, line, decision, confirm) {
			var buttons = line.querySelectorAll ? line.querySelectorAll('button') : [];
			buttons.forEach(function(b) { b.disabled = true; });
			return callDecide(r.id, decision, 'exact', '15m', confirm || false).then(check).then(function() {
				line.replaceChildren(E('em', {}, decision === 'allow' ? _('Allowed for 15 minutes.') : _('Denied.')));
			}).catch(function(e) {
				buttons.forEach(function(b) { b.disabled = false; });
				if (e.code === 'needs_confirm')
					return confirmShell(e.message, function() { decide(r, line, decision, true); });
				fail(e);
			});
		}

		function requestLine(r) {
			var tool = data.tools[r.tool] || {};
			var full = isFullControl(r);
			var risk = full ? 'full' : (RISK_OF_BADGE[tool.badge] || 'change');
			var line = E('div', { 'class': 'mcp-wrow', 'data-request': r.id });
			line.appendChild(E('span', { 'class': 'mcp-wtext' }, [
				E('strong', {}, _('%s wants to %s').format(displayName(r.client), requestAction(r))), ' ',
				E('span', { 'class': 'label mcp-risk mcp-risk-' + risk }, RISK[risk]) ]));
			if (data.writable) {
				if (!full)
					line.appendChild(E('button', { 'class': 'cbi-button cbi-button-action', 'type': 'button', 'data-act': 'allow',
						'click': function() { decide(r, line, 'allow'); } }, _('Allow for 15 minutes')));
				line.appendChild(E('button', { 'class': 'cbi-button cbi-button-negative' + (full ? '' : ' mcp-sep'), 'type': 'button', 'data-act': 'deny',
					'click': function() { decide(r, line, 'deny'); } }, _('Deny')));
			}
			return line;
		}

		function banner(a) {
			var line = E('div', { 'class': 'alert-message error', 'role': 'alert', 'data-permit-all': a.client });
			var lead = a.expires ?
				_('Full access is on for %s · %s').format(displayName(a.client), left(a.expires)) :
				_('Full access is on for %s · until you remove it').format(displayName(a.client));
			line.appendChild(E('div', { 'class': 'mcp-wrow' }, [ E('strong', { 'class': 'mcp-wtext' }, lead) ]));
			if (data.writable)
				line.children[0].appendChild(E('button', { 'class': 'cbi-button cbi-button-negative', 'type': 'button', 'data-act': 'end-permit-all',
					'click': function(ev) {
						ev.target.disabled = true;
						callEndPermitAll(a.client).then(check).then(function() {
							line.replaceChildren(E('em', {}, _('Ended.')));
						}).catch(function(e) { ev.target.disabled = false; fail(e); });
					} }, _('End now')));
			return line;
		}

		var open = data.open.sort(function(a, b) { return Date.parse(a.created) - Date.parse(b.created); });
		var nodes = [ E('style', {}, CSS) ].concat(permitAll.map(banner));
		if (open.length) {
			nodes.push(E('h3', {}, open.length === 1 ? _('MCP Server · 1 request waiting') : _('MCP Server · %d requests waiting').format(open.length)));
			open.slice(0, 3).forEach(function(r) { nodes.push(requestLine(r)); });
			if (open.length > 3)
				nodes.push(E('p', {}, _('and %d more').format(open.length - 3)));
		} else if (!permitAll.length)
			nodes.push(E('h3', {}, _('MCP Server')));
		pending.forEach(function(p) {
			nodes.push(E('div', { 'class': 'alert-message warning' },
				_('A change to %s by %s is waiting for confirmation. It undoes itself in %s.').format(
					p.configs.join(', '), displayName(p.client), span(Math.round((Date.parse(p.deadline) - Date.now()) / 1000)))));
		});
		nodes.push(E('div', { 'class': 'mcp-wrow' }, E('a', { 'class': 'cbi-button', 'data-act': 'open',
			'href': L.url('admin/services/openwrt-mcp') }, _('Open MCP Server'))));
		return E('div', { 'class': 'cbi-section', 'id': 'openwrt-mcp-overview' }, nodes);
	}
});
