'use strict';
'require baseclass';
'require rpc';
'require ui';

// Status -> Overview (docs/luci-approvals.md, 8.5). Shown only while something needs the owner:
// an open request or a rollback waiting for confirmation. render() returns null otherwise, and
// LuCI hides an include that renders nothing. It uses the same rpcd methods as Services -> MCP
// Server; the buttons need the write ACL, which rpcd enforces. The page there has the full
// controls (breadth and duration); here Allow is the narrowest breadth for one hour.

var callStatus = rpc.declare({ object: 'openwrt-mcp', method: 'status', params: [ 'audit' ], expect: { '': {} } });
var callTools = rpc.declare({ object: 'openwrt-mcp', method: 'tools', expect: { '': {} } });
var callDecide = rpc.declare({ object: 'openwrt-mcp', method: 'decide',
	params: [ 'id', 'decision', 'breadth', 'duration', 'confirm' ], expect: { '': {} } });
var callAccess = rpc.declare({ object: 'session', method: 'access',
	params: [ 'scope', 'object', 'function' ], expect: { 'access': true } });

function check(res) {
	if (res && res.error) {
		var e = new Error(res.error);
		e.code = res.code;
		throw e;
	}
	return res;
}

function fail(err) {
	ui.addNotification(null, E('p', {}, String((err && err.message) || err)), 'danger');
}

function until(iso) {
	var s = Math.round((Date.parse(iso) - Date.now()) / 1000);
	if (s <= 0) return _('now');
	if (s < 90) return _('%d s').format(s);
	if (s < 5400) return _('%d min').format(Math.round(s / 60));
	return _('%d h').format(Math.round(s / 3600));
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
			if (!open.length)
				return { st: st, open: open };
			return Promise.all([
				callTools().then(check).catch(function() { return {}; }),
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
		if (!data.open.length && !pending.length)
			return null;

		function confirmShell(message, retry) {
			ui.showModal(_('This is a root shell'), [
				E('p', {}, message),
				E('div', { 'class': 'right' }, [
					E('button', { 'class': 'btn', 'click': ui.hideModal }, _('Cancel')), ' ',
					E('button', { 'class': 'btn cbi-button-negative', 'click': function() { ui.hideModal(); retry(); } },
						_('I understand, allow'))
				])
			]);
		}

		// The row reports the outcome itself; the next poll drops it from the list.
		function decide(r, row, decision, confirm) {
			var buttons = row.querySelectorAll ? row.querySelectorAll('button') : [];
			buttons.forEach(function(b) { b.disabled = true; });
			return callDecide(r.id, decision, 'exact', '1h', confirm || false).then(check).then(function() {
				row.replaceChildren(E('em', {}, decision === 'allow' ? _('Allowed for 1 hour.') : _('Denied.')));
			}).catch(function(e) {
				buttons.forEach(function(b) { b.disabled = false; });
				if (e.code === 'needs_confirm')
					return confirmShell(e.message, function() { decide(r, row, decision, true); });
				fail(e);
			});
		}

		function card(r) {
			var tool = data.tools[r.tool] || { title: r.tool, badge: 'write' };
			var row = E('div', { 'style': 'margin-top:.5em' });
			if (data.writable)
				row.appendChild(E('span', {}, [
					E('button', { 'class': 'btn cbi-button-positive', 'data-act': 'allow', 'click': function() {
						decide(r, row, 'allow');
					} }, _('Allow')), ' ',
					E('button', { 'class': 'btn cbi-button-negative', 'data-act': 'deny', 'click': function() {
						decide(r, row, 'deny');
					} }, _('Deny')), ' '
				]));
			row.appendChild(E('a', { 'class': 'btn cbi-button', 'data-act': 'open',
				'href': L.url('admin/services/openwrt-mcp') }, _('Open')));
			return E('div', { 'class': 'alert-message warning', 'data-request': r.id }, [
				E('div', {}, E('strong', {}, _('%s asks for: %s').format(r.client, tool.title))),
				E('div', {}, [ _('scope'), ' ', E('code', {}, r.scope || '*'), ' · ',
					_('open for another'), ' ', until(r.expires) ]),
				tool.badge === 'shell' ? E('div', {}, E('strong', {},
					_('Allowing this gives %s the power of a root shell.').format(r.client))) : '',
				row
			]);
		}

		var nodes = data.open.sort(function(a, b) { return Date.parse(b.created) - Date.parse(a.created); }).map(card);
		pending.forEach(function(p) {
			nodes.push(E('div', { 'class': 'alert-message warning' },
				_('Change to %s by %s awaits confirmation; reverts automatically in %s').format(
					p.configs.join(', '), p.client, until(p.deadline))));
		});
		return E('div', { 'id': 'openwrt-mcp-overview' }, nodes);
	}
});
