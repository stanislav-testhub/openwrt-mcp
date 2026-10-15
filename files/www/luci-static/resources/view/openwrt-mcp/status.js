'use strict';
'require view';
'require rpc';
'require ui';
'require poll';

// Services -> MCP Server (docs/luci-approvals.md, 8.4). Everything goes through the openwrt-mcp
// rpcd plugin; nothing here runs a program. Reading is the read ACL group and every change is
// the write group, enforced by rpcd. The page hides the buttons a user cannot use, but that is
// presentation: a forged call without the write ACL is refused by rpcd itself.
//
// Requests always sit above the tabs. The groups and badges on Permissions come from the daemon's
// tool registry (the `tools` method), so the page cannot drift from the server.

var callStatus = rpc.declare({ object: 'openwrt-mcp', method: 'status', params: [ 'audit' ], expect: { '': {} } });
var callTools = rpc.declare({ object: 'openwrt-mcp', method: 'tools', expect: { '': {} } });
var callSettings = rpc.declare({ object: 'openwrt-mcp', method: 'settings', expect: { '': {} } });
var callDecide = rpc.declare({ object: 'openwrt-mcp', method: 'decide',
	params: [ 'id', 'decision', 'breadth', 'duration', 'confirm' ], expect: { '': {} } });
var callGrant = rpc.declare({ object: 'openwrt-mcp', method: 'grant',
	params: [ 'client', 'tool', 'scope', 'duration', 'confirm' ], expect: { '': {} } });
var callGrantPreset = rpc.declare({ object: 'openwrt-mcp', method: 'grant_preset',
	params: [ 'client', 'preset', 'duration' ], expect: { '': {} } });
var callRevoke = rpc.declare({ object: 'openwrt-mcp', method: 'revoke',
	params: [ 'client', 'index', 'all' ], expect: { '': {} } });
var callSetSettings = rpc.declare({ object: 'openwrt-mcp', method: 'set_settings',
	params: [ 'request_wait', 'request_ttl' ], expect: { '': {} } });
var callAccess = rpc.declare({ object: 'session', method: 'access',
	params: [ 'scope', 'object', 'function' ], expect: { 'access': true } });

var DURATIONS = [ [ '15m', _('15 minutes') ], [ '1h', _('1 hour') ], [ '8h', _('8 hours') ],
	[ '1d', _('1 day') ], [ '7d', _('7 days') ] ];
var AUDIT_LINES = 200;

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

function fail(err) {
	ui.addNotification(null, E('p', {}, String((err && err.message) || err)), 'danger');
}

function selectOf(options, value, change) {
	var sel = E('select', { 'class': 'cbi-input-select' }, options.map(function(o) {
		return E('option', { 'value': o[0], 'selected': o[0] === value ? '' : null }, o[1]);
	}));
	sel.value = value;
	if (change)
		sel.addEventListener('change', function() { change(sel.value); });
	return sel;
}

function badge(kind) {
	var text = { read: _('read'), write: _('writes'), shell: _('root shell') }[kind] || kind;
	var color = { read: '#2a8a2a', write: '#b8860b', shell: '#c22' }[kind] || '#888';
	return E('span', { 'class': 'label', 'style': 'background:' + color + ';color:#fff;padding:1px 6px;border-radius:3px;font-size:85%' }, text);
}

function noteLabel(n) {
	return { rollback: _('rollback armed'), keys: _('shows keys') }[n] || n;
}

function table(titles, rows, empty) {
	var t = E('table', { 'class': 'table' }, [
		E('tr', { 'class': 'tr table-titles' }, titles.map(function(h) {
			return E('th', { 'class': 'th' }, h);
		}))
	]);
	if (!rows.length)
		t.appendChild(E('tr', { 'class': 'tr placeholder' }, [
			E('td', { 'class': 'td', 'colspan': titles.length }, E('em', {}, empty))
		]));
	rows.forEach(function(r) {
		t.appendChild(E('tr', { 'class': 'tr' }, r.map(function(c) {
			return E('td', { 'class': 'td' }, c);
		})));
	});
	return t;
}

function ago(iso) {
	var s = Math.max(0, Math.round((Date.now() - Date.parse(iso)) / 1000));
	if (s < 90) return _('%d s').format(s);
	if (s < 5400) return _('%d min').format(Math.round(s / 60));
	return _('%d h').format(Math.round(s / 3600));
}

function until(iso) {
	var s = Math.round((Date.parse(iso) - Date.now()) / 1000);
	if (s <= 0) return _('now');
	if (s < 90) return _('%d s').format(s);
	if (s < 5400) return _('%d min').format(Math.round(s / 60));
	return _('%d h').format(Math.round(s / 3600));
}

// A live time: the ticker rewrites these once a second without re-rendering the card, so a
// selection the owner is making is not lost.
function clock(kind, iso) {
	return E('span', { 'data-clock': kind, 'data-ts': iso }, kind === 'ago' ? ago(iso) : until(iso));
}

function tick(root) {
	if (!root.querySelectorAll)
		return;
	root.querySelectorAll('[data-clock]').forEach(function(n) {
		var iso = n.getAttribute('data-ts');
		n.textContent = n.getAttribute('data-clock') === 'ago' ? ago(iso) : until(iso);
	});
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
		.sort(function(a, b) { return Date.parse(b.created) - Date.parse(a.created); });
}

// ---------------------------------------------------------------- the page

return view.extend({
	load: function() {
		return Promise.all([
			callStatus(AUDIT_LINES), callTools(), callSettings(),
			callAccess('ubus', 'openwrt-mcp', 'decide').catch(function() { return true; })
		]).then(function(r) {
			return { st: check(r[0]), tools: check(r[1]), settings: check(r[2]), writable: r[3] !== false };
		});
	},

	render: function(data) {
		var ui_ = { tab: 'overview', client: null, breadth: {}, duration: {}, sig: {} };
		var requestsBox = E('div', { 'id': 'openwrt-mcp-requests' });
		var panes = {
			overview: E('div', { 'class': 'cbi-section' }),
			permissions: E('div', { 'class': 'cbi-section' }),
			activity: E('div', { 'class': 'cbi-section' }),
			settings: E('div', { 'class': 'cbi-section' })
		};
		var titles = [ [ 'overview', _('Overview') ], [ 'permissions', _('Permissions') ],
			[ 'activity', _('Activity') ], [ 'settings', _('Settings') ] ];
		var tabbar = E('ul', { 'class': 'cbi-tabmenu' });
		var root = E('div', { 'id': 'openwrt-mcp-page' }, [ requestsBox, tabbar ]);
		titles.forEach(function(t) { root.appendChild(panes[t[0]]); });

		function showTab() {
			tabbar.replaceChildren.apply(tabbar, titles.map(function(t) {
				return E('li', { 'class': 'cbi-tab' + (t[0] === ui_.tab ? '' : '-disabled') }, [
					E('a', { 'href': '#', 'click': function(ev) { ev.preventDefault(); ui_.tab = t[0]; showTab(); } }, t[1])
				]);
			}));
			titles.forEach(function(t) { panes[t[0]].style.display = t[0] === ui_.tab ? '' : 'none'; });
		}

		function refresh() {
			return Promise.all([ callStatus(AUDIT_LINES), callSettings() ]).then(function(r) {
				data.st = check(r[0]);
				data.settings = check(r[1]);
				draw();
			}).catch(fail);
		}

		// A decision and anything after it: show the outcome, then re-read.
		function act(promise, done) {
			return promise.then(check).then(function(res) {
				if (done) done(res);
				return refresh();
			});
		}

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

		// ---- requests (above the tabs)

		function decide(r, decision, breadth, duration, confirm) {
			return callDecide(r.id, decision, breadth, duration, confirm || false).then(check).then(refresh).catch(function(e) {
				if (e.code === 'needs_confirm')
					return confirmShell(e.message, function() { decide(r, decision, breadth, duration, true); });
				fail(e);
				return refresh();
			});
		}

		function requestCard(r) {
			var tool = (toolIndex(data.tools.groups))[r.tool] || { title: r.tool, badge: 'write', notes: [] };
			var breadths = [ [ 'exact', _('this exact scope') ] ];
			if (r.family && r.family !== r.scope)
				breadths.push([ 'family', _('this tool on %s').format(r.family) ]);
			breadths.push([ 'tool', _('this tool, every scope') ], [ 'operator', _('the Operator preset') ]);
			var breadth = ui_.breadth[r.id] || 'exact', duration = ui_.duration[r.id] || '1h';
			var buttons = data.writable ? [
				selectOf(DURATIONS, duration, function(v) { ui_.duration[r.id] = v; }), ' ',
				selectOf(breadths, breadth, function(v) { ui_.breadth[r.id] = v; }), ' ',
				E('button', { 'class': 'btn cbi-button-positive', 'data-act': 'allow', 'click': function() {
					decide(r, 'allow', ui_.breadth[r.id] || 'exact', ui_.duration[r.id] || '1h');
				} }, _('Allow')), ' ',
				E('button', { 'class': 'btn cbi-button-negative', 'data-act': 'deny', 'click': function() {
					decide(r, 'deny');
				} }, _('Deny'))
			] : [ E('em', {}, _('Your LuCI account can see requests but not answer them.')) ];
			return E('div', { 'class': 'alert-message warning', 'data-request': r.id }, [
				E('div', {}, [
					E('strong', {}, _('%s asks for: %s').format(r.client, tool.title)), ' ', badge(tool.badge),
					(tool.notes || []).map(function(n) { return [ ' ', E('em', {}, noteLabel(n)) ]; })
				]),
				E('div', {}, [ _('scope'), ' ', E('code', {}, r.scope || '*') ]),
				r.args ? E('div', {}, [ _('args'), ' ', E('code', {}, r.args) ]) : '',
				E('div', {}, [ _('waiting'), ' ', clock('ago', r.created), ' · ', _('open for another'), ' ', clock('until', r.expires) ]),
				tool.badge === 'shell' ? E('div', {}, E('strong', {},
					_('Allowing this gives %s the power of a root shell.').format(r.client))) : '',
				E('div', { 'style': 'margin-top:.5em' }, buttons)
			]);
		}

		function drawRequests() {
			var reqs = openRequests(data.st);
			var sig = JSON.stringify([ reqs, data.writable, (data.st.pending || []) ]);
			if (sig === ui_.sig.requests)
				return;
			ui_.sig.requests = sig;
			var nodes = [];
			var byClient = {};
			reqs.forEach(function(r) { (byClient[r.client] = byClient[r.client] || []).push(r); });
			Object.keys(byClient).forEach(function(c) {
				if (data.writable && byClient[c].length > 1)
					nodes.push(E('div', {}, E('button', { 'class': 'btn cbi-button-action', 'data-act': 'allow-all', 'click': function() {
						byClient[c].reduce(function(p, r) {
							return p.then(function() { return decide(r, 'allow', 'exact', '1h'); });
						}, Promise.resolve());
					} }, _('Allow all %d from %s').format(byClient[c].length, c))));
			});
			reqs.forEach(function(r) { nodes.push(requestCard(r)); });
			(data.st.pending || []).forEach(function(p) {
				nodes.push(E('div', { 'class': 'alert-message warning' }, [
					_('Change to %s by %s awaits confirmation; reverts automatically in ').format(p.configs.join(', '), p.client),
					clock('until', p.deadline)
				]));
			});
			requestsBox.replaceChildren.apply(requestsBox, nodes);
		}

		// ---- overview

		function lastSeen(st) {
			var seen = {};
			(st.audit || []).forEach(function(a) { seen[a.client] = a.time; });
			return seen;
		}

		function drawOverview() {
			var st = data.st, seen = lastSeen(st), tokens = {};
			(st.clients || []).forEach(function(c) { tokens[c.name] = true; });
			var rows = knownClients(st).map(function(c) {
				var n = (st.policies || []).filter(function(p) { return p.client === c; }).length;
				return [ c, tokens[c] ? _('HTTP token') : _('SSH key or not paired'), String(n), seen[c] || '—' ];
			});
			panes.overview.replaceChildren(
				E('h3', {}, _('Daemon')),
				E('p', {}, [
					E('strong', {}, st.running ? _('Running') : _('Stopped')),
					' — openwrt-mcp ' + st.version + ', HTTP ' + st.listen + ', stdio socket ' + (st.socket || _('disabled'))
				]),
				E('h3', {}, _('Clients')),
				table([ _('Client'), _('Connects by'), _('Grants'), _('Last seen') ], rows,
					_('No client has connected yet.')));
		}

		// ---- permissions

		function grantsFor(client) {
			return (data.st.policies || []).filter(function(p) { return p.client === client; });
		}

		function liveGrants(client, tool) {
			return grantsFor(client).filter(function(p) {
				return p.enabled && !p.expired && (p.tools.indexOf(tool) >= 0 || p.tools.indexOf('*') >= 0);
			});
		}

		function revoke(client, index, all) {
			return callRevoke(client, all ? null : index, all || false).then(check).then(refresh).catch(fail);
		}

		function grantRow(client, tool, scopeInput, durSel) {
			return E('button', { 'class': 'btn cbi-button-action', 'data-act': 'grant', 'click': function() {
				var go = function(confirm) {
					callGrant(client, tool.name, scopeInput.value.trim() || '*', durSel.value, confirm).then(check).then(refresh).catch(function(e) {
						if (e.code === 'needs_confirm')
							return confirmShell(e.message, function() { go(true); });
						fail(e);
					});
				};
				go(false);
			} }, _('Grant'));
		}

		function toolRowNode(client, tool) {
			var live = liveGrants(client, tool.name);
			var granted = live.length ? live.map(function(p) {
				return E('div', {}, [
					E('code', {}, (p.scopes || []).join(' ') || '*'), ' ',
					p.expires ? _('until %s').format(p.expires) : _('never expires'), ' ',
					data.writable ? E('button', { 'class': 'btn cbi-button-negative', 'data-act': 'revoke',
						'title': _('Removes the whole grant block: %s').format(p.tools.join(', ')),
						'click': function() { revoke(client, p.index, false); } }, _('Revoke')) : ''
				]);
			}) : E('em', {}, tool.ungated ? tool.why : _('not granted'));
			var control = '';
			if (data.writable && !tool.ungated) {
				var scope = E('input', { 'class': 'cbi-input-text', 'type': 'text', 'placeholder': '*', 'size': 14,
					'title': _('Scope: a glob such as wireless.* ; empty means every scope') });
				var dur = selectOf(DURATIONS.concat([ [ 'never', _('never') ] ]), '1h');
				control = [ scope, ' ', dur, ' ', grantRow(client, tool, scope, dur) ];
			}
			return [
				[ E('strong', {}, tool.title), E('br'), E('code', {}, tool.name) ],
				[ badge(tool.badge), (tool.notes || []).map(function(n) { return [ ' ', E('em', {}, noteLabel(n)) ]; }) ],
				granted, control
			];
		}

		function drawPermissions() {
			var clients = knownClients(data.st);
			if (!ui_.client || (clients.indexOf(ui_.client) < 0 && !ui_.typed))
				ui_.client = clients[0] || '';
			var client = ui_.client;
			var name = E('input', { 'class': 'cbi-input-text', 'type': 'text', 'value': client, 'list': 'openwrt-mcp-clients',
				'size': 20, 'placeholder': _('client name') });
			name.addEventListener('change', function() { ui_.client = name.value.trim(); ui_.typed = true; ui_.sig.permissions = null; draw(); });
			var presetDur = selectOf(DURATIONS.concat([ [ 'never', _('never') ] ]), '1h');
			var nodes = [
				E('p', { 'class': 'cbi-section-descr' },
					_('Grants are per client and win over nothing else: the deny floor and the audit log stay on whatever you grant. A grant to a root-shell tool asks for a second confirmation.')),
				E('div', {}, [ E('strong', {}, _('Client')), ' ', name,
					E('datalist', { 'id': 'openwrt-mcp-clients' }, clients.map(function(c) { return E('option', { 'value': c }); })) ])
			];
			if (data.writable && client)
				nodes.push(E('div', { 'style': 'margin:.5em 0' }, [
					_('Preset'), ' ', presetDur, ' ',
					E('button', { 'class': 'btn cbi-button-action', 'data-act': 'preset-readonly', 'click': function() {
						callGrantPreset(client, 'readonly', presetDur.value).then(check).then(refresh).catch(fail);
					} }, _('Read-only')), ' ',
					E('button', { 'class': 'btn cbi-button-action', 'data-act': 'preset-operator', 'click': function() {
						callGrantPreset(client, 'operator', presetDur.value).then(check).then(refresh).catch(fail);
					} }, _('Operator')), ' ',
					grantsFor(client).length ? E('button', { 'class': 'btn cbi-button-negative', 'data-act': 'revoke-all', 'click': function() {
						revoke(client, null, true);
					} }, _('Revoke every grant')) : ''
				]));
			if (client)
				data.tools.groups.forEach(function(g) {
					var n = g.tools.filter(function(t) { return liveGrants(client, t.name).length; }).length;
					nodes.push(E('h4', {}, _('%s — %d of %d granted').format(g.title, n, g.tools.length)));
					nodes.push(table([ _('Tool'), _('Risk'), _('Granted'), data.writable ? _('Grant') : '' ],
						g.tools.map(function(t) { return toolRowNode(client, t); }), ''));
				});
			else
				nodes.push(E('p', {}, E('em', {}, _('Type a client name to manage its grants.'))));
			panes.permissions.replaceChildren.apply(panes.permissions, nodes);
		}

		// ---- activity

		function drawActivity() {
			var rows = data.st.audit || [];
			var f = ui_.filter = ui_.filter || { client: '', tool: '', outcome: '', text: '' };
			var uniq = function(key) {
				var seen = {};
				rows.forEach(function(a) { if (a[key]) seen[a[key]] = true; });
				return Object.keys(seen).sort().map(function(v) { return [ v, v ]; });
			};
			var body = E('div', { 'id': 'openwrt-mcp-activity-rows' });
			function fill() {
				var shown = rows.slice().reverse().filter(function(a) {
					return (!f.client || a.client === f.client) && (!f.tool || a.tool === f.tool) &&
						(!f.outcome || a.outcome === f.outcome) &&
						(!f.text || JSON.stringify(a).toLowerCase().indexOf(f.text.toLowerCase()) >= 0);
				});
				var outcome = function(o) {
					return E('strong', { 'style': 'color:' + (o === 'OK' ? '#2a2' : (o === 'DENIED' ? '#c80' : '#c22')) }, o);
				};
				body.replaceChildren(table([ _('Time'), _('Client'), _('Tool'), _('Outcome'), _('Detail') ],
					shown.map(function(a) {
						return [ a.time, a.client, a.tool || '', outcome(a.outcome), a.error || a.summary || a.scope || '' ];
					}), _('Nothing matches.')));
			}
			var any = [ [ '', _('any') ] ];
			var text = E('input', { 'class': 'cbi-input-text', 'type': 'text', 'value': f.text, 'placeholder': _('search') });
			text.addEventListener('input', function() { f.text = text.value; fill(); });
			panes.activity.replaceChildren(
				E('div', {}, [
					selectOf(any.concat(uniq('client')), f.client, function(v) { f.client = v; fill(); }), ' ',
					selectOf(any.concat(uniq('tool')), f.tool, function(v) { f.tool = v; fill(); }), ' ',
					selectOf(any.concat(uniq('outcome')), f.outcome, function(v) { f.outcome = v; fill(); }), ' ', text
				]), body);
			fill();
		}

		// ---- settings

		function drawSettings() {
			var s = data.settings;
			var wait = E('input', { 'class': 'cbi-input-text', 'type': 'number', 'min': 0, 'max': s.wait_max, 'value': s.request_wait });
			var ttl = E('input', { 'class': 'cbi-input-text', 'type': 'number', 'min': s.ttl_min, 'max': s.ttl_max, 'value': s.request_ttl });
			panes.settings.replaceChildren(
				E('div', { 'class': 'cbi-value' }, [
					E('label', { 'class': 'cbi-value-title' }, _('Hold a denied call for (seconds)')),
					E('div', { 'class': 'cbi-value-field' }, [ wait, ' ',
						E('em', {}, _('0 to %d. 0 returns the denial at once, with no request.').format(s.wait_max)) ])
				]),
				E('div', { 'class': 'cbi-value' }, [
					E('label', { 'class': 'cbi-value-title' }, _('Keep a request open for (seconds)')),
					E('div', { 'class': 'cbi-value-field' }, [ ttl, ' ',
						E('em', {}, _('%d to %d.').format(s.ttl_min, s.ttl_max)) ])
				]),
				data.writable ? E('button', { 'class': 'btn cbi-button-save', 'data-act': 'save-settings', 'click': function() {
					callSetSettings(parseInt(wait.value, 10), parseInt(ttl.value, 10)).then(check).then(function() {
						ui.addNotification(null, E('p', {}, _('Saved. The daemon applies it to the next request.')), 'info');
						return refresh();
					}).catch(fail);
				} }, _('Save')) : E('em', {}, _('Your LuCI account cannot change settings.')),
				E('h3', {}, _('Second factor')),
				E('p', {}, (s.mfa_clients || []).length ?
					_('Enrolled for: %s. Enrolment stays on the command line (openwrt-mcp mfa).').format(s.mfa_clients.join(', ')) :
					_('No client is enrolled. Enrolment is done on the command line (openwrt-mcp mfa).')));
		}

		function draw() {
			drawRequests();
			var key = function(k, v) { var s = JSON.stringify(v); if (ui_.sig[k] === s) return false; ui_.sig[k] = s; return true; };
			if (key('overview', [ data.st.version, data.st.running, data.st.clients, data.st.policies, lastSeen(data.st) ])) drawOverview();
			if (key('permissions', [ data.st.policies, data.st.clients, data.writable, ui_.client ])) drawPermissions();
			if (key('activity', data.st.audit)) drawActivity();
			if (key('settings', data.settings)) drawSettings();
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
