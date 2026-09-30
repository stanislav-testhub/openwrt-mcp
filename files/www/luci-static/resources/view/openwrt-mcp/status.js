'use strict';
'require view';
'require fs';
'require poll';

// Read-only by design: pairing, grants and key authorisation stay on the command line, so
// nothing reachable over the network can widen what an agent may do. The page explains
// grants; it never issues them.

function table(titles, rows, empty) {
	var t = E('table', { 'class': 'table' }, [
		E('tr', { 'class': 'tr table-titles' }, titles.map(function(h) {
			return E('th', { 'class': 'th' }, h);
		}))
	]);
	if (!rows.length)
		t.appendChild(E('tr', { 'class': 'tr placeholder' }, [
			E('td', { 'class': 'td', 'colspan': titles.length }, E('em', empty))
		]));
	rows.forEach(function(r) {
		t.appendChild(E('tr', { 'class': 'tr' }, r.map(function(c) {
			return E('td', { 'class': 'td' }, c);
		})));
	});
	return t;
}

function load() {
	return fs.exec('/usr/bin/openwrt-mcp', [ 'status', '--json', '--audit', '40' ]).then(function(res) {
		if (res.code !== 0)
			throw new Error(res.stderr || ('exit ' + res.code));
		return JSON.parse(res.stdout);
	});
}

function render(st) {
	var outcome = function(o) {
		var color = o === 'OK' ? '#2a2' : (o === 'DENIED' ? '#c80' : '#c22');
		return E('strong', { 'style': 'color:' + color }, o);
	};

	return E('div', { 'id': 'openwrt-mcp-status' }, [
		E('div', { 'class': 'cbi-section' }, [
			E('h3', _('Daemon')),
			E('p', {}, [
				E('strong', {}, st.running ? _('Running') : _('Stopped')),
				' — openwrt-mcp ' + st.version + ', HTTP ' + st.listen +
				', stdio socket ' + (st.socket || _('disabled'))
			]),
			(st.pending || []).length ? E('p', { 'class': 'alert-message warning' },
				(st.pending || []).map(function(p) {
					return E('div', _('Change to %s by %s awaits confirmation; reverts automatically at %s')
						.format(p.configs.join(', '), p.client, p.deadline));
				})) : ''
		]),
		E('div', { 'class': 'cbi-section' }, [
			E('h3', _('Paired HTTP clients')),
			table([ _('Client'), _('Policies') ], (st.clients || []).map(function(c) {
				return [ c.name, String(c.policies) ];
			}), _('None. SSH-key (stdio) clients are listed in the audit log instead.'))
		]),
		E('div', { 'class': 'cbi-section' }, [
			E('h3', _('Standing policies')),
			table([ _('Client'), _('Tools'), _('Scopes'), _('Rate'), _('Expires') ], (st.policies || []).map(function(p) {
				return [
					p.client + (p.enabled ? '' : ' ' + _('(disabled)')),
					p.tools.join(', '),
					(p.scopes || []).join(' ') || '—',
					p.max_per_min + '/min',
					(p.expires || _('never')) + (p.expired ? ' ' + _('(EXPIRED)') : '')
				];
			}), _('No grants: every gated tool is denied.'))
		]),
		E('div', { 'class': 'cbi-section' }, [
			E('h3', _('Recent activity')),
			table([ _('Time'), _('Client'), _('Tool'), _('Outcome'), _('Detail') ], (st.audit || []).slice().reverse().map(function(a) {
				return [ a.time, a.client, a.tool || '', outcome(a.outcome), a.error || a.summary || a.scope || '' ];
			}), _('Nothing yet.'))
		]),
		E('p', { 'class': 'cbi-section-descr' },
			_('Grants are managed on the router: openwrt-mcp allow | revoke | policies | authorize-key.'))
	]);
}

return view.extend({
	load: load,

	render: function(st) {
		poll.add(function() {
			return load().then(function(fresh) {
				var node = document.getElementById('openwrt-mcp-status');
				if (node)
					node.replaceWith(render(fresh));
			});
		}, 15);
		return render(st);
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
