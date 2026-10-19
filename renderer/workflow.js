// Renderer: alerts, finding details, POA&M and RBD, compliance policies, file import and data cleaning.
// Loaded after app.js and shares its helpers (el, panel, table, toast, renderView, settings, lineSvg).

const ALERT_KIND = { overdue: 'Overdue', upcoming: 'Due soon', noncompliant: 'Non-compliant', milestone: 'Milestone overdue', review: 'Risk review' };
const POLICY_KINDS = [['deadline', 'Deadline met'], ['severity', 'Severity threshold'], ['control', 'Control mapping']];
const STATUSES = ['open', 'in progress', 'closed'];

// Navigation state for the detail and POA&M screens.
let findingId = null;
let poamView = { kind: 'poam', selectedId: null, draft: null };

const blankItem = (kind) => ({ id: null, kind, template: 'custom', title: '', status: 'open', data: {}, vuln_ids: [], milestones: [] });
const shortTime = (iso) => (iso || '').replace('T', ' ').replace(/\.\d+Z$|Z$/, '').slice(0, 16);

function settingRow(title, description, control) {
  return el('div', { class: 'setting-row' },
    el('div', { class: 'info' }, el('div', {}, title), el('div', { class: 'muted' }, description)),
    control);
}

// ---------- Alerts ----------

async function refreshAlertBadge() {
  const badge = document.getElementById('alert-badge');
  if (!badge) return;
  try {
    const n = (await window.api.alerts()).length;
    badge.textContent = String(n);
    badge.hidden = n === 0;
  } catch (_) {
    badge.hidden = true;
  }
}

function openAlertTarget(a) {
  if (a.vuln_id) return openFinding(a.vuln_id);
  if (a.poam_id) return openPoam(a.poam_id);
}

function alertRow(a) {
  return el('div', { class: 'rule' },
    el('div', { class: 'info' },
      el('div', {}, a.title),
      el('div', { class: 'summary' }, `${ALERT_KIND[a.kind]} · ${a.detail}`)),
    a.vuln_id || a.poam_id ? el('button', { onclick: () => openAlertTarget(a) }, 'Open') : null,
    el('button', { onclick: async () => { await window.api.dismissAlert(a.key); renderView(); } }, 'Dismiss'));
}

async function renderAlerts(root) {
  const alerts = await window.api.alerts();
  refreshAlertBadge();
  root.append(
    el('h1', {}, 'Alerts'),
    el('p', { class: 'muted' }, `Upcoming deadlines (within ${settings.leadDays ?? 7} days), overdue findings, non-compliant findings and overdue milestones. Dismissing hides an alert for 7 days.`),
    panel(alerts.length ? `${alerts.length} active` : null,
      alerts.length ? alerts.map(alertRow) : el('div', { class: 'muted' }, 'No active alerts.')));
}

// Dashboard summary: alert counts and the trend of open, overdue and non-compliant findings.
function dashboardAlerts() {
  const host = el('div', {});
  (async () => {
    try {
      const [alerts, snaps] = await Promise.all([window.api.alerts(), window.api.snapshots(90)]);
      const counts = {};
      for (const a of alerts) counts[a.kind] = (counts[a.kind] || 0) + 1;
      host.replaceChildren(el('div', { class: 'two-col' },
        panel('Alerts',
          Object.keys(counts).length
            ? Object.entries(counts).map(([k, n]) => el('div', { class: 'setting-row' }, el('span', {}, ALERT_KIND[k]), el('span', {}, String(n))))
            : el('div', { class: 'muted' }, 'No active alerts.'),
          el('div', { class: 'toolbar' }, el('span', { class: 'spacer' }),
            el('button', { onclick: () => { currentView = 'alerts'; renderView(); } }, 'Open alerts'))),
        panel('Trend (last 90 days)', trendPanel(snaps))));
    } catch (err) {
      host.replaceChildren(el('div', { class: 'note' }, errorMessage(err)));
    }
  })();
  return host;
}

function trendPanel(snaps) {
  const series = { open_count: 'Open', overdue_count: 'Overdue', noncompliant_count: 'Non-compliant' };
  const host = el('div', {});
  const paint = (key) => {
    if (snaps.length < 2) {
      host.replaceChildren(el('div', { class: 'muted' }, 'The trend appears after two daily snapshots. A snapshot is taken at each start and every 30 minutes.'));
      return;
    }
    const data = snaps.map((s) => ({ label: s.snapshot_date, n: s[key] }));
    host.replaceChildren(el('div', { class: 'chart-wrap' }, lineSvg(data, () => {})));
  };
  const select = el('select', { onchange: (e) => paint(e.target.value) },
    Object.entries(series).map(([v, l]) => el('option', { value: v }, l)));
  paint('open_count');
  return el('div', {}, el('div', { class: 'toolbar' }, select), host);
}

// ---------- Finding details ----------

function openFinding(id) {
  findingId = id;
  currentView = 'finding';
  renderView();
}

async function setField(id, column, value) {
  try {
    await window.api.updateCell({ table: 'vulnerabilities', rowid: id, column, value });
    toast(`${column.replace(/_/g, ' ')} saved`);
    renderView();
  } catch (err) { toast(errorMessage(err), true); }
}

async function renderFinding(root) {
  if (!findingId) { currentView = 'data'; return renderView(); }
  const { finding: f, comments, history } = await window.api.finding(findingId);
  const [defs, poamsA, poamsB] = await Promise.all([
    window.api.columnDefs('vulnerabilities'),
    window.api.poamList('poam'),
    window.api.poamList('rbd'),
  ]);
  const linked = [...poamsA, ...poamsB].filter((p) => p.vuln_ids.includes(f.id));
  const statuses = STATUSES.includes(f.status) ? STATUSES : [...STATUSES, f.status];
  const attachments = attachmentsPanel({ vulnId: f.id });

  const detailRows = [
    ['CVE', f.cve], ['Title', f.title], ['Asset', f.asset], ['Severity', f.severity], ['CVSS', f.cvss],
    ['Source', f.source], ['Control', f.control_id], ['First seen', f.first_seen], ['Last seen', f.last_seen],
    ['Due date (computed)', f.due_date], ['Priority', f.priority_score], ['Timeline', f.timeline_bucket],
    ['Compliance', f.compliance_status],
    ...defs.filter((d) => !d.system).map((d) => [d.label, f[d.name]]),
  ].map(([k, v]) => [k, v ?? '']);

  const statusSel = el('select', { onchange: (e) => setField(f.id, 'status', e.target.value) },
    statuses.map((s) => el('option', { value: s, selected: s === f.status }, s)));

  const overrideIn = el('input', { type: 'date', value: f.deadline_override || '' });

  const commentBox = el('textarea', { placeholder: 'Add a comment…' });
  const author = settings.userName || 'user';

  const poamList = linked.length
    ? linked.map((p) => el('div', { class: 'rule' },
      el('div', { class: 'info' }, el('div', {}, p.title), el('div', { class: 'summary' }, `${p.kind.toUpperCase()} · ${p.status}`)),
      el('button', { onclick: () => openPoam(p.id) }, 'Open')))
    : el('div', { class: 'muted' }, 'Not linked to any POA&M or RBD.');

  root.append(
    el('div', { class: 'toolbar' },
      el('button', { onclick: () => { currentView = 'data'; renderView(); } }, '← Back to data grid'),
      el('span', { class: 'spacer' })),
    el('h1', {}, `Finding #${f.id}: ${f.title}`),
    attachments,
    el('div', { class: 'two-col' },
      panel('Details', table(['Field', 'Value'], detailRows)),
      el('div', {},
        panel('Status and deadline',
          el('div', { class: 'toolbar' }, el('label', { class: 'inline-field' }, el('span', {}, 'Status'), statusSel)),
          el('div', { class: 'toolbar' },
            el('label', { class: 'inline-field' }, el('span', {}, 'Deadline override'), overrideIn),
            el('button', { onclick: () => setField(f.id, 'deadline_override', overrideIn.value) }, 'Set deadline'),
            el('button', { onclick: () => setField(f.id, 'deadline_override', '') }, 'Use computed deadline')),
          el('p', { class: 'muted' }, `Due ${f.due_date || '—'} · ${f.deadline_override ? 'manual deadline' : 'computed deadline'}`)),
        panel('POA&M and RBD', poamList,
          el('div', { class: 'toolbar' }, el('span', { class: 'spacer' }),
            el('button', { onclick: () => openPoam(null, { vuln_ids: [f.id], title: `Remediate: ${f.title}` }) }, 'Create POA&M'))))),
    el('div', { class: 'two-col' },
      panel('Comments',
        comments.length
          ? comments.map((c) => el('div', { class: 'card' },
            el('div', { class: 'meta' }, `${c.author} · ${shortTime(c.created_at)}`),
            el('div', {}, c.body),
            el('div', { class: 'toolbar' }, el('span', { class: 'spacer' }),
              el('button', {
                class: 'danger',
                onclick: async () => { await window.api.deleteComment({ id: f.id, commentId: c.id }); renderView(); },
              }, 'Delete'))))
          : el('div', { class: 'muted' }, 'No comments yet.'),
        commentBox,
        el('div', { class: 'toolbar' }, el('span', { class: 'spacer' }),
          el('button', {
            class: 'primary',
            onclick: async () => {
              try {
                await window.api.addComment({ id: f.id, author, body: commentBox.value });
                renderView();
              } catch (err) { toast(errorMessage(err), true); }
            },
          }, 'Add comment'))),
      panel('History',
        history.length
          ? table(['When (UTC)', 'Field', 'From', 'To'],
            history.map((h) => [shortTime(h.changed_at), h.field, h.old_value ?? '', h.new_value ?? '']))
          : el('div', { class: 'muted' }, 'No changes recorded yet.')))
  );
}

// ---------- POA&M and RBD ----------

function openPoam(id, prefill = null) {
  poamView = { kind: poamView.kind, selectedId: id, draft: prefill ? { ...blankItem(poamView.kind), ...prefill } : null };
  currentView = 'poam';
  renderView();
}

async function saveMilestone(m) {
  try {
    poamView.draft = await window.api.milestoneSave(m);
    renderView();
  } catch (err) { toast(errorMessage(err), true); }
}

function milestonesPanel(draft) {
  const rows = (draft.milestones || []).map((m) => el('div', { class: 'rule' },
    el('input', {
      type: 'checkbox',
      checked: m.status === 'done',
      title: 'Done',
      onchange: (e) => saveMilestone({ ...m, poam_id: draft.id, status: e.target.checked ? 'done' : 'open' }),
    }),
    el('div', { class: 'info' },
      el('div', {}, m.title),
      el('div', { class: 'summary' }, `due ${m.due_date || '—'}${m.completed_at ? ` · completed ${m.completed_at}` : ''}`)),
    el('button', {
      class: 'danger',
      onclick: async () => {
        if (!window.confirm(`Delete milestone "${m.title}"?`)) return;
        poamView.draft = await window.api.milestoneDelete({ id: m.id, poamId: draft.id });
        renderView();
      },
    }, 'Delete')));

  const title = el('input', { placeholder: 'Milestone' });
  const due = el('input', { type: 'date' });
  if (!draft.id) {
    return panel('Milestones', el('div', { class: 'muted' }, 'Save the record to add milestones.'));
  }
  return panel('Milestones',
    rows.length ? rows : el('div', { class: 'muted' }, 'No milestones yet.'),
    el('div', { class: 'toolbar' }, title, due,
      el('button', {
        onclick: () => {
          if (!title.value.trim()) return toast('Enter a milestone name', true);
          saveMilestone({ poam_id: draft.id, title: title.value, due_date: due.value || null, status: 'open' });
        },
      }, 'Add milestone')));
}

async function poamEditor(draft, templates) {
  const fields = await window.api.poamFields({ template: draft.template, kind: draft.kind });
  const inputs = {};
  const control = (f) => {
    const current = draft.data[f.key] ?? '';
    if (f.type === 'select') {
      return el('select', { id: `f-${f.key}` }, [el('option', { value: '' }, '—'),
        ...f.options.map((o) => el('option', { value: o, selected: o === current }, o))]);
    }
    if (f.type === 'long') return el('textarea', { id: `f-${f.key}` }, current);
    return el('input', { id: `f-${f.key}`, type: f.type === 'date' ? 'date' : 'text', value: current });
  };
  for (const f of fields) inputs[f.key] = control(f);

  const collect = () => Object.fromEntries(Object.entries(inputs).map(([k, c]) => [k, c.value.trim() || null]));

  const titleIn = el('input', { value: draft.title, placeholder: 'Title' });
  const statusSel = el('select', {}, STATUSES.map((s) => el('option', { value: s, selected: s === draft.status }, s)));
  const templateSel = el('select', {
    onchange: (e) => {
      draft.data = collect();
      draft.template = e.target.value;
      renderView();
    },
  }, templates.map((t) => el('option', { value: t.id, selected: t.id === draft.template }, t.name)));
  const vulnIn = el('input', { value: draft.vuln_ids.join(', '), placeholder: 'Finding IDs, e.g. 12, 40' });

  const save = async () => {
    try {
      const saved = await window.api.poamSave({
        id: draft.id,
        kind: draft.kind,
        template: templateSel.value,
        title: titleIn.value,
        status: statusSel.value,
        data: collect(),
        vuln_ids: vulnIn.value.split(',').map((s) => s.trim()).filter(Boolean).map(Number),
      });
      poamView.selectedId = saved.id;
      poamView.draft = saved;
      toast('Saved');
      renderView();
    } catch (err) { toast(errorMessage(err), true); }
  };

  const remove = async () => {
    if (!draft.id || !window.confirm(`Delete "${draft.title}" and its milestones?`)) return;
    await window.api.poamDelete(draft.id);
    poamView = { kind: draft.kind, selectedId: null, draft: null };
    renderView();
  };

  return [
    panel(draft.id ? `Edit #${draft.id}` : 'New record',
      el('div', { class: 'form-grid' },
        el('label', {}, 'Title', titleIn),
        el('label', {}, 'Template', templateSel),
        el('label', {}, 'Status', statusSel),
        el('label', {}, 'Linked finding IDs', vulnIn)),
      el('div', { class: 'form-grid' },
        fields.map((f) => el('label', {}, f.label, inputs[f.key]))),
      el('div', { class: 'toolbar' },
        draft.id ? el('button', { class: 'danger', onclick: remove }, 'Delete') : null,
        el('span', { class: 'spacer' }),
        el('button', { class: 'primary', onclick: save }, 'Save'))),
    milestonesPanel(draft),
  ];
}

async function renderPoam(root) {
  const [items, templates] = await Promise.all([window.api.poamList(poamView.kind), window.api.poamTemplates()]);
  if (poamView.selectedId && !poamView.draft) poamView.draft = await window.api.poamGet(poamView.selectedId);
  const templateName = (id) => templates.find((t) => t.id === id)?.name ?? id;
  const kindLabel = poamView.kind === 'poam' ? 'POA&M' : 'RBD';

  const kindBar = el('div', { class: 'toolbar' },
    ['poam', 'rbd'].map((k) => el('button', {
      class: poamView.kind === k ? 'primary' : '',
      onclick: () => { poamView = { kind: k, selectedId: null, draft: null }; renderView(); },
    }, k === 'poam' ? 'POA&M' : 'RBD')),
    el('span', { class: 'spacer' }),
    el('button', { onclick: () => { poamView = { kind: poamView.kind, selectedId: null, draft: blankItem(poamView.kind) }; renderView(); } }, 'New'));

  const exportTemplate = el('select', {}, templates.map((t) => el('option', { value: t.id }, t.name)));
  const exportBar = el('div', { class: 'toolbar' },
    el('span', { class: 'muted' }, 'Export template'), exportTemplate,
    el('button', {
      onclick: async () => {
        const res = await window.api.poamExport({ kind: poamView.kind, template: exportTemplate.value });
        if (res) toast(`Exported ${kindLabel} records`);
      },
    }, 'Export CSV'),
    el('button', {
      onclick: async () => {
        const res = await window.api.poamExportXlsx({ kind: poamView.kind, template: exportTemplate.value });
        if (res) toast(`Exported ${kindLabel} workbook`);
      },
    }, 'Export Excel'));

  const list = panel(`${kindLabel} records`,
    items.length
      ? items.map((it) => el('div', { class: 'rule' },
        el('div', { class: 'info' },
          el('div', {}, it.title),
          el('div', { class: 'summary' }, `${templateName(it.template)} · ${it.status} · ${it.vuln_ids.length} linked finding(s)`)),
        el('button', { onclick: () => openPoam(it.id) }, 'Edit')))
      : el('div', { class: 'muted' }, `No ${kindLabel} records yet. Create one, or use "Create POA&M" on a finding.`));

  const editor = poamView.draft ? await poamEditor(poamView.draft, templates) : [];

  root.append(
    el('h1', {}, 'POA&M and RBD'),
    el('p', { class: 'muted' }, 'Template field sets are approximations of the common formats. Check them against your official template before submitting.'),
    kindBar, exportBar, list, ...editor);
}

// ---------- Compliance policies (shown on the Rules view) ----------

async function policiesPanel() {
  const draft = (await window.api.listPolicies()).map((p) => ({ ...p }));
  const rows = el('div', {});
  const paint = () => rows.replaceChildren(...draft.map((p, i) => policyRow(p, i, draft, paint)));
  paint();
  const save = async () => {
    try {
      await window.api.savePolicies(draft.map((p) => ({ name: p.name, kind: p.kind, params: p.params, enabled: p.enabled })));
      toast('Compliance policies saved');
      renderView();
    } catch (err) { toast(errorMessage(err), true); }
  };
  return panel('Compliance policies',
    el('p', { class: 'muted' }, 'A finding is Non-compliant when any enabled policy fails for it. Closed findings are not evaluated.'),
    rows,
    el('div', { class: 'toolbar' },
      el('button', { onclick: () => { draft.push({ name: 'New policy', kind: 'deadline', params: {}, enabled: true }); paint(); } }, '+ Policy'),
      el('span', { class: 'spacer' }),
      el('button', { class: 'primary', onclick: save }, 'Save policies')));
}

function policyRow(p, i, draft, paint) {
  if (p.kind === 'severity' && !p.params.threshold) p.params.threshold = 'High';
  if (p.kind === 'control' && !p.params.controls) p.params.controls = [];
  const kindSel = el('select', {
    onchange: (e) => { p.kind = e.target.value; p.params = {}; paint(); },
  }, POLICY_KINDS.map(([v, l]) => el('option', { value: v, selected: v === p.kind }, l)));
  const nameIn = el('input', { value: p.name, onchange: (e) => { p.name = e.target.value; } });
  let param;
  if (p.kind === 'severity') {
    param = el('select', { onchange: (e) => { p.params.threshold = e.target.value; } },
      ['Critical', 'High', 'Medium', 'Low'].map((s) => el('option', { value: s, selected: s === p.params.threshold }, `${s} and above`)));
  } else if (p.kind === 'control') {
    param = el('input', {
      placeholder: 'AC-2, SI-2',
      value: p.params.controls.join(', '),
      onchange: (e) => { p.params.controls = e.target.value.split(',').map((s) => s.trim()).filter(Boolean); },
    });
  } else {
    param = el('span', { class: 'muted' }, 'Open findings past their deadline fail');
  }
  return el('div', { class: 'rule' },
    el('input', { type: 'checkbox', checked: p.enabled, title: 'Enabled', onchange: (e) => { p.enabled = e.target.checked; } }),
    nameIn, kindSel, param,
    el('button', { class: 'danger', onclick: () => { draft.splice(i, 1); paint(); } }, 'Remove'));
}

// ---------- Settings: alerts and profile ----------

function alertSettingsPanel() {
  return panel('Alerts and profile',
    settingRow('In-app alerts', 'Show alerts in the Alerts view and on the dashboard.',
      el('input', { type: 'checkbox', checked: settings.alertsEnabled !== false, onchange: (e) => changeSetting('alertsEnabled', e.target.checked) })),
    settingRow('Desktop notifications', 'Notify when new alerts appear (checked at start and every 30 minutes).',
      el('input', { type: 'checkbox', checked: settings.desktopNotifications !== false, onchange: (e) => changeSetting('desktopNotifications', e.target.checked) })),
    settingRow('Upcoming deadline window', 'Days ahead to flag a deadline as due soon.',
      el('input', { type: 'number', min: '0', max: '90', value: settings.leadDays ?? 7, onchange: (e) => changeSetting('leadDays', Math.max(0, Number(e.target.value) || 0)) })),
    settingRow('Your name', 'Shown as the author of comments.',
      el('input', { value: settings.userName || '', placeholder: 'Your name', onchange: (e) => changeSetting('userName', e.target.value.trim()) })));
}

// ---------- Settings: where data lives (local or team server) and sign-in ----------

function teamPanel() {
  const host = el('div', {});
  const paint = async () => {
    const st = await window.api.authStatus();
    const modeSel = el('select', { onchange: (e) => changeSetting('mode', e.target.value) },
      [['local', 'Local (this computer)'], ['team', 'Team server']]
        .map(([v, l]) => el('option', { value: v, selected: st.mode === v }, l)));
    const serverIn = el('input', { value: st.serverUrl, placeholder: 'https://server-name:8443', onchange: (e) => changeSetting('serverUrl', e.target.value.trim()) });
    const caIn = el('input', { value: st.caFile, placeholder: 'Certificate file, for self-signed servers', onchange: (e) => changeSetting('caFile', e.target.value.trim()) });
    const userIn = el('input', { placeholder: 'Username' });
    const passIn = el('input', { type: 'password', placeholder: 'Password' });

    const signIn = async () => {
      const values = { username: userIn.value.trim(), password: passIn.value };
      try {
        if (serverIn.value.trim() !== (settings.serverUrl || '')) await changeSetting('serverUrl', serverIn.value.trim());
        if (caIn.value.trim() !== (settings.caFile || '')) await changeSetting('caFile', caIn.value.trim());
        const who = await window.api.authLogin(values);
        toast(`Signed in as ${who.username} (${who.role})`);
        renderView();
      } catch (err) { toast(errorMessage(err), true); }
    };

    host.replaceChildren(panel('Data storage and team sign-in',
      el('p', { class: 'muted' }, 'Local keeps everything on this computer. Team mode stores data on the team server. Your settings stay on this computer. Every team action is checked against your role and logged.'),
      el('div', { class: 'form-grid' },
        el('label', {}, 'Storage', modeSel),
        el('label', {}, 'Team server address', serverIn),
        el('label', {}, 'Server certificate file', caIn)),
      st.signedIn
        ? el('div', { class: 'toolbar' },
          el('span', {}, `Signed in as ${st.username} (${st.role})`), el('span', { class: 'spacer' }),
          el('button', { onclick: async () => { await window.api.authLogout(); renderView(); } }, 'Sign out'))
        : el('div', { class: 'form-grid' },
          el('label', {}, 'Username', userIn),
          el('label', {}, 'Password', passIn),
          el('div', { class: 'toolbar' }, el('span', { class: 'spacer' }), el('button', { class: 'primary', onclick: signIn }, 'Sign in')))));
  };
  paint().catch((err) => host.replaceChildren(el('div', { class: 'note' }, errorMessage(err))));
  return host;
}

// ---------- Import and cleaning ----------

async function renderImportFiles(root) {
  const result = el('div', { class: 'muted' });
  const show = (text) => result.replaceChildren(text);

  const source = el('input', { value: 'import', placeholder: 'source name' });
  const dedupe = el('input', { type: 'checkbox' });
  const prune = el('input', { type: 'checkbox' });
  const sheet = el('input', { placeholder: 'first sheet' });
  const itemsPath = el('input', { placeholder: 'JSON only, e.g. findings (blank = top-level array)' });
  const presetSel = el('select', {}, el('option', { value: '' }, 'Generic (any column names)'));
  window.api.importPresets().then((list) => {
    presetSel.append(...list.map((p) => el('option', { value: p.id }, p.label)));
  }).catch(() => {});
  const options = () => ({
    preset: presetSel.value || undefined,
    source: source.value.trim() || 'import',
    dedupe: dedupe.checked,
    pruneSource: prune.checked,
    sheet: sheet.value.trim() || undefined,
    itemsPath: itemsPath.value.trim() || undefined,
  });

  const chooseBtn = el('button', {
    class: 'primary',
    onclick: async () => {
      try {
        const res = await window.api.importFile(options());
        if (!res) return;
        show(`${res.file}: ${res.parsed} rows, ${res.written} written, ${res.skipped} skipped (no title), ${res.deduped} duplicates removed, ${res.pruned} stale rows from this source removed.`);
        toast('Import complete');
      } catch (err) { toast(errorMessage(err), true); }
    },
  }, 'Choose file (CSV, JSON or Excel)…');

  const apiFields = {
    url: el('input', { placeholder: 'https://scanner.example.com/api/findings' }),
    headers: el('textarea', { placeholder: '{"Authorization": "Bearer …"}' }),
    mapping: el('textarea', {}, JSON.stringify({ title: 'name', cve: 'cve_id', asset: 'host.hostname', severity: 'severity', cvss: 'cvss', first_seen: 'discovered' }, null, 2)),
    itemsPath: el('input', { placeholder: 'data.findings  (blank = response is the array)' }),
  };
  const pullBtn = el('button', {
    class: 'primary',
    onclick: async () => {
      let headers;
      let mapping;
      try {
        headers = apiFields.headers.value.trim() ? JSON.parse(apiFields.headers.value) : {};
        mapping = apiFields.mapping.value.trim() ? JSON.parse(apiFields.mapping.value) : {};
      } catch (err) { return toast(`Invalid JSON: ${err.message}`, true); }
      show('Pulling…');
      try {
        const res = await window.api.importApi({
          url: apiFields.url.value.trim(),
          source: source.value.trim() || 'api',
          itemsPath: apiFields.itemsPath.value.trim(),
          headers,
          mapping,
          dedupe: dedupe.checked,
          pruneSource: prune.checked,
        });
        show(`${res.fetched} items fetched, ${res.written} written, ${res.skipped} skipped (no title), ${res.deduped} duplicates removed, ${res.pruned} stale rows removed.`);
        toast('API pull complete');
      } catch (err) {
        show('');
        toast(errorMessage(err), true);
      }
    },
  }, 'Pull from API');

  const days = el('input', { type: 'number', min: '1', value: '90' });
  const preview = el('div', { class: 'muted' }, 'Press Preview to count what would be removed.');
  const refreshPreview = async () => {
    const p = await window.api.cleaningPreview(Number(days.value) || 90);
    preview.replaceChildren(`${p.duplicateRows} duplicate row(s) in ${p.duplicateGroups} group(s). ${p.staleRows} finding(s) not seen in the last ${Number(days.value) || 90} days.`);
  };

  root.append(
    el('h1', {}, 'Import'),
    panel('Import a file',
      el('p', { class: 'muted' }, 'CSV, JSON or Excel (.xlsx). Columns are matched by name; unknown columns become custom fields. Re-importing the same source + CVE + asset updates the row.'),
      el('div', { class: 'form-grid' },
        el('label', {}, 'Source name', source),
        el('label', {}, 'Excel sheet', sheet),
        el('label', {}, 'Scanner preset', presetSel),
        el('label', {}, 'JSON items path', itemsPath)),
      el('div', { class: 'toolbar' },
        el('label', { class: 'inline-check' }, dedupe, 'Remove duplicates after import'),
        el('label', { class: 'inline-check' }, prune, 'Drop rows from this source that the file no longer has')),
      el('div', { class: 'toolbar' }, el('span', { class: 'spacer' }), chooseBtn),
      result),
    panel('HTTP(S) JSON API', el('div', { class: 'form-grid' },
      el('label', {}, 'URL', apiFields.url),
      el('label', {}, 'Items path', apiFields.itemsPath),
      el('label', {}, 'Headers (JSON)', apiFields.headers)),
      el('label', { class: 'field' }, 'Field mapping (JSON: app field → response path)', apiFields.mapping),
      el('div', { class: 'toolbar' }, el('span', { class: 'spacer' }), pullBtn)),
    panel('Clean up data',
      el('p', { class: 'muted' }, 'Removing is permanent. Preview first.'),
      el('div', { class: 'toolbar' },
        el('label', { class: 'inline-field' }, el('span', {}, 'Stale after (days)'), days),
        el('button', { onclick: refreshPreview }, 'Preview')),
      preview,
      el('div', { class: 'toolbar' },
        el('button', {
          onclick: async () => {
            if (!window.confirm('Remove duplicate findings? The most recently seen row in each group is kept.')) return;
            const n = await window.api.dedupe();
            toast(`Removed ${n} duplicate(s)`);
            refreshPreview();
          },
        }, 'Remove duplicates'),
        el('button', {
          class: 'danger',
          onclick: async () => {
            const d = Number(days.value) || 90;
            if (!window.confirm(`Permanently remove every finding not seen in the last ${d} days, including closed ones?`)) return;
            const n = await window.api.removeStale(d);
            toast(`Removed ${n} stale finding(s)`);
            refreshPreview();
          },
        }, 'Remove stale findings'))));
}

// ---------- Helpers for panels that load data first ----------

// Returns a host element straight away and fills it when the data arrives.
function asyncHost(build) {
  const host = el('div', {});
  build()
    .then((node) => host.replaceChildren(node))
    .catch((err) => host.replaceChildren(el('div', { class: 'note' }, errorMessage(err))));
  return host;
}

// ---------- Dashboard: remediation metrics and threat intelligence ----------

function dashboardMetrics() {
  return asyncHost(async () => {
    const [m, intel] = await Promise.all([window.api.remediationMetrics(), window.api.intelStatus()]);
    return el('div', { class: 'two-col' },
      panel('Remediation metrics',
        el('p', {}, `Overdue: ${m.overdueTotal} of ${m.openTotal} open findings (${m.overduePercent}%). Closed so far: ${m.closedTotal}.`),
        table(['Severity', 'Closed', 'Average days to fix'], m.bySeverity.map((s) => [s.severity, s.closed, s.avgDays ?? '—'])),
        el('h2', {}, 'Open findings by age'),
        table(['Age', 'Open'], m.aging.map((a) => [a.label, a.count]))),
      panel('Threat intelligence',
        el('p', { class: 'muted' }, `CISA known-exploited list: ${intel.kev} entries. EPSS scores: ${intel.epss}.`),
        el('p', {}, `Open findings on the known-exploited list: ${intel.exploitedOpen}. These are raised in priority automatically.`),
        el('div', { class: 'toolbar' }, el('span', { class: 'spacer' }),
          el('button', {
            class: 'primary',
            onclick: async () => {
              try {
                const r = await window.api.intelRefresh();
                toast(`Updated ${r.kev} known-exploited entries and ${r.epss} EPSS scores`);
                renderView();
              } catch (err) { toast(errorMessage(err), true); }
            },
          }, 'Refresh threat feeds'))));
  });
}

// ---------- Data grid: saved views ----------

let savedViewHost = null;

function savedViewsBar() {
  savedViewHost = el('div', { class: 'toolbar' });
  return savedViewHost;
}

async function paintSavedViews() {
  if (!savedViewHost) return;
  const views = await window.api.viewsList(grid.table);
  const pick = el('select', {
    onchange: (e) => {
      const v = views.find((x) => String(x.id) === e.target.value);
      if (!v) return;
      grid.filters = { ...(v.config.filters || {}) };
      grid.sortBy = v.config.sortBy || null;
      grid.sortDir = v.config.sortDir || 'asc';
      refreshGrid(true);
    },
  }, [el('option', { value: '' }, 'Saved views…'), ...views.map((v) => el('option', { value: String(v.id) }, v.name))]);
  const name = el('input', { placeholder: 'Name this view' });
  savedViewHost.replaceChildren(
    pick,
    name,
    el('button', {
      onclick: async () => {
        const n = name.value.trim();
        if (!n) return toast('Name the view first', true);
        try {
          await window.api.viewsSave({ name: n, table: grid.table, config: { filters: grid.filters, sortBy: grid.sortBy, sortDir: grid.sortDir } });
          toast(`Saved view "${n}"`);
          paintSavedViews();
        } catch (err) { toast(errorMessage(err), true); }
      },
    }, 'Save view'),
    el('button', {
      class: 'danger',
      onclick: async () => {
        const v = views.find((x) => String(x.id) === pick.value);
        if (!v) return toast('Pick a saved view to delete', true);
        if (!window.confirm(`Delete saved view "${v.name}"?`)) return;
        await window.api.viewsDelete(v.id);
        paintSavedViews();
      },
    }, 'Delete view'));
}

// ---------- Finding page: attachments (evidence) ----------

function attachmentsPanel({ vulnId = null, poamId = null }) {
  return asyncHost(async () => {
    const list = await window.api.attachmentsList(vulnId ? { vulnId } : { poamId });
    const rows = list.map((a) => el('div', { class: 'rule' },
      el('div', { class: 'info' },
        el('div', {}, a.filename),
        el('div', { class: 'summary' }, `${Math.max(1, Math.round(a.size / 1024))} KB · ${a.uploaded_by || 'unknown'} · ${shortTime(a.created_at)}`)),
      el('button', {
        onclick: async () => {
          try {
            if (await window.api.attachmentsSave(a.id)) toast('File saved');
          } catch (err) { toast(errorMessage(err), true); }
        },
      }, 'Save'),
      el('button', {
        class: 'danger',
        onclick: async () => {
          if (!window.confirm(`Delete ${a.filename}?`)) return;
          await window.api.attachmentsDelete(a.id);
          renderView();
        },
      }, 'Delete')));
    const attach = el('button', {
      class: 'primary',
      onclick: async () => {
        try {
          const file = await window.api.attachmentsPick();
          if (!file) return;
          await window.api.attachmentsAdd({ vulnId, poamId, filename: file.filename, mime: file.mime, content: file.content, uploadedBy: settings.userName || 'user' });
          toast(`Attached ${file.filename}`);
          renderView();
        } catch (err) { toast(errorMessage(err), true); }
      },
    }, 'Attach file…');
    return panel('Attachments (evidence)',
      rows.length ? rows : el('div', { class: 'muted' }, 'No attachments yet. Up to 10 MB per file.'),
      el('div', { class: 'toolbar' }, el('span', { class: 'spacer' }), attach));
  });
}

// ---------- Assets: owner, criticality and business impact ----------

async function renderAssets(root) {
  const assets = await window.api.assetsList();
  const name = el('input', { placeholder: 'Asset name, as it appears in the asset column' });
  const owner = el('input', { placeholder: 'Owner' });
  const criticality = el('select', {}, ['', 'Low', 'Medium', 'High', 'Critical'].map((c) => el('option', { value: c }, c || 'Not set')));
  const environment = el('input', { placeholder: 'e.g. production' });
  const businessUnit = el('input', { placeholder: 'Business unit' });

  const save = async () => {
    try {
      await window.api.assetsSave({
        name: name.value, owner: owner.value, criticality: criticality.value || null,
        environment: environment.value, business_unit: businessUnit.value,
      });
      toast('Asset saved. Priorities updated.');
      renderView();
    } catch (err) { toast(errorMessage(err), true); }
  };

  const rows = assets.map((a) => el('div', { class: 'rule' },
    el('div', { class: 'info' },
      el('div', {}, a.name),
      el('div', { class: 'summary' }, `${a.owner || 'no owner'} · ${a.criticality || 'criticality not set'} · ${a.environment || '—'} · ${a.business_unit || '—'}`)),
    el('button', {
      onclick: () => {
        name.value = a.name; owner.value = a.owner || ''; criticality.value = a.criticality || '';
        environment.value = a.environment || ''; businessUnit.value = a.business_unit || '';
      },
    }, 'Edit'),
    el('button', {
      class: 'danger',
      onclick: async () => {
        if (!window.confirm(`Remove asset "${a.name}"? Its findings keep their priorities without the criticality bonus.`)) return;
        await window.api.assetsDelete(a.name);
        renderView();
      },
    }, 'Delete')));

  root.append(
    el('h1', {}, 'Assets'),
    el('p', { class: 'muted' }, 'Owner and criticality for each asset. Critical and High assets raise the priority of their findings.'),
    panel('Asset inventory', rows.length ? rows : el('div', { class: 'muted' }, 'No assets recorded yet.')),
    panel('Add or update an asset',
      el('div', { class: 'form-grid' },
        el('label', {}, 'Asset', name), el('label', {}, 'Owner', owner),
        el('label', {}, 'Criticality', criticality), el('label', {}, 'Environment', environment),
        el('label', {}, 'Business unit', businessUnit)),
      el('div', { class: 'toolbar' }, el('span', { class: 'spacer' }), el('button', { class: 'primary', onclick: save }, 'Save asset'))));
}

// ---------- Settings: backups and team administration ----------

function backupsPanel() {
  return asyncHost(async () => {
    const st = await window.api.authStatus();
    if (st.mode === 'team') {
      return panel('Backups',
        el('p', { class: 'muted' }, 'The team server takes a verified backup every day and keeps the 14 most recent. An administrator restores from the server: node server/server.js restore --from <file>.'));
    }
    const items = await window.api.backupList();
    return panel('Backups',
      el('p', { class: 'muted' }, 'A verified copy of your database is taken each day, and the 14 most recent are kept. Restoring replaces your current data, and a copy of the current data is kept first.'),
      items.length
        ? items.map((b) => el('div', { class: 'rule' },
          el('div', { class: 'info' }, el('div', {}, b.name),
            el('div', { class: 'summary' }, `${Math.max(1, Math.round(b.bytes / 1024))} KB · ${shortTime(b.created)} UTC`)),
          el('button', {
            class: 'danger',
            onclick: async () => {
              if (!window.confirm(`Restore ${b.name}? Your current data is replaced. A copy of it is kept.`)) return;
              try {
                await window.api.backupRestore(b.name);
                toast('Restored from backup');
                renderView();
              } catch (err) { toast(errorMessage(err), true); }
            },
          }, 'Restore')))
        : el('div', { class: 'muted' }, 'No backups yet.'),
      el('div', { class: 'toolbar' }, el('span', { class: 'spacer' }),
        el('button', {
          class: 'primary',
          onclick: async () => {
            try {
              const r = await window.api.backupCreate();
              toast(`Backup ${r.name} created`);
              renderView();
            } catch (err) { toast(errorMessage(err), true); }
          },
        }, 'Back up now')));
  });
}

function teamAdminPanel() {
  return asyncHost(async () => {
    const st = await window.api.authStatus();
    if (st.mode !== 'team' || !st.signedIn || st.role !== 'admin') return el('span', {});
    const [accounts, audit] = await Promise.all([window.api.usersList(), window.api.auditList(50)]);
    const username = el('input', { placeholder: 'Username' });
    const role = el('select', {}, ['viewer', 'editor', 'admin'].map((r) => el('option', { value: r }, r)));
    const password = el('input', { type: 'password', placeholder: 'Starting password (12 to 256 characters)' });

    const rows = accounts.map((u) => el('div', { class: 'rule' },
      el('div', { class: 'info' }, el('div', {}, u.username),
        el('div', { class: 'summary' }, `${u.disabled ? 'Disabled' : 'Active'} · created ${shortTime(u.created_at)} UTC`)),
      el('select', {
        onchange: async (e) => {
          try { await window.api.usersSetRole({ username: u.username, role: e.target.value }); renderView(); }
          catch (err) { toast(errorMessage(err), true); renderView(); }
        },
      }, ['viewer', 'editor', 'admin'].map((r) => el('option', { value: r, selected: r === u.role }, r))),
      el('button', {
        onclick: async () => {
          try { await window.api.usersSetDisabled({ username: u.username, disabled: !u.disabled }); renderView(); }
          catch (err) { toast(errorMessage(err), true); }
        },
      }, u.disabled ? 'Enable' : 'Disable')));

    return panel('Team accounts (admin)',
      rows,
      el('h2', {}, 'Add an account'),
      el('div', { class: 'form-grid' },
        el('label', {}, 'Username', username), el('label', {}, 'Role', role), el('label', {}, 'Starting password', password)),
      el('div', { class: 'toolbar' }, el('span', { class: 'spacer' }),
        el('button', {
          class: 'primary',
          onclick: async () => {
            try {
              await window.api.usersCreate({ username: username.value.trim(), role: role.value, password: password.value });
              toast('Account created. Share the starting password securely.');
              renderView();
            } catch (err) { toast(errorMessage(err), true); }
          },
        }, 'Create account')),
      el('h2', {}, 'Recent activity (audit log)'),
      audit.length
        ? table(['When (UTC)', 'User', 'Action', 'Outcome'], audit.map((a) => [shortTime(a.at), a.username || '', a.channel || '', a.outcome]))
        : el('div', { class: 'muted' }, 'No activity yet.'));
  });
}

// ---------- Keyboard shortcuts: Ctrl or Cmd with 1 to 9 switches views ----------

const SHORTCUT_VIEWS = ['dashboard', 'data', 'charts', 'alerts', 'poam', 'assets', 'rules', 'import', 'settings'];

document.addEventListener('keydown', (e) => {
  if (!(e.metaKey || e.ctrlKey) || e.altKey || e.shiftKey) return;
  const n = Number(e.key);
  if (Number.isInteger(n) && n >= 1 && n <= SHORTCUT_VIEWS.length) {
    e.preventDefault();
    currentView = SHORTCUT_VIEWS[n - 1];
    editingRule = null;
    renderView();
  }
});

// ---------- Register views and start the badge ----------

Object.assign(views, {
  alerts: renderAlerts,
  finding: renderFinding,
  poam: renderPoam,
  import: renderImportFiles,
  assets: renderAssets,
});

refreshAlertBadge();
setInterval(refreshAlertBadge, 60 * 1000);
