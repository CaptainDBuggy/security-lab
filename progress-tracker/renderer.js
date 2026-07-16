let state = { ctfs: [] };

const $ = (sel) => document.querySelector(sel);

async function boot() {
  state = await window.api.load();
  render();
  wireStaticEvents();
}

function persist() {
  window.api.save(JSON.parse(JSON.stringify(state)));
}

function computeStats() {
  const ctfs = state.ctfs;
  const solved = ctfs.filter((c) => c.status === 'solved');
  const open = ctfs.filter((c) => c.status !== 'solved');
  const totalHints = ctfs.reduce((s, c) => s + (c.hints || 0), 0);
  const avgHints = solved.length ? (totalHints / solved.length) : 0;

  // exploits trained = distinct primitives that appear in >=1 solved CTF
  const trained = new Set();
  solved.forEach((c) => (c.primitives || []).forEach((p) => trained.add(p)));

  return {
    total: ctfs.length,
    solved: solved.length,
    open: open.length,
    totalHints,
    avgHints,
    trainedCount: trained.size,
  };
}

function exploitBreakdown() {
  // per primitive: total CTFs and solved CTFs
  const map = new Map();
  state.ctfs.forEach((c) => {
    (c.primitives || []).forEach((p) => {
      if (!map.has(p)) map.set(p, { total: 0, solved: 0 });
      const rec = map.get(p);
      rec.total += 1;
      if (c.status === 'solved') rec.solved += 1;
    });
  });
  return [...map.entries()]
    .map(([name, v]) => ({ name, ...v }))
    .sort((a, b) => b.solved - a.solved || b.total - a.total || a.name.localeCompare(b.name));
}

function render() {
  renderStats();
  renderExploits();
  renderTable();
}

function renderStats() {
  const s = computeStats();
  const cards = [
    { num: s.total, lbl: 'Total CTFs', cls: '' },
    { num: s.solved, lbl: 'Solved', cls: 'accent' },
    { num: s.open, lbl: 'Open', cls: 'warn' },
    { num: s.trainedCount, lbl: 'Exploits trained', cls: 'blue' },
    { num: s.totalHints, lbl: 'Hints used', cls: '' },
    { num: s.avgHints.toFixed(1), lbl: 'Avg hints / solved', cls: '' },
  ];
  $('#stats').innerHTML = cards
    .map(
      (c) => `<div class="stat"><div class="num ${c.cls}">${c.num}</div>
      <div class="lbl">${c.lbl}</div></div>`
    )
    .join('');
}

function renderExploits() {
  const rows = exploitBreakdown();
  const maxTotal = Math.max(1, ...rows.map((r) => r.total));
  $('#exploitsSub').textContent = `${rows.length} distinct exploit types`;
  $('#exploits').innerHTML = rows
    .map((r) => {
      const pct = Math.round((r.total / maxTotal) * 100);
      const solvedPct = r.total ? Math.round((r.solved / r.total) * 100) : 0;
      return `<div class="exp-row">
        <div class="exp-name">${escapeHtml(r.name)}</div>
        <div class="exp-bar" title="${r.solved}/${r.total} solved">
          <div class="exp-fill" style="width:${pct}%;opacity:${0.35 + 0.65 * (solvedPct / 100)}"></div>
        </div>
        <div class="exp-count">${r.solved}/${r.total}</div>
      </div>`;
    })
    .join('');
}

function renderTable() {
  const s = computeStats();
  $('#tableSub').textContent = `${s.solved} of ${s.total} cleared`;
  $('#ctfBody').innerHTML = state.ctfs
    .map((c) => {
      const prims = (c.primitives || [])
        .map((p) => `<span class="tag prim">${escapeHtml(p)}</span>`)
        .join('');
      const solved = c.status === 'solved';
      return `<tr data-id="${c.id}">
        <td>${c.id}</td>
        <td><strong>${escapeHtml(c.name)}</strong></td>
        <td><span class="tag">${escapeHtml(c.type)}</span></td>
        <td>${escapeHtml(c.difficulty)}</td>
        <td>${prims}</td>
        <td>
          <span class="hint-cell">
            <button class="step" data-act="hint-dec">−</button>
            <span class="hint-val">${c.hints || 0}</span>
            <button class="step" data-act="hint-inc">+</button>
          </span>
        </td>
        <td>
          <button class="status-btn ${solved ? 'solved' : 'open'}" data-act="toggle">
            ${solved ? '✅ solved' : '⬜ open'}
          </button>
        </td>
      </tr>`;
    })
    .join('');

  $('#ctfBody').querySelectorAll('tr').forEach((tr) => {
    const id = Number(tr.dataset.id);
    tr.querySelector('[data-act="hint-inc"]').onclick = () => changeHints(id, +1);
    tr.querySelector('[data-act="hint-dec"]').onclick = () => changeHints(id, -1);
    tr.querySelector('[data-act="toggle"]').onclick = () => toggleStatus(id);
  });
}

function changeHints(id, delta) {
  const c = state.ctfs.find((x) => x.id === id);
  if (!c) return;
  c.hints = Math.max(0, (c.hints || 0) + delta);
  persist();
  render();
}

function toggleStatus(id) {
  const c = state.ctfs.find((x) => x.id === id);
  if (!c) return;
  c.status = c.status === 'solved' ? 'open' : 'solved';
  persist();
  render();
}

function wireStaticEvents() {
  $('#addBtn').onclick = () => $('#addModal').classList.remove('hidden');
  $('#m_cancel').onclick = closeModal;
  $('#addModal').onclick = (e) => { if (e.target.id === 'addModal') closeModal(); };
  $('#m_save').onclick = addCtf;
  $('#resetBtn').onclick = async () => {
    if (confirm('Reset all progress to the seeded data? This overwrites your edits.')) {
      state = await window.api.reset();
      render();
    }
  };
}

function closeModal() {
  $('#addModal').classList.add('hidden');
  $('#m_name').value = '';
  $('#m_prims').value = '';
}

function addCtf() {
  const name = $('#m_name').value.trim();
  if (!name) { $('#m_name').focus(); return; }
  const prims = $('#m_prims').value.split(',').map((s) => s.trim()).filter(Boolean);
  const nextId = state.ctfs.reduce((m, c) => Math.max(m, c.id), 0) + 1;
  state.ctfs.push({
    id: nextId,
    name,
    type: $('#m_type').value,
    difficulty: $('#m_diff').value,
    status: 'open',
    hints: 0,
    primitives: prims,
  });
  persist();
  closeModal();
  render();
}

function escapeHtml(str) {
  return String(str).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

boot();
