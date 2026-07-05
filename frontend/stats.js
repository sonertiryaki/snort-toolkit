const API = "";
const PAGE_SIZE = 50;
let currentPage = 0;
let currentVersion = "";
let currentQuery = "";

function fmtDate(iso) {
  if (!iso) return "–";
  return new Date(iso).toLocaleString("tr-TR", { dateStyle: "medium", timeStyle: "short" });
}

function escapeHtml(str) {
  return String(str ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

async function apiGet(path) {
  const res = await fetch(API + path);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

async function loadSummary() {
  const s = await apiGet("/api/status");

  document.getElementById("summaryCards").innerHTML = `
    <div class="stat-card"><div class="num">${s.total_rules ?? 0}</div><div class="lbl">Toplam kural (tüm sürümler)</div></div>
    <div class="stat-card"><div class="num">${(s.versions || []).filter(v => v.count > 0).length}</div><div class="lbl">Aktif sürüm sayısı</div></div>
  `;

  const lu = s.last_update_overall;
  const up = s.last_manual_upload;
  document.getElementById("lastUpdateBody").innerHTML = `
    <div class="rule-meta" style="flex-direction:column;gap:10px;align-items:flex-start;">
      <span><b>Son senkronizasyon:</b> ${lu ? `${fmtDate(lu.finished_at)} — ${escapeHtml(lu.source || "-")} (sürüm ${escapeHtml(lu.snort_version || "-")}, ${lu.rules_ingested} kural${lu.rules_skipped ? `, ${lu.rules_skipped} satır atlandı` : ""})` : "Henüz yapılmadı"}</span>
      <span><b>Son manuel dosya yükleme:</b> ${up ? `${escapeHtml(up.file_name)} — ${fmtDate(up.finished_at)} (sürüm ${escapeHtml(up.snort_version)}, ${up.rules_ingested} kural)` : "Henüz yapılmadı"}</span>
    </div>
  `;

  const versions = (s.versions || []).filter((v) => v.count > 0);
  document.querySelector("#versionTable tbody").innerHTML = versions.length
    ? versions
        .map(
          (v) => `<tr>
            <td><span class="version-pill">${escapeHtml(v.snort_version)}</span></td>
            <td>${v.count}</td>
            <td><a href="#" class="backlink" onclick="filterToVersion('${v.snort_version}');return false;">listeyi göster →</a></td>
          </tr>`
        )
        .join("")
    : `<tr><td colspan="3" style="color:var(--text-low);">Henüz kural yok</td></tr>`;

  document.getElementById("versionFilter").innerHTML =
    `<option value="">Tüm sürümler</option>` +
    versions.map((v) => `<option value="${v.snort_version}">${v.snort_version} (${v.count})</option>`).join("");
}

window.filterToVersion = function (version) {
  document.getElementById("versionFilter").value = version;
  currentVersion = version;
  currentPage = 0;
  loadRules();
  document.getElementById("rulesTable").scrollIntoView({ behavior: "smooth" });
};

async function loadRules() {
  const version = currentVersion;
  const offset = currentPage * PAGE_SIZE;

  if (!version) {
    const rules = await apiGet(`/api/rules?limit=${PAGE_SIZE}`);
    renderRows(rules.map((r) => ({ sid: r.sid, rev: r.rev, msg: r.msg, classtype: r.classtype, snort_version: r.snort_version })));
    document.getElementById("listCountTag").textContent = `${rules.length} kural gösteriliyor (tam sayfalama için bir sürüm seçin)`;
    document.getElementById("pageInfo").textContent = "";
    return;
  }

  const qs = new URLSearchParams({ snort_version: version, limit: PAGE_SIZE, offset });
  if (currentQuery) qs.set("q", currentQuery);
  const data = await apiGet(`/api/stats/rules?${qs.toString()}`);
  renderRows(data.items.map((r) => ({ ...r, snort_version: version })));
  document.getElementById("listCountTag").textContent = `${data.total} kuraldan ${offset + 1}-${Math.min(offset + PAGE_SIZE, data.total)} arası gösteriliyor`;
  document.getElementById("pageInfo").textContent = `Sayfa ${currentPage + 1} / ${Math.max(1, Math.ceil(data.total / PAGE_SIZE))}`;
}

function renderRows(rows) {
  document.getElementById("rulesTbody").innerHTML = rows.length
    ? rows
        .map(
          (r) => `<tr>
            <td>${r.sid}</td>
            <td>${r.rev ?? "-"}</td>
            <td>${escapeHtml(r.classtype || "-")}</td>
            <td style="color:var(--text-mid);">${escapeHtml(r.msg || "-")}</td>
          </tr>`
        )
        .join("")
    : `<tr><td colspan="4" style="color:var(--text-low);">Kural bulunamadı</td></tr>`;
}

document.getElementById("versionFilter").addEventListener("change", (e) => {
  currentVersion = e.target.value;
  currentPage = 0;
  loadRules();
});

let searchTimeout;
document.getElementById("searchBox").addEventListener("input", (e) => {
  clearTimeout(searchTimeout);
  searchTimeout = setTimeout(() => {
    currentQuery = e.target.value.trim();
    currentPage = 0;
    loadRules();
  }, 350);
});

document.getElementById("prevPage").addEventListener("click", () => {
  if (currentPage > 0) {
    currentPage--;
    loadRules();
  }
});
document.getElementById("nextPage").addEventListener("click", () => {
  currentPage++;
  loadRules();
});

loadSummary();
loadRules();
