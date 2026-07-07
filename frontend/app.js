const API = ""; // aynı origin üzerinden servis edildiği için boş bırakıldı

const els = {
  sidInput: document.getElementById("sidInput"),
  versionSelect: document.getElementById("versionSelect"),
  runBtn: document.getElementById("runBtn"),
  syncOfflineBtn: document.getElementById("syncOfflineBtn"),
  syncAllBtn: document.getElementById("syncAllBtn"),
  syncSourceSelect: document.getElementById("syncSourceSelect"),
  syncOneBtn: document.getElementById("syncOneBtn"),
  listBtn: document.getElementById("listBtn"),
  fileInput: document.getElementById("fileInput"),
  uploadVersionSelect: document.getElementById("uploadVersionSelect"),
  uploadBtn: document.getElementById("uploadBtn"),
  stateMsg: document.getElementById("stateMsg"),
  pipeline: document.getElementById("pipeline"),
};

let lastPcapBase64 = null;

function setStage(name, status) {
  const stage = els.pipeline.querySelector(`[data-stage="${name}"]`);
  if (!stage) return;
  stage.classList.remove("active", "done");
  if (status) stage.classList.add(status);
}

function resetPipeline() {
  ["find", "http", "pan", "test"].forEach((s) => setStage(s, null));
  ["rulePanel", "httpPanel", "panPanel", "testPanel", "listPanel"].forEach((id) =>
    document.getElementById(id).classList.remove("show")
  );
}

function setState(msg, isError = false) {
  els.stateMsg.textContent = msg;
  els.stateMsg.classList.toggle("error", isError);
}

function show(id) {
  document.getElementById(id).classList.add("show");
}

async function apiGet(path) {
  const res = await fetch(API + path);
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.detail || `HTTP ${res.status}`);
  }
  return res.json();
}

async function apiPost(path, options = {}) {
  const res = await fetch(API + path, { method: "POST", ...options });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.detail || `HTTP ${res.status}`);
  }
  return res.json();
}

function copyBlock(id) {
  const text = document.getElementById(id).textContent;
  navigator.clipboard.writeText(text);
}
window.copyBlock = copyBlock;

function fmtDate(iso) {
  if (!iso) return "–";
  const d = new Date(iso);
  return d.toLocaleString("tr-TR", { dateStyle: "medium", timeStyle: "short" });
}

// ---------------------------------------------------------------------------
// Kaynak / sürüm listesini yükle (dropdown'ları doldurur)
// ---------------------------------------------------------------------------
async function loadSources() {
  try {
    const sources = await apiGet("/api/sources");

    els.versionSelect.innerHTML = `<option value="">Sürüm: otomatik</option>`;
    const seenVersions = new Set();
    sources.forEach((s) => {
      if (seenVersions.has(s.snort_version)) return;
      seenVersions.add(s.snort_version);
      els.versionSelect.innerHTML += `<option value="${s.snort_version}">Sürüm: ${s.snort_version}</option>`;
    });

    els.syncSourceSelect.innerHTML = sources
      .map(
        (s) =>
          `<option value="${s.key}">${s.live_available ? "🟢" : "⚪"} ${s.label}</option>`
      )
      .join("");

    els.uploadVersionSelect.innerHTML = [...seenVersions, "manual"]
      .map((v) => `<option value="${v}">${v}</option>`)
      .join("");
  } catch (e) {
    console.error("Kaynaklar yüklenemedi", e);
  }
}

// ---------------------------------------------------------------------------
// Durum çubuğu (son güncelleme / son dosya / toplam kural)
// ---------------------------------------------------------------------------
async function loadStatus() {
  try {
    const s = await apiGet("/api/status");
    document.getElementById("statTotal").textContent = `${s.total_rules ?? 0} kural`;

    const lu = s.last_update_overall;
    document.getElementById("statLastUpdate").textContent = lu
      ? `${fmtDate(lu.finished_at)}\n${lu.source || "-"} · ${lu.snort_version || "-"} sürümü · ${lu.rules_ingested} kural eklendi`
      : "Henüz senkronizasyon yapılmadı";

    const up = s.last_manual_upload;
    document.getElementById("statLastUpload").textContent = up
      ? `${up.file_name}\n${fmtDate(up.finished_at)} · sürüm ${up.snort_version} · ${up.rules_ingested} kural`
      : "Henüz dosya yüklenmedi";

    const versions = (s.versions || []).filter((v) => v.count > 0);
    const listEl = document.getElementById("versionBreakdownList");
    listEl.innerHTML = versions.length
      ? versions
          .map((v) => `<div class="vb-pill">Snort <b>${escapeHtml(v.snort_version)}</b> → ${v.count} kural</div>`)
          .join("")
      : `<span style="color:var(--text-low);font-size:13px;">Henüz kural yok — önce bir senkronizasyon/yükleme yapın.</span>`;

    if (s.database_persistence_warning) {
      let warnEl = document.getElementById("dbPersistWarning");
      if (!warnEl) {
        warnEl = document.createElement("div");
        warnEl.id = "dbPersistWarning";
        warnEl.className = "notice";
        warnEl.style.marginBottom = "14px";
        els.stateMsg.parentNode.insertBefore(warnEl, els.stateMsg);
      }
      warnEl.innerHTML = `⚠️ <b>Veritabanı: SQLite (kalıcı değil).</b> ${escapeHtml(s.database_persistence_warning)}`;
    }
  } catch (e) {
    console.error("Durum bilgisi yüklenemedi", e);
    setState("Durum bilgisi yüklenemedi: " + e.message, true);
  }
}

// ---------------------------------------------------------------------------
// Ana analiz akışı
// ---------------------------------------------------------------------------
async function runAnalysis() {
  const sid = els.sidInput.value.trim();
  const version = els.versionSelect.value;
  if (!sid || isNaN(Number(sid))) {
    setState("Lütfen geçerli bir sayısal SID girin.", true);
    return;
  }
  const qs = version ? `?snort_version=${encodeURIComponent(version)}` : "";

  resetPipeline();
  setState("SID veritabanında aranıyor...");
  setStage("find", "active");

  try {
    const rule = await apiGet(`/api/rule/${sid}${qs}`);
    setStage("find", "done");
    await renderRule(rule, sid);
    show("rulePanel");

    setStage("http", "active");
    setState("Tetikleyici HTTP isteği üretiliyor...");
    const http = await apiGet(`/api/rule/${sid}/http${qs}`);
    setStage("http", "done");
    renderHttp(http);
    show("httpPanel");

    setStage("pan", "active");
    setState("Palo Alto Custom Vulnerability Signature'a dönüştürülüyor...");
    const pan = await apiGet(`/api/rule/${sid}/paloalto${qs}`);
    setStage("pan", "done");
    renderPan(pan);
    show("panPanel");

    setStage("test", "active");
    setState("PCAP oluşturuluyor ve temiz trafik havuzuna karşı test ediliyor...");
    const test = await apiGet(`/api/rule/${sid}/test${qs}`);
    setStage("test", "done");
    renderTest(test);
    show("testPanel");

    setState(`SID ${sid} (sürüm: ${rule.snort_version}) için analiz tamamlandı.`);
  } catch (e) {
    setState("Hata: " + e.message, true);
  }
}

async function renderRule(rule, sid) {
  document.getElementById("ruleTag").textContent = `SID ${rule.sid} · rev ${rule.rev}`;
  document.getElementById("ruleMeta").innerHTML = `
    <span><b>Mesaj:</b> ${escapeHtml(rule.msg || "-")}</span>
    <span><b>Sürüm:</b> <span class="version-pill">${escapeHtml(rule.snort_version)}</span></span>
    <span><b>Sınıf:</b> ${escapeHtml(rule.classtype || "-")}</span>
    <span><b>Protokol:</b> ${escapeHtml(rule.protocol)}</span>
    <span><b>Yön:</b> ${escapeHtml(rule.src)}:${escapeHtml(rule.src_port)} ${escapeHtml(rule.direction)} ${escapeHtml(rule.dst)}:${escapeHtml(rule.dst_port)}</span>
  `;
  document.getElementById("ruleRaw").textContent = rule.raw_rule;

  // Bu SID başka sürümlerde de kayıtlıysa bilgi ver
  try {
    const versions = await apiGet(`/api/rule/${sid}/versions`);
    const notice = document.getElementById("otherVersionsNotice");
    if (versions.length > 1) {
      notice.style.display = "block";
      notice.innerHTML =
        "Bu SID veritabanında birden fazla sürümde kayıtlı: " +
        versions.map((v) => `<b>${escapeHtml(v.snort_version)}</b>`).join(", ") +
        ". Belirli bir sürümü görmek için yukarıdaki sürüm seçiciyi kullanıp tekrar analiz edin.";
    } else {
      notice.style.display = "none";
    }
  } catch (_) {
    /* sessiz geç */
  }
}

function renderHttp(http) {
  document.getElementById("httpRaw").textContent = http.raw_request;
  document.getElementById("httpNotes").innerHTML = (http.notes || []).map(escapeHtml).join("<br>");
}

function renderPan(pan) {
  document.getElementById("panTag").textContent = `custom-vuln-${pan.signature_id}`;
  document.getElementById("panXml").textContent = pan.xml;
  document.getElementById("panCli").textContent = pan.cli_commands.join("\n");
  const warnEl = document.getElementById("panWarnings");
  const confBadge =
    pan.conversion_confidence === "low"
      ? `<span class="badge bad" style="margin-bottom:10px;display:inline-block;">⚠️ DÜŞÜK GÜVEN: Bu dönüşüm manuel doğrulama gerektirir</span><br>`
      : pan.conversion_confidence === "medium"
      ? `<span class="badge warn" style="margin-bottom:10px;display:inline-block;">⚠️ ORTA GÜVEN: Gözden geçirilmesi önerilir</span><br>`
      : `<span class="badge ok" style="margin-bottom:10px;display:inline-block;">✔ YÜKSEK GÜVEN</span><br>`;
  if (pan.warnings && pan.warnings.length) {
    warnEl.innerHTML = confBadge + "⚠️ " + pan.warnings.map(escapeHtml).join("<br><br>⚠️ ");
    warnEl.style.display = "block";
  } else {
    warnEl.innerHTML = confBadge;
    warnEl.style.display = "block";
  }
}

function renderTest(test) {
  lastPcapBase64 = test.pcap_base64 || null;

  const summaryEl = document.getElementById("testSummaryBadge");
  let badgeClass = "ok";
  if (test.false_positive_rate > 0) badgeClass = "warn";
  if (!test.true_positive.matched) badgeClass = "bad";
  let summaryHtml = `<span class="badge ${badgeClass}">${escapeHtml(test.summary)}</span>`;
  if (test.pcap_warning) {
    summaryHtml += `<div class="notice" style="margin-top:10px;">⚠️ ${escapeHtml(test.pcap_warning)}</div>`;
  }
  summaryEl.innerHTML = summaryHtml;

  const tpEl = document.getElementById("tpValue");
  tpEl.textContent = test.true_positive.matched ? "ALARM ✔" : "ALARM YOK ✘";
  tpEl.style.color = test.true_positive.matched ? "var(--green)" : "var(--red)";

  const fpEl = document.getElementById("fpValue");
  const fpPct = Math.round(test.false_positive_rate * 100);
  fpEl.textContent = fpPct + "%";
  fpEl.style.color = fpPct === 0 ? "var(--green)" : fpPct < 30 ? "var(--amber)" : "var(--red)";

  const fpList = document.getElementById("fpList");
  fpList.innerHTML = test.false_positive_checks
    .map(
      (r) => `
      <div class="fp-item">
        <span>${escapeHtml(r.label)}</span>
        <span class="badge ${r.matched ? "bad" : "ok"}">${r.matched ? "EŞLEŞTİ (FP)" : "temiz"}</span>
      </div>`
    )
    .join("");

  const downloadBtn = document.getElementById("downloadPcapBtn");
  downloadBtn.disabled = !lastPcapBase64;
  downloadBtn.textContent = lastPcapBase64 ? "PCAP indir" : "PCAP üretilemedi (bkz. yukarıdaki uyarı)";
}

document.getElementById("downloadPcapBtn").addEventListener("click", () => {
  if (!lastPcapBase64) return;
  const bytes = Uint8Array.from(atob(lastPcapBase64), (c) => c.charCodeAt(0));
  const blob = new Blob([bytes], { type: "application/vnd.tcpdump.pcap" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `sid_${els.sidInput.value.trim()}_test.pcap`;
  a.click();
  URL.revokeObjectURL(url);
});

// ---------------------------------------------------------------------------
// Senkronizasyon eylemleri
// ---------------------------------------------------------------------------
async function doOfflineSync() {
  resetPipeline();
  setState("Offline demo veri seti (3.x + 2.9) yükleniyor...");
  try {
    const r = await apiPost("/api/sync/offline-sample");
    setState(`Senkronizasyon tamam: ${r.rules_ingested} kural yüklendi.` + (r.rules_skipped ? ` (${r.rules_skipped} satır atlandı)` : ""));
    await loadStatus();
  } catch (e) {
    setState("Hata: " + e.message, true);
  }
}

async function doSyncAll() {
  resetPipeline();
  setState("Tüm canlı kaynaklar (3.x, 2.9 community, ET Open) sırayla senkronize ediliyor...");
  try {
    const results = await apiPost("/api/sync/all");
    const okCount = results.filter((r) => r.status === "success").length;
    const totalRules = results.reduce((sum, r) => sum + (r.rules_ingested || 0), 0);
    const totalSkipped = results.reduce((sum, r) => sum + (r.rules_skipped || 0), 0);
    setState(
      `${okCount}/${results.length} kaynak başarıyla senkronize edildi, toplam ${totalRules} kural eklendi` +
        (totalSkipped ? `, ${totalSkipped} satır atlandı.` : ".")
    );
    await loadStatus();
  } catch (e) {
    setState("Hata: " + e.message, true);
  }
}

async function doSyncOne() {
  const key = els.syncSourceSelect.value;
  resetPipeline();
  setState(`'${key}' kaynağı senkronize ediliyor...`);
  try {
    const r = await apiPost(`/api/sync/source/${key}`);
    if (r.status === "success") {
      setState(
        `Senkronizasyon tamam: ${r.rules_ingested} kural (sürüm ${r.snort_version}).` +
          (r.rules_skipped ? ` ${r.rules_skipped} satır atlandı.` : "")
      );
    } else {
      setState(`Senkronizasyon başarısız: ${r.error}`, true);
    }
    await loadStatus();
  } catch (e) {
    setState("Hata: " + e.message, true);
  }
}

async function doUpload() {
  const file = els.fileInput.files[0];
  const version = els.uploadVersionSelect.value;
  if (!file) {
    setState("Lütfen önce bir dosya seçin (.rules / .txt / .tar.gz).", true);
    return;
  }
  resetPipeline();
  setState(`'${file.name}' yükleniyor ve veritabanına işleniyor...`);
  try {
    const formData = new FormData();
    formData.append("file", file);
    formData.append("snort_version", version);
    const r = await apiPost("/api/upload-rules", { body: formData });
    setState(
      `Dosya yüklendi: ${r.rules_ingested} kural eklendi/güncellendi (sürüm ${r.snort_version}).` +
        (r.rules_skipped ? ` ${r.rules_skipped} satır atlandı.` : "")
    );
    await loadStatus();
  } catch (e) {
    setState("Hata: " + e.message, true);
  }
}

async function listRules() {
  resetPipeline();
  const version = els.versionSelect.value;
  setState(version ? `'${version}' sürümündeki SID'ler getiriliyor...` : "Tüm sürümlerden SID'ler getiriliyor...");
  try {
    const qs = version ? `?snort_version=${encodeURIComponent(version)}&limit=2000` : "?limit=2000";
    const rules = await apiGet(`/api/rules${qs}`);
    document.getElementById("listTag").textContent = version
      ? `${rules.length} kural (sürüm: ${version})`
      : `${rules.length} kural (tüm sürümler, en fazla 2000 gösterilir)`;
    document.getElementById("listBody").innerHTML = rules.length
      ? `<div class="rule-meta" style="flex-direction:column;gap:6px;">${rules
          .map(
            (r) =>
              `<span><b>${r.sid}</b> <span class="version-pill">${escapeHtml(r.snort_version)}</span> — ${escapeHtml(r.msg || "")}</span>`
          )
          .join("")}</div>`
      : `<p style="color:var(--text-mid);font-size:13px;">Henüz senkronize edilmiş kural yok. Önce senkronizasyon çalıştırın.</p>`;
    show("listPanel");
    setState(`${rules.length} kural listelendi. Sürüme göre toplam sayılar için yukarıdaki "Tüm istatistikleri ayrı sekmede aç" linkini kullanabilirsiniz.`);
  } catch (e) {
    setState("Hata: " + e.message, true);
  }
}

function escapeHtml(str) {
  return String(str ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

els.runBtn.addEventListener("click", runAnalysis);
els.sidInput.addEventListener("keydown", (e) => { if (e.key === "Enter") runAnalysis(); });
els.syncOfflineBtn.addEventListener("click", doOfflineSync);
els.syncAllBtn.addEventListener("click", doSyncAll);
els.syncOneBtn.addEventListener("click", doSyncOne);
els.uploadBtn.addEventListener("click", doUpload);
els.listBtn.addEventListener("click", listRules);

// Sayfa açılışında dropdown'ları ve durum çubuğunu doldur
loadSources();
loadStatus();
