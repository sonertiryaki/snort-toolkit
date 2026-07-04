const API = ""; // aynı origin üzerinden servis edildiği için boş bırakıldı

const els = {
  sidInput: document.getElementById("sidInput"),
  runBtn: document.getElementById("runBtn"),
  syncOfflineBtn: document.getElementById("syncOfflineBtn"),
  syncLiveBtn: document.getElementById("syncLiveBtn"),
  listBtn: document.getElementById("listBtn"),
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

async function apiPost(path) {
  const res = await fetch(API + path, { method: "POST" });
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

async function runAnalysis() {
  const sid = els.sidInput.value.trim();
  if (!sid || isNaN(Number(sid))) {
    setState("Lütfen geçerli bir sayısal SID girin.", true);
    return;
  }

  resetPipeline();
  setState("SID veritabanında aranıyor...");
  setStage("find", "active");

  try {
    // 1) Kural bul
    const rule = await apiGet(`/api/rule/${sid}`);
    setStage("find", "done");
    renderRule(rule);
    show("rulePanel");

    // 2) HTTP üret
    setStage("http", "active");
    setState("Tetikleyici HTTP isteği üretiliyor...");
    const http = await apiGet(`/api/rule/${sid}/http`);
    setStage("http", "done");
    renderHttp(http);
    show("httpPanel");

    // 3) Palo Alto dönüştür
    setStage("pan", "active");
    setState("Palo Alto Custom Vulnerability Signature'a dönüştürülüyor...");
    const pan = await apiGet(`/api/rule/${sid}/paloalto`);
    setStage("pan", "done");
    renderPan(pan);
    show("panPanel");

    // 4) Test et
    setStage("test", "active");
    setState("PCAP oluşturuluyor ve temiz trafik havuzuna karşı test ediliyor...");
    const test = await apiGet(`/api/rule/${sid}/test`);
    setStage("test", "done");
    renderTest(test);
    show("testPanel");

    setState(`SID ${sid} için analiz tamamlandı.`);
  } catch (e) {
    setState("Hata: " + e.message, true);
  }
}

function renderRule(rule) {
  document.getElementById("ruleTag").textContent = `SID ${rule.sid} · rev ${rule.rev}`;
  document.getElementById("ruleMeta").innerHTML = `
    <span><b>Mesaj:</b> ${escapeHtml(rule.msg || "-")}</span>
    <span><b>Sınıf:</b> ${escapeHtml(rule.classtype || "-")}</span>
    <span><b>Protokol:</b> ${escapeHtml(rule.protocol)}</span>
    <span><b>Yön:</b> ${escapeHtml(rule.src)}:${escapeHtml(rule.src_port)} ${escapeHtml(rule.direction)} ${escapeHtml(rule.dst)}:${escapeHtml(rule.dst_port)}</span>
  `;
  document.getElementById("ruleRaw").textContent = rule.raw_rule;
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
  if (pan.warnings && pan.warnings.length) {
    warnEl.innerHTML = "⚠️ " + pan.warnings.map(escapeHtml).join("<br>⚠️ ");
    warnEl.style.display = "block";
  } else {
    warnEl.style.display = "none";
  }
}

function renderTest(test) {
  lastPcapBase64 = test.pcap_base64;

  const summaryEl = document.getElementById("testSummaryBadge");
  let badgeClass = "ok";
  if (test.false_positive_rate > 0) badgeClass = "warn";
  if (!test.true_positive.matched) badgeClass = "bad";
  summaryEl.innerHTML = `<span class="badge ${badgeClass}">${escapeHtml(test.summary)}</span>`;

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

async function doSync(offline) {
  resetPipeline();
  setState(offline ? "Offline demo veri seti yükleniyor..." : "Canlı kaynaktan (snort.org) senkronizasyon başlatılıyor...");
  try {
    const result = await apiPost(`/api/sync?offline_sample=${offline}`);
    if (result.status === "success") {
      setState(`Senkronizasyon tamam: ${result.rules_ingested} kural yüklendi (${result.source_used}).`);
    } else {
      setState(`Senkronizasyon başarısız: ${result.error}`, true);
    }
  } catch (e) {
    setState("Hata: " + e.message, true);
  }
}

async function listRules() {
  resetPipeline();
  setState("SID listesi getiriliyor...");
  try {
    const rules = await apiGet("/api/rules?limit=100");
    document.getElementById("listTag").textContent = `${rules.length} kural`;
    document.getElementById("listBody").innerHTML = rules.length
      ? `<div class="rule-meta" style="flex-direction:column;gap:6px;">${rules
          .map((r) => `<span><b>${r.sid}</b> — ${escapeHtml(r.msg || "")}</span>`)
          .join("")}</div>`
      : `<p style="color:var(--text-mid);font-size:13px;">Henüz senkronize edilmiş kural yok. Önce senkronizasyon çalıştırın.</p>`;
    show("listPanel");
    setState(`${rules.length} kural listelendi.`);
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
els.syncOfflineBtn.addEventListener("click", () => doSync(true));
els.syncLiveBtn.addEventListener("click", () => doSync(false));
els.listBtn.addEventListener("click", listRules);
