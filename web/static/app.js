const STORAGE_KEY = "holycheck.activeJob";
const MAX_UPLOAD_BYTES = 1.9 * 1024 * 1024 * 1024;

const drop = document.getElementById("drop");
const fileInput = document.getElementById("fileInput");
const useMl = document.getElementById("useMl");
const progress = document.getElementById("progress");
const barFill = document.getElementById("barFill");
const progressText = document.getElementById("progressText");
const progressRate = document.getElementById("progressRate");
const phaseFast = document.getElementById("phaseFast");
const phaseMl = document.getElementById("phaseMl");
const results = document.getElementById("results");
const drawer = document.getElementById("drawer");
const backdrop = document.getElementById("backdrop");
const drawerClose = document.getElementById("drawerClose");
const drawerTitle = document.getElementById("drawerTitle");
const drawerMeta = document.getElementById("drawerMeta");
const drawerBody = document.getElementById("drawerBody");
const btnReport = document.getElementById("btnReport");
const btnStop = document.getElementById("btnStop");
const btnHistory = document.getElementById("btnHistory");
const btnClearLogs = document.getElementById("btnClearLogs");
const historyPanel = document.getElementById("historyPanel");
const historyBody = document.getElementById("historyBody");
const historyClose = document.getElementById("historyClose");
const btnClearLogsHist = document.getElementById("btnClearLogsHist");

const store = new Map();
let activeJobId = null;
let eventSource = null;
let scanStartedAt = 0;
let currentPhase = "fast";
let drawerFile = null;

function esc(s) {
  return String(s ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function formatEta(sec) {
  if (!Number.isFinite(sec) || sec < 0) return "—";
  if (sec < 60) return `${Math.ceil(sec)}с`;
  const m = Math.floor(sec / 60);
  const s = Math.ceil(sec % 60);
  return `${m}м ${s}с`;
}

function formatMb(bytes) {
  const n = Number(bytes) || 0;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(0)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

function formatSpeed(bytesPerSec) {
  const n = Number(bytesPerSec) || 0;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(0)} KB/s`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB/s`;
}

function setPhaseUI(phase) {
  currentPhase = phase;
  phaseFast.classList.toggle("on", phase === "fast" || phase === "done" || phase === "ml");
  phaseFast.classList.toggle("done", phase === "ml" || phase === "done");
  phaseMl.classList.toggle("on", phase === "ml");
  phaseMl.classList.toggle("done", phase === "done");
  phaseMl.classList.toggle("off", phase === "fast");
}

function updateRate(done, total, finished = false) {
  const elapsedMs = Date.now() - scanStartedAt;
  const elapsedMin = elapsedMs / 60000;
  const elapsedSec = elapsedMs / 1000;
  let rate = 0;
  if (elapsedMin > 0 && done > 0) rate = done / elapsedMin;
  let text = "— мод/мин";
  if (done > 0 && elapsedSec >= 0.4) {
    const rateStr = rate >= 10 ? rate.toFixed(0) : rate.toFixed(1);
    text = `${rateStr} мод/мин`;
    if (!finished && rate > 0 && done < total) {
      text += ` · ETA ${formatEta(((total - done) / rate) * 60)}`;
    }
    if (finished) {
      text += ` · ${elapsedSec < 60 ? `${elapsedSec.toFixed(1)}с` : formatEta(elapsedSec)}`;
    }
  } else if (!finished) {
    text = "считаем скорость…";
  }
  progressRate.textContent = text;
}

function setProgress(i, total, text) {
  progress.classList.remove("hidden");
  progress.classList.remove("uploading");
  barFill.style.width = `${total ? Math.round((i / total) * 100) : 0}%`;
  progressText.textContent = text || `${i}/${total}`;
}

function setUploadProgress(loaded, total, fileCount) {
  progress.classList.remove("hidden");
  progress.classList.add("uploading");
  const pct = total > 0 ? Math.min(100, Math.round((loaded / total) * 100)) : 0;
  barFill.style.width = `${pct}%`;
  const loadedStr = formatMb(loaded);
  const totalStr = formatMb(total);
  progressText.textContent = `загрузка · ${loadedStr} / ${totalStr} · ${fileCount} ${
    fileCount === 1 ? "файл" : fileCount < 5 ? "файла" : "файлов"
  } (${pct}%)`;
}

function uploadScan(url, fd, fileCount, totalBytes) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", url);
    let lastLoaded = 0;
    let lastTs = Date.now();
    setUploadProgress(0, totalBytes, fileCount);
    progressRate.textContent = "отправка…";

    xhr.upload.onprogress = (e) => {
      const loaded = e.lengthComputable ? e.loaded : Math.min(lastLoaded, totalBytes);
      const total = e.lengthComputable ? e.total : totalBytes;
      setUploadProgress(loaded, total, fileCount);

      const now = Date.now();
      const dt = (now - lastTs) / 1000;
      if (dt >= 0.25 && loaded > lastLoaded) {
        const speed = (loaded - lastLoaded) / dt;
        const remain = total > loaded && speed > 0 ? (total - loaded) / speed : NaN;
        let rate = formatSpeed(speed);
        if (Number.isFinite(remain) && remain >= 0) rate += ` · ETA ${formatEta(remain)}`;
        progressRate.textContent = rate;
        lastLoaded = loaded;
        lastTs = now;
      }
    };

    xhr.onload = () => {
      progress.classList.remove("uploading");
      if (xhr.status >= 200 && xhr.status < 300) {
        try {
          resolve(JSON.parse(xhr.responseText));
        } catch (_) {
          reject(new Error("bad json"));
        }
        return;
      }
      reject(new Error(`HTTP ${xhr.status}`));
    };
    xhr.onerror = () => {
      progress.classList.remove("uploading");
      reject(new Error("network"));
    };
    xhr.onabort = () => {
      progress.classList.remove("uploading");
      reject(new Error("aborted"));
    };
    xhr.send(fd);
  });
}

function cardKey(file) {
  return "card-" + encodeURIComponent(file).replace(/%/g, "_");
}

function cardEl(file) {
  const id = cardKey(file);
  let el = document.getElementById(id);
  if (el) return el;
  el = document.createElement("article");
  el.className = "card scanning";
  el.id = id;
  el.dataset.file = file;
  el.dataset.percent = "-1";
  el.innerHTML = `
    <span class="badge wait">…</span>
    <div>
      <h3>${esc(file)}</h3>
      <p class="meta">сканирование…</p>
    </div>
    <div class="pct">—</div>
    <div class="points"></div>
  `;
  el.addEventListener("click", () => openDrawer(file));
  results.appendChild(el);
  return el;
}

function applyHeat(el, percent, mode) {
  
  const p = Math.max(0, Math.min(100, Number(percent) || 0));
  const heat = mode === "clean" ? 0 : Math.max(0.15, p / 100);
  el.dataset.percent = String(p);
  el.dataset.mode = mode;
  el.style.setProperty("--heat", heat.toFixed(3));
  el.style.setProperty("--pct", `${p}%`);
  el.classList.toggle("hot", mode === "zpo");
  el.classList.toggle("obf", mode === "obf");
  el.classList.toggle("clean", mode === "clean");
}

function sortResults() {
  const cards = [...results.querySelectorAll(".card")];
  cards.sort((a, b) => {
    const scanA = a.classList.contains("scanning") ? 1 : 0;
    const scanB = b.classList.contains("scanning") ? 1 : 0;
    if (scanA !== scanB) return scanA - scanB;
    const rank = (el) => {
      if (el.classList.contains("hot")) return 2;
      if (el.classList.contains("obf")) return 1;
      return 0;
    };
    const ra = rank(a);
    const rb = rank(b);
    if (rb !== ra) return rb - ra;
    const pa = Number(a.dataset.percent ?? -1);
    const pb = Number(b.dataset.percent ?? -1);
    if (pb !== pa) return pb - pa;
    return String(a.dataset.file || "").localeCompare(String(b.dataset.file || ""));
  });
  cards.forEach((c) => results.appendChild(c));
}

function renderResult(r) {
  store.set(r.file, r);
  const el = cardEl(r.file);
  el.classList.remove("scanning");
  const badge = el.querySelector(".badge");
  const meta = el.querySelector(".meta");
  const pct = el.querySelector(".pct");
  const points = el.querySelector(".points");

  if (r.error && !r.zpo_fast && r.zpo_ml == null) {
    badge.className = "badge wait";
    badge.textContent = "ERR";
    meta.textContent = r.error;
    pct.textContent = "—";
    applyHeat(el, -1, "clean");
    sortResults();
    return;
  }

  const percent = Number(r.percent || 0);
  const obfPct = Number(r.obfuscation_percent || 0);
  const isObf = !!r.obfuscated;
  const isLegacyMc = !!r.mc_below_116;

  if (r.zpo) {
    badge.className = "badge yes";
    badge.textContent = "ЗПО";
  } else if (isObf) {
    badge.className = "badge obf";
    badge.textContent = "ОБФ";
  } else if (isLegacyMc) {
    badge.className = "badge legacy";
    badge.textContent = "<1.16";
  } else {
    badge.className = "badge no";
    badge.textContent = "OK";
  }

  const bits = [];
  if (r.phase) bits.push(r.phase === "ml" ? "ml" : "fast");
  if (r.factor_status) bits.push(r.factor_status);
  if (isLegacyMc) bits.push("MC < 1.16 · только fast");
  if (r.mod_id) bits.push(r.mod_id);
  if (r.mc_version) bits.push(`MC ${r.mc_version}`);
  else if (r.loader) bits.push(r.loader);
  if (isObf) bits.push(`обф ${obfPct.toFixed(0)}%`);
  bits.push(`${Math.round((r.size || 0) / 1024)} KB`);
  meta.textContent = bits.join(" · ");

  if (r.zpo) {
    pct.innerHTML = `${percent.toFixed(0)}%${
      isObf ? `<span class="pct-sub">обф ${obfPct.toFixed(0)}%</span>` : ""
    }`;
    applyHeat(el, percent, "zpo");
  } else if (isObf) {
    pct.innerHTML = `${obfPct.toFixed(0)}%<span class="pct-sub">обфускация</span>`;
    applyHeat(el, obfPct, "obf");
  } else {
    pct.textContent = `${percent.toFixed(0)}%`;
    applyHeat(el, percent, "clean");
  }

  points.innerHTML = (r.guide_points || [])
    .map((p) => `<span class="chip">${esc(p)}</span>`)
    .join("");
  if (isLegacyMc) {
    points.insertAdjacentHTML(
      "beforeend",
      `<span class="chip legacy">мод &lt; 1.16 · ML пропущен</span>`
    );
  }
  sortResults();
}

function buildReportText(r) {
  const factors = r.factors || {};
  const lines = [
    "=== holycheck report ===",
    `file: ${r.file || "—"}`,
    `md5: ${r.md5 || "—"}`,
    `sha256: ${r.sha256 || "—"}`,
    `size: ${r.size ?? "—"}`,
    `mod_id: ${r.mod_id || "—"}`,
    `mod_name: ${r.mod_name || "—"}`,
    `mc_version: ${r.mc_version || "—"}`,
    `loader: ${r.loader || "—"}`,
    "",
    `zpo: ${r.zpo ? "да" : "нет"}`,
    `percent: ${r.percent ?? 0}%`,
    `phase: ${r.phase || "—"}`,
    `factor_status: ${r.factor_status || "—"}`,
    `fast: ${factors.fast === true ? "да" : factors.fast === false ? "нет" : "—"} (${r.percent_fast ?? "—"}%)`,
    `ml: ${factors.ml === true ? "да" : factors.ml === false ? "нет" : "—"} (${r.percent_ml ?? r.ml_confidence ?? "—"}%)`,
    `obfuscated: ${r.obfuscated ? "да" : "нет"} (${r.obfuscation_percent ?? 0}%)`,
  ];

  if ((r.guide_points || []).length) {
    lines.push("", "guide_points:");
    for (const p of r.guide_points) lines.push(`- ${p}`);
  }
  if (r.summary || r.ml_summary) {
    lines.push("", "summary:", String(r.ml_summary || r.summary));
  }
  if ((r.malware_notes || []).length) {
    lines.push("", "malware_notes:");
    for (const n of r.malware_notes) lines.push(`- ${n}`);
  }
  if ((r.obfuscation_notes || []).length) {
    lines.push("", "obfuscation_notes:");
    for (const n of r.obfuscation_notes) lines.push(`- ${n}`);
  }
  const nestedBad = (r.nested_jars || []).filter((n) => n.suspicious);
  if (nestedBad.length) {
    lines.push("", "nested_suspicious:");
    for (const n of nestedBad) {
      lines.push(`- ${n.path}: ${n.reason} (id=${n.mod_id || "?"})`);
    }
  }
  if ((r.evidence || []).length) {
    lines.push("", "evidence:");
    for (const ev of r.evidence) {
      lines.push(`# ${ev.category}: ${ev.title}`);
      for (const s of (ev.strings || []).slice(0, 12)) {
        lines.push(`  ${s.class_path} | ${s.string} | ${s.pattern}`);
      }
    }
  }
  if (r.error) {
    lines.push("", `error: ${r.error}`);
  }

  lines.push(
    "",
    "--- raw client output ---",
    JSON.stringify(
      {
        file: r.file,
        md5: r.md5,
        sha256: r.sha256,
        size: r.size,
        mod_id: r.mod_id,
        mod_name: r.mod_name,
        mod_version: r.mod_version,
        mc_version: r.mc_version,
        loader: r.loader,
        zpo: r.zpo,
        percent: r.percent,
        zpo_fast: r.zpo_fast,
        percent_fast: r.percent_fast,
        zpo_ml: r.zpo_ml,
        percent_ml: r.percent_ml,
        ml_confidence: r.ml_confidence,
        factors: r.factors,
        factor_status: r.factor_status,
        phase: r.phase,
        guide_points: r.guide_points,
        obfuscated: r.obfuscated,
        obfuscation_percent: r.obfuscation_percent,
        obfuscation_notes: r.obfuscation_notes,
        malware_notes: r.malware_notes,
        summary: r.summary,
        ml_summary: r.ml_summary,
        nested_jars: r.nested_jars,
        evidence: r.evidence,
        error: r.error || null,
      },
      null,
      2
    )
  );
  return lines.join("\n");
}

async function copyReport() {
  if (!drawerFile) return;
  const r = store.get(drawerFile);
  if (!r) return;
  const text = buildReportText(r);
  try {
    await navigator.clipboard.writeText(text);
  } catch (_) {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.left = "-9999px";
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    ta.remove();
  }
  const prev = btnReport.textContent;
  btnReport.textContent = "copied";
  btnReport.classList.add("copied");
  setTimeout(() => {
    btnReport.textContent = prev;
    btnReport.classList.remove("copied");
  }, 1400);
}

function openDrawer(file) {
  const r = store.get(file);
  if (!r) return;
  drawerFile = file;
  drawerTitle.textContent = r.file;
  drawerMeta.textContent = [
    r.zpo ? "ЗПО: да" : "ЗПО: нет",
    `${r.percent ?? 0}%`,
    r.mc_version ? `MC ${r.mc_version}` : null,
    r.loader || null,
    r.obfuscated ? `обф: ${r.obfuscation_percent ?? 0}%` : null,
    r.factor_status || "",
    r.mod_name || r.mod_id || "",
  ]
    .filter(Boolean)
    .join(" · ");

  const parts = [];
  const factors = r.factors || {};
  parts.push(`<div class="block"><h4>факторы</h4>
    <div class="row"><code>fast: ${factors.fast === true ? "да" : factors.fast === false ? "нет" : "—"} (${r.percent_fast ?? "—"}%)</code></div>
    <div class="row"><code>ml: ${factors.ml === true ? "да" : factors.ml === false ? "нет" : "—"} (${r.percent_ml ?? r.ml_confidence ?? "—"}%)</code></div>
    <div class="row"><code>статус: ${esc(r.factor_status || r.phase || "—")}</code></div>
    <div class="row"><code>обфускация: ${r.obfuscated ? "да" : "нет"} (${r.obfuscation_percent ?? 0}%)</code></div>
  </div>`);

  parts.push(`<div class="block"><h4>хеши</h4>
    <div class="row"><code>md5: ${esc(r.md5 || "—")}</code></div>
    <div class="row"><code>sha256: ${esc(r.sha256 || "—")}</code></div>
  </div>`);

  if (r.obfuscation_notes && r.obfuscation_notes.length) {
    parts.push(
      `<div class="block"><h4>обфускация</h4><div class="row"><code>${r.obfuscation_notes.map(esc).join("<br>")}</code></div></div>`
    );
  }

  if (r.zpo && (r.guide_points || []).length) {
    parts.push(`<div class="block"><h4>пункты гайда</h4><div class="row"><code>${(r.guide_points || []).map(esc).join("<br>")}</code></div></div>`);
  }
  if (r.summary || r.ml_summary) {
    parts.push(`<div class="block"><h4>комментарий</h4><div class="row"><code>${esc(r.ml_summary || r.summary)}</code></div></div>`);
  }
  const nestedBad = (r.nested_jars || []).filter((n) => n.suspicious);
  if (nestedBad.length) {
    parts.push(
      `<div class="block"><h4>подложенные nested-jar</h4>${nestedBad
        .map(
          (n) => `<div class="row"><code class="cls">${esc(n.path)}</code><code>${esc(n.reason)} · id=${esc(n.mod_id || "?")}</code><code class="pat">nested</code></div>`
        )
        .join("")}</div>`
    );
  }
  if ((r.evidence || []).length) {
    for (const ev of r.evidence) {
      const rows = (ev.strings || [])
        .map(
          (s) => `<div class="row">
            <code class="cls">${esc(s.class_path)}</code>
            <code>${esc(s.string)}</code>
            <code class="pat">${esc(s.pattern)}</code>
          </div>`
        )
        .join("");
      parts.push(`<div class="block"><h4>${esc(ev.category)}: ${esc(ev.title)}</h4>
        <div class="row small"><code>класс</code><code>строка</code><code>паттерн</code></div>
        ${rows || '<div class="row"><code>нет точных строк</code></div>'}</div>`);
    }
  } else if (!r.zpo) {
    parts.push(`<div class="block"><h4>чисто</h4><div class="row"><code>сильных чит-сигналов не найдено</code></div></div>`);
  }

  drawerBody.innerHTML = parts.join("");
  drawer.classList.remove("hidden");
  backdrop.classList.remove("hidden");
  historyPanel.classList.add("hidden");
}

function closeDrawer() {
  drawer.classList.add("hidden");
  drawerFile = null;
  if (historyPanel.classList.contains("hidden")) backdrop.classList.add("hidden");
}

function closeHistory() {
  historyPanel.classList.add("hidden");
  if (drawer.classList.contains("hidden")) backdrop.classList.add("hidden");
}

function rememberJob(jobId) {
  activeJobId = jobId;
  localStorage.setItem(STORAGE_KEY, jobId);
  const url = new URL(location.href);
  url.searchParams.set("job", jobId);
  history.replaceState(null, "", url);
}

function forgetJob() {
  activeJobId = null;
  localStorage.removeItem(STORAGE_KEY);
}

function closeStream() {
  if (eventSource) {
    eventSource.close();
    eventSource = null;
  }
}

function handleEvent(ev) {
  if (ev.type === "ping") return;
  if (ev.type === "snapshot") {
    const job = ev.job || {};
    setPhaseUI(job.phase === "done" ? "done" : job.phase || "fast");
    progress.classList.remove("hidden");
    (job.files || []).forEach((f) => cardEl(f));
    (ev.results || []).forEach((r) => renderResult(r));
    const done = job.phase === "ml" ? job.ml_done : job.fast_done;
    const total = (job.files || []).length;
    setProgress(done || 0, total, `${job.phase || "fast"} · ${done || 0}/${total}`);
    updateRate(done || 0, total, job.status === "done" || job.status === "stopped");
    sortResults();
    return;
  }
  if (ev.type === "start") {
    setPhaseUI(ev.phase || "fast");
    scanStartedAt = Date.now();
    setProgress(0, ev.total, `${ev.phase} · старт · ${ev.total}`);
    updateRate(0, ev.total);
    (ev.files || []).forEach((f) => cardEl(f));
  }
  if (ev.type === "result") {
    if (ev.phase) setPhaseUI(ev.phase);
    renderResult(ev.result);
    setProgress(ev.index, ev.total, `${ev.phase} · ${ev.result.file} (${ev.index}/${ev.total})`);
    updateRate(ev.index, ev.total);
  }
  if (ev.type === "phase_done") {
    setProgress(ev.total, ev.total, `fast готов · ${ev.total}`);
    updateRate(ev.total, ev.total, true);
  }
  if (ev.type === "done") {
    setPhaseUI("done");
    setProgress(ev.total, ev.total, `готово · ${ev.total}`);
    updateRate(ev.total, ev.total, true);
    sortResults();
    closeStream();
  }
  if (ev.type === "stopped") {
    setProgress(ev.done || 0, ev.total || 0, `остановлено · ${ev.phase}`);
    progressText.textContent = `стоп · ${ev.phase} · ${ev.done || 0}/${ev.total || 0}`;
    closeStream();
  }
  if (ev.type === "error") {
    progressText.textContent = ev.message || "ошибка";
    closeStream();
  }
}

function subscribe(jobId) {
  closeStream();
  rememberJob(jobId);
  eventSource = new EventSource(`/api/scan/${jobId}/events`);
  eventSource.onmessage = (msg) => {
    try {
      handleEvent(JSON.parse(msg.data));
    } catch (_) {}
  };
  eventSource.onerror = () => {
    progressText.textContent = (progressText.textContent || "") + "";
  };
}

async function restoreJob(jobId) {
  const res = await fetch(`/api/scan/${jobId}`);
  const data = await res.json();
  if (data.error) {
    forgetJob();
    return false;
  }
  results.innerHTML = "";
  store.clear();
  progress.classList.remove("hidden");
  scanStartedAt = Date.now();
  (data.files || []).forEach((f) => cardEl(f));
  Object.values(data.results || {}).forEach((r) => renderResult(r));
  setPhaseUI(data.phase === "done" ? "done" : data.phase || "fast");
  const done = data.phase === "ml" ? data.ml_done : data.fast_done;
  setProgress(done || 0, (data.files || []).length, `${data.phase} · ${done || 0}/${(data.files || []).length}`);
  updateRate(done || 0, (data.files || []).length, data.status === "done" || data.status === "stopped");
  if (data.status === "queued" || data.status === "fast" || data.status === "ml") {
    subscribe(jobId);
  } else {
    rememberJob(jobId);
  }
  return true;
}

async function startScan(files) {
  const jarFiles = files.filter((f) => /\.(jar|zip)$/i.test(f.name));
  if (!jarFiles.length) {
    progress.classList.remove("hidden");
    progressText.textContent = "нужны .jar / .zip";
    return;
  }

  results.innerHTML = "";
  store.clear();
  closeStream();
  scanStartedAt = Date.now();
  jarFiles.forEach((f) => cardEl(f.name));
  setPhaseUI("fast");
  const totalBytes = jarFiles.reduce((sum, f) => sum + (f.size || 0), 0);
  if (totalBytes > MAX_UPLOAD_BYTES) {
    progress.classList.remove("hidden");
    progressText.textContent = `слишком большая загрузка: ${formatMb(totalBytes)} (лимит ${formatMb(MAX_UPLOAD_BYTES)}) — разбей на несколько частей`;
    progressRate.textContent = `${jarFiles.length} файлов`;
    barFill.style.width = "0%";
    return;
  }
  setUploadProgress(0, totalBytes, jarFiles.length);

  const fd = new FormData();
  jarFiles.forEach((f) => fd.append("files", f));
  const q = useMl.checked ? "?use_ml=true" : "?use_ml=false";
  let data;
  try {
    data = await uploadScan(`/api/scan${q}`, fd, jarFiles.length, totalBytes);
  } catch (err) {
    const msg = String(err?.message || err || "");
    if (msg.includes("413")) {
      progressText.textContent = `413: слишком большая загрузка (${formatMb(totalBytes)}). Разбей пачку или загрузи меньше модов за раз (лимит ~2 GB).`;
    } else {
      progressText.textContent = "ошибка загрузки";
    }
    progressRate.textContent = "—";
    barFill.style.width = "0%";
    return;
  }
  if (!data.job_id) {
    progressText.textContent = "ошибка загрузки";
    return;
  }
  subscribe(data.job_id);
}

async function stopAll() {
  if (activeJobId) {
    await fetch(`/api/scan/${activeJobId}/stop`, { method: "POST" });
  }
  await fetch("/api/stop", { method: "POST" });
  progressText.textContent = "стоп запрошен";
  closeStream();
}

function resetUiState() {
  closeStream();
  store.clear();
  results.innerHTML = "";
  progress.classList.add("hidden");
  progress.classList.remove("uploading");
  barFill.style.width = "0%";
  progressText.textContent = "ожидание…";
  progressRate.textContent = "— мод/мин";
  setPhaseUI("fast");
  phaseFast.classList.remove("on", "done");
  phaseMl.classList.remove("on", "done", "off");
  closeDrawer();
  activeJobId = null;
  localStorage.removeItem(STORAGE_KEY);
  const url = new URL(location.href);
  url.searchParams.delete("job");
  history.replaceState(null, "", url);
}

async function clearLastLogs() {
  const res = await fetch("/api/history/clear-last", { method: "POST" });
  const data = await res.json().catch(() => ({}));
  if (!res.ok || data.error) {
    progress.classList.remove("hidden");
    progressText.textContent = "не удалось очистить логи";
    return;
  }
  const wasActive = data.cleared_job && data.cleared_job === activeJobId;
  const saved = localStorage.getItem(STORAGE_KEY);
  if (wasActive || !saved || saved === data.cleared_job || !data.cleared_job) {
    resetUiState();
  }
  progress.classList.remove("hidden");
  const parts = [];
  if (data.cleared_job) parts.push(`джоб ${data.cleared_job}`);
  if ((data.cleared_logs || []).length) parts.push(`лог ${data.cleared_logs.join(", ")}`);
  progressText.textContent = parts.length
    ? `скрыто из истории: ${parts.join(" · ")} (файлы на сервере сохранены)`
    : "нечего скрывать";
  progressRate.textContent = `история: ${data.history_left ?? 0}`;
  if (!historyPanel.classList.contains("hidden")) {
    await openHistory();
  }
}

async function openHistory() {
  const res = await fetch("/api/history");
  const data = await res.json();
  const items = data.items || [];
  historyBody.innerHTML = items.length
    ? items
        .map(
          (it) => `<button class="hist-item" type="button" data-id="${esc(it.id)}">
            <strong>${esc(it.id)}</strong>
            <span>${esc(it.status)} · ${it.files} файлов · зпо ${it.zpo_count ?? 0}</span>
            <span class="small">${esc(it.created_at || "")}</span>
          </button>`
        )
        .join("")
    : `<div class="row"><code>пусто</code></div>`;
  historyPanel.classList.remove("hidden");
  backdrop.classList.remove("hidden");
  drawer.classList.add("hidden");
  historyBody.querySelectorAll(".hist-item").forEach((btn) => {
    btn.addEventListener("click", async () => {
      closeHistory();
      await restoreJob(btn.dataset.id);
    });
  });
}

drawerClose.addEventListener("click", closeDrawer);
if (btnReport) btnReport.addEventListener("click", copyReport);
historyClose.addEventListener("click", closeHistory);
backdrop.addEventListener("click", () => {
  closeDrawer();
  closeHistory();
});
btnStop.addEventListener("click", stopAll);
btnHistory.addEventListener("click", openHistory);
btnClearLogs.addEventListener("click", clearLastLogs);
if (btnClearLogsHist) btnClearLogsHist.addEventListener("click", clearLastLogs);

["dragenter", "dragover"].forEach((ev) => {
  drop.addEventListener(ev, (e) => {
    e.preventDefault();
    drop.classList.add("over");
  });
});
["dragleave", "drop"].forEach((ev) => {
  drop.addEventListener(ev, (e) => {
    e.preventDefault();
    drop.classList.remove("over");
  });
});
drop.addEventListener("drop", (e) => {
  const files = [...(e.dataTransfer?.files || [])];
  if (files.length) startScan(files);
});
fileInput.addEventListener("change", () => {
  const files = [...fileInput.files];
  if (files.length) startScan(files);
  fileInput.value = "";
});

(async function boot() {
  const urlJob = new URL(location.href).searchParams.get("job");
  const saved = urlJob || localStorage.getItem(STORAGE_KEY);
  if (saved) await restoreJob(saved);
})();
