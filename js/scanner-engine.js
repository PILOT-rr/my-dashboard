(function(){
  "use strict";

  let allRecords = [];
  let filtered = [];
  let invalidCount = 0;
  let duplicateCount = 0;
  let pendingTailCount = 0;
  let currentPage = 0;
  let pageSize = 100;
  let sortKey = "RootDomain";
  let sortAsc = true;

  let selectedFile = null;
  let selectedFileHandle = null;
  let inputFile = null;
  let logFile = null;
  let inputSourceFile = null;
  let logSourceFile = null;

  let inputTotal = 0;
  let inputLoadedAt = 0;
  let logLoadedAt = 0;
  let scannerPosition = null;
  let scannerLastDomain = "";
  let parsedLogState = {
    latest: null, lastDomain: "", events: [], lastTimestamp: null,
    currentStatus: "UNKNOWN", currentIndex: 0, total: 0,
    counts: { completed: 0, partial: 0, failed: 0, skipped: 0 },
    terminal: 0, ratePerMinute: 0, etaMinutes: null
  };

  let liveMode = false;
  let liveTimer = null;
  let lastFileSignature = "";
  let lastLoadedAt = 0;

  let autoMonitorTimer = null;
  let autoMonitorOn = false;
  let snapshotMode = "latest";

  const $ = id => document.getElementById(id);
  const kpiGrid = $("kpiGrid");
  const tableHead = $("tableHead");
  const tableBody = $("tableBody");
  const pageInfo = $("pageInfo");
  const prevBtn = $("prevPage");
  const nextBtn = $("nextPage");
  const pageSizeSelect = $("pageSizeSelect");
  const globalSearch = $("globalSearch");
  const globalSearchInput = $("globalSearchInput");
  const fRegStatus = $("fRegStatus");
  const fConfidence = $("fConfidence");
  const fDnsStatus = $("fDnsStatus");
  const fLifecycle = $("fLifecycle");
  const drawerOverlay = $("drawerOverlay");
  const drawerBody = $("drawerBody");
  const drawerTitle = $("drawerTitle");
  const drawerSubtitle = $("drawerSubtitle");
  const detailSummary = $("detailSummary");
  const loadStatus = $("loadStatus");
  const threatBadge = $("threatBadge");
  const refreshBtn = $("refreshBtn");
  const liveBtn = $("liveBtn");
  const liveIndicator = $("liveIndicator");
  const liveLabel = $("liveLabel");
  const liveMeta = $("liveMeta");
  const progressFill = $("progressFill");
  const progressText = $("progressText");
  const progressValue = $("progressValue");
  const progressDetail = $("progressDetail");
  const dataDetail = $("dataDetail");
  const exportXlsxBtn = $("exportXlsxBtn");
  const fileInput = $("fileInput");
  const inputFileInput = $("inputFileInput");
  const logFileInput = $("logFileInput");
  const loadFileBtn = $("loadFileBtn");
  const loadInputBtn = $("loadInputBtn");
  const loadLogBtn = $("loadLogBtn");
  const offlinePanel = $("offlinePanel");
  const dataFileIndicator = $("dataFileIndicator");
  const errorBox = $("errorBox");

  function escapeHTML(value){
    if(value === null || value === undefined) return "";
    const map = { "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#x27;" };
    return String(value).replace(/[&<>"']/g, s => map[s]);
  }
  function displayValue(value){
    if(value === null || value === undefined || value === "") return "—";
    if(Array.isArray(value)){
      if(!value.length) return "—";
      return value.map(v => typeof v === "object" ? JSON.stringify(v) : String(v)).join(", ");
    }
    if(typeof value === "object") return JSON.stringify(value);
    return String(value);
  }
  function getVal(obj, key){
    if(!obj) return "";
    const value = obj[key];
    if(value === null || value === undefined) return "";
    if(Array.isArray(value)) return value.join(", ");
    if(typeof value === "object") return JSON.stringify(value);
    return String(value);
  }
  function statusClass(value){
    const s = String(value || "").toUpperCase();
    const map = {
      REGISTERED:"registered", ACTIVE:"active", EXPIRED:"expired",
      PENDING_DELETE:"pending_delete", REDEMPTION_PERIOD:"redemption_period",
      AVAILABLE:"available", NOT_REGISTERED:"not_registered",
      DROPPED:"dropped", UNKNOWN:"unknown", ERROR:"error"
    };
    return map[s] || "unknown";
  }
  function confidenceClass(value){
    const s = String(value || "").toUpperCase();
    if(s === "HIGH") return "high";
    if(s === "MEDIUM") return "medium";
    if(s === "LOW") return "low";
    return "";
  }
  function showError(message){ errorBox.textContent = "⚠️ " + message; errorBox.classList.add("show"); }
  function hideError(){ errorBox.classList.remove("show"); }

  function firstPresent(obj, keys){
    for(const key of keys){
      if(Object.prototype.hasOwnProperty.call(obj, key) && obj[key] !== null && obj[key] !== undefined && obj[key] !== "") return obj[key];
    }
    return "";
  }
  function normalizeRecord(source){
    const r = Object.assign({}, source);
    r.RootDomain = firstPresent(source, ["RootDomain","ROOT_DOMAIN","ROOTDOMAIN","root_domain"]);
    r.Subdomain = firstPresent(source, ["Subdomain","SUBDOMAIN","subdomain","HOSTNAME","HOST"]);
    r.CNAME = firstPresent(source, ["CNAME","cname","Cname"]);
    r.CNAME_ROOT = firstPresent(source, ["CNAME_ROOT","CnameRoot","CNAME_ROOT_DOMAIN","cname_root"]);
    r.RegistrationStatus = firstPresent(source, ["CNAME_ROOT_STATUS","RegistrationStatus","REGISTRATION_STATUS","REGISTRATIONSTATUS","registration_status","STATUS"]);
    r.RawRegistryStatus = firstPresent(source, ["RAW_REGISTRY_STATUS","RawRegistryStatus","REGISTRY_STATUS"]);
    r.LifecycleConfidence = firstPresent(source, ["LifecycleConfidence","LIFECYCLE_CONFIDENCE","CONFIDENCE"]);
    r.ExpiryDate = firstPresent(source, ["CNAME_ROOT_EXPIRATION_DATE","EXPIRATION_DATE","EXPIRY_DATE","ExpiryDate","EXPIRYDATE","expiration_date"]);
    r.CreatedDate = firstPresent(source, ["CNAME_ROOT_CREATED_DATE","CREATED_DATE","CREATE_DATE","CreatedDate"]);
    r.DaysLeft = firstPresent(source, ["DAYS_REMAINING","DaysLeft","DAYS_LEFT"]);
    r.DNSStatus = firstPresent(source, ["DNS_STATUS","DNSStatus","DNS_STATUS_RESULT"]);
    r.IPs = firstPresent(source, ["IPS","IPs","IP","ip_addresses"]);
    r.CheckedAt = firstPresent(source, ["CHECKED_AT","CheckedAt","TIMESTAMP"]);
    return r;
  }
  function recordIdentity(r){
    const parts = [r.RootDomain, r.Subdomain, r.CNAME, r.CNAME_ROOT];
    const normalized = parts.map(v => String(v ?? "").trim().toLowerCase());
    if(normalized.every(v => !v)) return "RAW\u001f" + JSON.stringify(r);
    return normalized.join("\u001f");
  }
  function deduplicateRecords(records){
    if(snapshotMode === "all"){
      const normalized = records.map(normalizeRecord);
      return { records: normalized, duplicates: 0 };
    }
    const byKey = new Map();
    let duplicates = 0;
    for(const source of records){
      const r = normalizeRecord(source);
      const key = recordIdentity(r);
      if(byKey.has(key)) duplicates++;
      byKey.set(key, r);
    }
    return { records: Array.from(byKey.values()), duplicates };
  }
  function parseJSONL(text){
    const raw = String(text || "");
    const lines = raw.split(/\r?\n/);
    const hasFinalNewline = /\r?\n$/.test(raw);
    const records = [];
    let invalid = 0;
    let pendingTail = 0;
    for(let i=0; i<lines.length; i++){
      const clean = lines[i].trim();
      if(!clean) continue;
      try {
        const obj = JSON.parse(clean);
        if(obj && typeof obj === "object" && !Array.isArray(obj)) records.push(obj);
        else invalid++;
      } catch(_) {
        if(i === lines.length - 1 && !hasFinalNewline) pendingTail++;
        else invalid++;
      }
    }
    const unique = deduplicateRecords(records);
    return { records: unique.records, invalid, duplicates: unique.duplicates, pendingTail };
  }

  function updateOfflinePanel(){
    if(location.protocol === "file:" && !allRecords.length){
      offlinePanel.hidden = false;
    } else {
      offlinePanel.hidden = true;
    }
  }

  function finishLoadedData(name){
    if(!allRecords.length){
      showError("No valid JSON records found in " + name);
      loadStatus.textContent = "⚠️ 0 valid records";
      loadStatus.className = "badge red";
      updateProgress();
      updateOfflinePanel();
      return false;
    }
    hideError();
    const indicator = name + " · " + allRecords.length.toLocaleString() + " records" +
      (duplicateCount ? " · " + duplicateCount.toLocaleString() + " dup" : "") +
      (invalidCount ? " · " + invalidCount.toLocaleString() + " invalid" : "");
    loadStatus.textContent = "✅ " + indicator;
    loadStatus.className = "badge green";
    if(dataFileIndicator){
      dataFileIndicator.textContent = "📂 " + indicator;
      dataFileIndicator.classList.add("loaded");
    }
    lastLoadedAt = Date.now();
    updateLiveMeta();
    updateProgress();
    currentPage = 0;
    applyFiltersAndRender();
    updateOfflinePanel();
    return true;
  }

  async function loadJSONLBlob(blob, name){
    if(!blob) throw new Error("No JSONL file selected.");
    allRecords = [];
    filtered = [];
    invalidCount = 0;
    duplicateCount = 0;
    pendingTailCount = 0;

    const totalBytes = Number(blob.size || 0);
    const CHUNK_BYTES = 1024 * 1024;
    let offset = 0;
    let carry = "";
    let lastUiUpdate = 0;
    const decoder = new TextDecoder("utf-8");

    loadStatus.textContent = "⏳ Reading " + name + "…";
    loadStatus.className = "badge yellow";
    dataDetail.textContent = "0 records · 0 invalid";

    while(offset < totalBytes){
      const end = Math.min(offset + CHUNK_BYTES, totalBytes);
      const buffer = await blob.slice(offset, end).arrayBuffer();
      const text = decoder.decode(buffer, { stream: end < totalBytes });
      const combined = carry + text;
      const lines = combined.split(/\r?\n/);
      carry = lines.pop() || "";
      for(let i=0; i<lines.length; i++){
        const clean = lines[i].trim();
        if(!clean) continue;
        try {
          const obj = JSON.parse(clean);
          if(obj && typeof obj === "object" && !Array.isArray(obj)) allRecords.push(obj);
          else invalidCount++;
        } catch(_) { invalidCount++; }
      }
      offset = end;
      const now = performance.now();
      if(now - lastUiUpdate > 120){
        lastUiUpdate = now;
        const pct = totalBytes ? (offset / totalBytes * 100) : 100;
        loadStatus.textContent = "⏳ Parsing · " + pct.toFixed(1) + "% · " + allRecords.length.toLocaleString() + " records";
        dataDetail.textContent = allRecords.length.toLocaleString() + " records · " + invalidCount.toLocaleString() + " invalid";
        await new Promise(resolve => setTimeout(resolve, 0));
      }
    }

    const tail = carry + decoder.decode();
    if(tail.trim()){
      try {
        const obj = JSON.parse(tail.trim());
        if(obj && typeof obj === "object" && !Array.isArray(obj)) allRecords.push(obj);
        else invalidCount++;
      } catch(_) { pendingTailCount++; }
    }

    const unique = deduplicateRecords(allRecords);
    allRecords = unique.records;
    duplicateCount = unique.duplicates;
    return finishLoadedData(name);
  }

  async function useLoadedText(text, name){
    const result = parseJSONL(text);
    allRecords = result.records;
    invalidCount = result.invalid;
    duplicateCount = result.duplicates || 0;
    pendingTailCount = result.pendingTail || 0;
    return finishLoadedData(name);
  }

  async function openLocalFile(){
    try {
      if("showOpenFilePicker" in window){
        const handles = await window.showOpenFilePicker({
          multiple: false,
          types: [{ description: "JSONL files", accept: { "application/json": [".jsonl",".json"], "text/plain": [".txt"] } }]
        });
        if(!handles.length) return;
        selectedFileHandle = handles[0];
        selectedFile = await selectedFileHandle.getFile();
        await readHandleFile(true);
        setLiveMode(true);
        return;
      }
      liveMode = false; stopLiveWatcher(); updateLiveIndicator();
      loadStatus.textContent = "📂 Browser fallback: manual file reload";
      loadStatus.className = "badge yellow";
      fileInput.click();
    } catch(error){
      if(error && error.name === "AbortError") return;
      showError("Could not open the JSONL file: " + (error.message || error));
      loadStatus.textContent = "⚠️ Open failed";
      loadStatus.className = "badge red";
    }
  }

  async function readHandleFile(force){
    if(!selectedFileHandle) return false;
    try {
      selectedFile = await selectedFileHandle.getFile();
      const signature = [selectedFile.name, selectedFile.size, selectedFile.lastModified].join(":");
      if(!force && signature === lastFileSignature) return false;
      lastFileSignature = signature;
      await loadJSONLBlob(selectedFile, selectedFile.name);
      return true;
    } catch(error){
      showError("Could not read the selected file: " + (error.message || error));
      loadStatus.textContent = "⚠️ Read failed";
      loadStatus.className = "badge red";
      return false;
    }
  }

  async function readLocalFile(file){
    if(!file) return;
    selectedFileHandle = null;
    selectedFile = file;
    lastFileSignature = [file.name, file.size, file.lastModified].join(":");
    try {
      await loadJSONLBlob(file, file.name);
      liveMode = false; stopLiveWatcher(); updateLiveIndicator();
    } catch(error){
      showError("Could not read the selected file: " + (error.message || error));
      loadStatus.textContent = "⚠️ Read failed";
      loadStatus.className = "badge red";
    }
  }

  async function refreshLocalFile(){
    if(selectedFileHandle){ await readHandleFile(false); return; }
    if(!selectedFile){
      loadStatus.textContent = "📂 Select FINAL_RESULTS.jsonl";
      loadStatus.className = "badge";
      updateOfflinePanel();
      return;
    }
    await readLocalFile(selectedFile);
  }

  function updateLiveIndicator(){
    liveIndicator.classList.toggle("on", liveMode);
    liveIndicator.classList.remove("changed");
    liveLabel.textContent = liveMode ? "LIVE ON" : "LIVE OFF";
    liveBtn.textContent = liveMode ? "● Live: On" : "● Live: Off";
  }
  function updateLiveMeta(){
    if(!selectedFile){ liveMeta.textContent = "No local file selected"; return; }
    const when = lastLoadedAt ? new Date(lastLoadedAt).toLocaleTimeString() : "—";
    const size = Number(selectedFile.size || 0);
    const mb = size / 1048576;
    const sizeText = mb >= 1 ? mb.toFixed(1) + " MB" : Math.max(1, Math.round(size / 1024)) + " KB";
    liveMeta.textContent = selectedFile.name + " · " + sizeText + " · last read " + when +
      (liveMode ? " · watcher active (1.5s)" : " · watcher off") +
      (logLoadedAt ? " · log " + new Date(logLoadedAt).toLocaleTimeString() : " · log not loaded") +
      (inputLoadedAt ? " · input " + new Date(inputLoadedAt).toLocaleTimeString() : " · input not loaded");
  }
  function stopLiveWatcher(){ if(liveTimer){ clearInterval(liveTimer); liveTimer = null; } }
  function startLiveWatcher(){
    stopLiveWatcher();
    if(!liveMode || !selectedFileHandle) return;
    liveTimer = setInterval(async () => {
      if(document.hidden) return;
      const changed = await readHandleFile(false);
      if(changed){
        liveIndicator.classList.add("changed");
        setTimeout(() => liveIndicator.classList.remove("changed"), 900);
      }
    }, 1500);
  }
  function setLiveMode(enabled){
    liveMode = Boolean(enabled && selectedFileHandle);
    updateLiveIndicator();
    if(liveMode) startLiveWatcher(); else stopLiveWatcher();
    updateLiveMeta();
  }

  async function loadHTTP(){
    const response = await fetch("./FINAL_RESULTS.jsonl?t=" + Date.now(), { cache: "no-store" });
    if(!response.ok) throw new Error("HTTP " + response.status);
    if(response.body && response.body.getReader){
      allRecords = []; filtered = []; invalidCount = 0; duplicateCount = 0; pendingTailCount = 0;
      const reader = response.body.getReader();
      const decoder = new TextDecoder("utf-8");
      let carry = "", bytesRead = 0, lastUiUpdate = 0;
      loadStatus.textContent = "⏳ Streaming FINAL_RESULTS.jsonl…";
      loadStatus.className = "badge yellow";
      while(true){
        const part = await reader.read();
        if(part.done) break;
        bytesRead += part.value.byteLength;
        const text = decoder.decode(part.value, { stream: true });
        const combined = carry + text;
        const lines = combined.split(/\r?\n/);
        carry = lines.pop() || "";
        for(let i=0; i<lines.length; i++){
          const clean = lines[i].trim();
          if(!clean) continue;
          try {
            const obj = JSON.parse(clean);
            if(obj && typeof obj === "object" && !Array.isArray(obj)) allRecords.push(obj);
            else invalidCount++;
          } catch(_) { invalidCount++; }
        }
        const now = performance.now();
        if(now - lastUiUpdate > 120){
          lastUiUpdate = now;
          loadStatus.textContent = "⏳ Streaming · " + (bytesRead / 1048576).toFixed(1) + " MB · " + allRecords.length.toLocaleString() + " records";
          dataDetail.textContent = allRecords.length.toLocaleString() + " records · " + invalidCount.toLocaleString() + " invalid";
          await new Promise(resolve => setTimeout(resolve, 0));
        }
      }
      const tail = carry + decoder.decode();
      if(tail.trim()){
        try {
          const obj = JSON.parse(tail.trim());
          if(obj && typeof obj === "object" && !Array.isArray(obj)) allRecords.push(obj);
          else invalidCount++;
        } catch(_) { pendingTailCount++; }
      }
      const unique = deduplicateRecords(allRecords);
      allRecords = unique.records;
      duplicateCount = unique.duplicates;
      finishLoadedData("FINAL_RESULTS.jsonl");
      return;
    }
    const text = await response.text();
    await useLoadedText(text, "FINAL_RESULTS.jsonl");
  }

  async function loadData(){
    hideError();
    if(location.protocol === "file:"){
      updateOfflinePanel();
      if(selectedFile) refreshLocalFile();
      else { loadStatus.textContent = "📂 Select FINAL_RESULTS.jsonl"; loadStatus.className = "badge"; }
      return;
    }
    offlinePanel.hidden = true;
    try { await loadHTTP(); }
    catch(error){
      showError("Could not load FINAL_RESULTS.jsonl: " + error.message);
      loadStatus.textContent = "⚠️ Load failed";
      loadStatus.className = "badge red";
    }
  }

  function parseDateValue(value){
    if(value === null || value === undefined || value === "") return null;
    const d = new Date(value);
    return Number.isNaN(d.getTime()) ? null : d;
  }

  function calcStats(records){
    let registered=0, active=0, expiredStatus=0, pendingDelete=0, redemptionPeriod=0,
        available=0, notRegistered=0, dropped=0, unknown=0, error=0,
        high=0, cnameFound=0, expiring7=0, expiring30=0, expired=0;
    const roots = new Set(), subs = new Set(), cnameRoots = new Set();
    for(const r of records){
      if(r.RootDomain) roots.add(r.RootDomain);
      if(r.Subdomain) subs.add(r.Subdomain);
      if(r.CNAME_ROOT) cnameRoots.add(r.CNAME_ROOT);
      const status = String(r.RegistrationStatus || "UNKNOWN").trim().toUpperCase();
      if(status === "REGISTERED") registered++;
      else if(status === "ACTIVE") active++;
      else if(status === "EXPIRED") expiredStatus++;
      else if(status === "PENDING_DELETE") pendingDelete++;
      else if(status === "REDEMPTION_PERIOD") redemptionPeriod++;
      else if(status === "AVAILABLE") available++;
      else if(status === "NOT_REGISTERED") notRegistered++;
      else if(status === "DROPPED") dropped++;
      else if(status === "ERROR") error++;
      else unknown++;
      const confidence = String(r.LifecycleConfidence || "").toUpperCase();
      if(confidence === "HIGH") high++;
      if(r.CNAME !== undefined && r.CNAME !== null && String(r.CNAME).trim()) cnameFound++;
      const expiry = parseDateValue(r.ExpiryDate);
      if(expiry){
        const days = (expiry.getTime() - Date.now()) / 86400000;
        if(days < 0) expired++;
        else if(days <= 7) expiring7++;
        if(days >= 0 && days <= 30) expiring30++;
      }
    }
    return { total: records.length, rootDomains: roots.size, subdomains: subs.size, cnameRoots: cnameRoots.size,
      registered, active, expiredStatus, pendingDelete, redemptionPeriod, available, notRegistered,
      dropped, unknown, error, highConfidence: high, cnameFound, expiring7, expiring30, expired };
  }

  function filterRecords(){
    const search = globalSearchInput.value.toLowerCase().trim();
    const reg = fRegStatus.value.toUpperCase();
    const conf = fConfidence.value.toUpperCase();
    const dns = fDnsStatus.value.toUpperCase();
    return allRecords.filter(r => {
      if(reg && String(r.RegistrationStatus || "").toUpperCase() !== reg) return false;
      if(conf && String(r.LifecycleConfidence || "").toUpperCase() !== conf) return false;
      if(dns && String(r.DNSStatus || "").toUpperCase() !== dns) return false;
      const life = fLifecycle.value;
      if(life){
        const d = parseDateValue(r.ExpiryDate);
        const days = d ? (d.getTime() - Date.now()) / 86400000 : null;
        const statusUpper = String(r.RegistrationStatus || "").toUpperCase();
        if(life === "EXPIRED"){
          const isExpired = statusUpper === "EXPIRED" || (days !== null && days < 0);
          if(!isExpired) return false;
        }
        if(life === "EXPIRING_7" && !(days !== null && days >= 0 && days <= 7)) return false;
        if(life === "EXPIRING_30" && !(days !== null && days >= 0 && days <= 30)) return false;
      }
      if(search){
        const fields = [r.RootDomain, r.Subdomain, r.CNAME, r.CNAME_ROOT, r.RegistrationStatus,
          r.RawRegistryStatus, r.LifecycleProvider, r.LifecycleConfidence, r.DNSStatus,
          r.DNSProviders, r.IPs, r.ExpiryDate, r.CheckedAt, JSON.stringify(r)];
        const haystack = fields.filter(v => v !== null && v !== undefined && String(v).length)
          .map(v => String(v).toLowerCase()).join(" ");
        if(!haystack.includes(search)) return false;
      }
      return true;
    });
  }

  function sortRecords(records){
    return records.slice().sort((a, b) => {
      let va = getVal(a, sortKey).toUpperCase();
      let vb = getVal(b, sortKey).toUpperCase();
      if(va < vb) return sortAsc ? -1 : 1;
      if(va > vb) return sortAsc ? 1 : -1;
      return 0;
    });
  }

  function applyFiltersAndRender(){
    filtered = sortRecords(filterRecords());
    updateStats(filtered);
    renderLifecycleMonitor(filtered);
    renderTable();
    renderCharts(filtered);
    renderOverviewPanels(filtered);
  }

  function parseInputTotal(text){
    const set = new Set();
    String(text || "").split(/\r?\n/).forEach(line => {
      const d = line.trim().replace(/^https?:\/\//i, "").replace(/\/$/, "");
      if(d && !d.startsWith("#")) set.add(d.toLowerCase());
    });
    return set.size;
  }

  function parseScannerLog(text){
    const lines = String(text || "").split(/\r?\n/);
    let latest = null, lastDomain = "", lastTimestamp = null;
    const events = new Map();
    const simpleRe = /\[(\d{4}-\d{2}-\d{2} [^\]]+)\] \[(INFO|WARN|ERROR)\] \[(\d+)\/(\d+)\] DOMAIN: (.+)$/i;
    const terminalRe = /^\[(\d{4}-\d{2}-\d{2} [^\]]+)\] \[(INFO|WARN|ERROR)\] \[(\d+)\/(\d+)\] DOMAIN: (.+?)\s*\|\s*(COMPLETED_PARTIAL|COMPLETED|FAILED|SKIPPED)\b/i;
    for(let i=0; i<lines.length; i++){
      const line = lines[i];
      const ts = line.match(/^\[(\d{4}-\d{2}-\d{2} [^\]]+)\]/);
      if(ts) lastTimestamp = ts[1];
      const m = line.match(simpleRe);
      if(m){
        const name = m[5].trim();
        latest = { time: m[1], current: Number(m[3]), total: Number(m[4]) };
        let status = "IN_PROGRESS";
        if(/\bCOMPLETED_PARTIAL\b/i.test(name)) status = "PARTIAL";
        else if(/\bCOMPLETED\b/i.test(name)) status = "COMPLETED";
        else if(/\bFAILED\b/i.test(name)) status = "FAILED";
        else if(/\bSKIPPED\b/i.test(name)) status = "SKIPPED";
        else if(/\bstate=PENDING\b/i.test(name)) status = "PENDING";
        const cleanName = name.replace(/\s*\|\s*(COMPLETED_PARTIAL|COMPLETED|FAILED|SKIPPED).*$/i, "")
          .replace(/\s*\|\s*state=PENDING.*$/i, "").trim();
        lastDomain = cleanName;
        events.set(Number(m[3]), { index: Number(m[3]), total: Number(m[4]), domain: cleanName, status, time: m[1] });
      } else {
        const terminal = line.match(terminalRe);
        if(terminal){
          const idx = Number(terminal[3]), domain = terminal[5].trim(), token = terminal[6].toUpperCase();
          const status = token === "COMPLETED_PARTIAL" ? "PARTIAL" : token;
          events.set(idx, { index: idx, total: Number(terminal[4]), domain, status, time: terminal[1] });
          latest = { time: terminal[1], current: idx, total: Number(terminal[4]) };
          lastDomain = domain;
        }
      }
    }
    const ordered = [...events.values()].sort((a, b) => a.index - b.index);
    const counts = { completed: 0, partial: 0, failed: 0, skipped: 0 };
    for(const ev of ordered){
      if(ev.status === "COMPLETED") counts.completed++;
      else if(ev.status === "PARTIAL") counts.partial++;
      else if(ev.status === "FAILED") counts.failed++;
      else if(ev.status === "SKIPPED") counts.skipped++;
    }
    const terminal = counts.completed + counts.partial + counts.failed + counts.skipped;
    const current = ordered.length ? ordered[ordered.length - 1] : null;
    let rate = 0, eta = null;
    if(lastTimestamp && ordered.length){
      const firstTime = new Date(ordered[0].time.replace(" ", "T"));
      const lastTime = new Date(lastTimestamp.replace(" ", "T"));
      const elapsedMin = (lastTime - firstTime) / 60000;
      if(elapsedMin > 0){
        rate = terminal / elapsedMin;
        if(rate > 0){
          const total = latest ? latest.total : inputTotal;
          if(total > terminal) eta = (total - terminal) / rate;
        }
      }
    }
    return { latest, lastDomain, events: ordered, lastTimestamp, currentStatus: current ? current.status : "UNKNOWN",
      currentIndex: current ? current.index : 0, total: latest ? latest.total : 0, counts, terminal, ratePerMinute: rate, etaMinutes: eta };
  }

  function formatDuration(minutes){
    if(!Number.isFinite(minutes) || minutes < 0) return "—";
    const mins = Math.round(minutes), days = Math.floor(mins / 1440),
          hours = Math.floor((mins % 1440) / 60), rem = mins % 60;
    return (days ? days + "d " : "") + (hours ? hours + "h " : "") + rem + "m";
  }

  function updateProgress(){
    const records = allRecords.length;
    dataDetail.textContent = records.toLocaleString() + " records · " + invalidCount.toLocaleString() + " invalid · " +
      duplicateCount.toLocaleString() + " dup" + (pendingTailCount ? " · " + pendingTailCount + " incomplete tail" : "");
    const state = parsedLogState;
    const total = inputTotal;
    const index = state.currentIndex || 0;
    const mismatch = !!(state.total && total && state.total !== total);
    const processed = state.counts.completed + state.counts.partial + state.counts.failed + state.counts.skipped;
    const currentEvent = state.events.length ? state.events[state.events.length - 1] : null;
    const treated = Math.min(total, processed + (currentEvent && ["IN_PROGRESS","PENDING"].includes(currentEvent.status) ? 1 : 0));

    $("statusCompleted").textContent = state.counts.completed.toLocaleString();
    $("statusPartial").textContent = state.counts.partial.toLocaleString();
    $("statusFailed").textContent = state.counts.failed.toLocaleString();
    $("statusSkipped").textContent = state.counts.skipped.toLocaleString();
    $("statusPending").textContent = total ? Math.max(0, total - processed).toLocaleString() : "—";
    const ageMs = logLoadedAt ? Date.now() - logLoadedAt : null;
    $("statusFreshness").textContent = ageMs === null ? "Not loaded" : ageMs < 60000 ? "Just loaded" : Math.floor(ageMs / 60000) + "m ago";
    $("statusFreshness").title = logLoadedAt ? "Dashboard last read the selected log at " + new Date(logLoadedAt).toLocaleString() : "Load scanner.log; log auto-watch is not active.";

    if(total && state.latest && !mismatch){
      const pct = Math.min(100, treated / total * 100);
      progressFill.style.width = pct.toFixed(2) + "%";
      progressValue.textContent = pct.toFixed(1) + "%";
      progressText.textContent = `${treated.toLocaleString()} / ${total.toLocaleString()} domains treated`;
      const rateBits = state.ratePerMinute > 0 ? ` · ${state.ratePerMinute.toFixed(1)} roots/min · ETA ${formatDuration(state.etaMinutes)}` : "";
      progressDetail.textContent = `Log position ${index.toLocaleString()} / ${state.total.toLocaleString()} · ${scannerLastDomain || "domain unknown"}${rateBits}`;
    } else if(total && state.latest && mismatch){
      progressFill.style.width = "0%";
      progressValue.textContent = "CHECK";
      progressText.textContent = `Input ${total.toLocaleString()} ≠ log ${state.total.toLocaleString()}`;
      progressDetail.textContent = "Progress percentage withheld: domains.txt and scanner.log totals do not match.";
    } else if(total){
      progressFill.style.width = "0%";
      progressValue.textContent = "0%";
      progressText.textContent = `0 / ${total.toLocaleString()} domains treated`;
      progressDetail.textContent = "Load scanner.log for accurate progress.";
    } else {
      progressFill.style.width = "0%";
      progressValue.textContent = "—";
      progressText.textContent = "Input total not loaded";
      progressDetail.textContent = "Load domains.txt + scanner.log; results count is not a progress source.";
    }
    renderProHealth();
  }

  function renderProHealth(){
    const grid = $("fileHealthGrid"); if(!grid) return;
    const now = Date.now();
    const files = [
      { name: "FINAL_RESULTS.jsonl", f: selectedFile, readAt: lastLoadedAt, kind: "results" },
      { name: "scanner.log", f: logFile, readAt: logFile && logFile.readAt, kind: "log" },
      { name: "domains.txt", f: inputFile, readAt: inputFile && inputFile.readAt, kind: "input" }
    ];
    grid.innerHTML = files.map(x => {
      const exists = !!x.f;
      const modified = x.f && x.f.lastModified ? x.f.lastModified : 0;
      const age = modified ? Math.max(0, now - modified) : Infinity;
      const stale = exists && (age > 15 * 60 * 1000);
      const status = !exists ? "missing" : stale ? "stale" : "fresh";
      const size = exists ? Number(x.f.size || 0).toLocaleString() + " bytes" : "—";
      const read = x.readAt ? new Date(x.readAt).toLocaleString() : "not read";
      const mod = modified ? new Date(modified).toLocaleString() : "unknown";
      return `<div class="file-health-card"><strong>${x.name}</strong><div style="margin-bottom:7px"><span class="health-pill health-${status}">${status}</span></div><div class="meta">Size: ${size}<br>Last modified: ${mod}<br>Last read: ${read}</div></div>`;
    }).join("");
    const warning = $("progressWarning");
    const mismatch = !!(parsedLogState.total && inputTotal && parsedLogState.total !== inputTotal);
    const logStale = parsedLogState.lastTimestamp && (Date.now() - Date.parse(parsedLogState.lastTimestamp.replace(" ", "T")) > 15 * 60 * 1000);
    if(warning){
      warning.hidden = !(mismatch || logStale);
      warning.textContent = mismatch
        ? `⚠ Progress safety lock: scanner.log total (${parsedLogState.total}) differs from domains.txt (${inputTotal}). Percentage is intentionally not calculated.`
        : logStale ? `⚠ scanner.log appears stale. Last log timestamp: ${parsedLogState.lastTimestamp}.` : "";
    }
    const ev = parsedLogState.events.length ? parsedLogState.events[parsedLogState.events.length - 1] : null;
    const name = $("currentDomainName"), meta = $("currentDomainMeta"), badge = $("currentDomainStatus");
    if(name) name.textContent = ev ? ev.domain : "Waiting for scanner.log";
    if(meta) meta.textContent = ev
      ? `Domain ${ev.index.toLocaleString()} / ${ev.total.toLocaleString()} · ${ev.status} · log timestamp ${ev.time}`
      : "Progress uses terminal/domain events in scanner.log; result-row counts are excluded.";
    if(badge){
      const st = ev ? ev.status : "NO LOG";
      badge.textContent = st;
      badge.className = "health-pill " + (
        /FAILED/.test(st) ? "health-missing" :
        /PARTIAL|PENDING|IN_PROGRESS/.test(st) ? "health-stale" :
        /COMPLETED|SKIPPED/.test(st) ? "health-fresh" : "health-missing"
      );
    }
    const integ = $("integrityMeta");
    if(integ) integ.textContent = `Integrity: ${allRecords.length.toLocaleString()} records loaded · ${invalidCount.toLocaleString()} invalid lines · ${duplicateCount.toLocaleString()} duplicate identities removed · dedup key RootDomain + Subdomain + CNAME + CNAME_ROOT (${snapshotMode === "latest" ? "latest" : "all"} mode).`;
  }

  function setInputText(text, name){
    inputTotal = parseInputTotal(text);
    inputLoadedAt = Date.now();
    inputFile = { name, size: String(text || "").length, lastModified: Date.now(), text, readAt: Date.now() };
    loadStatus.textContent = `📥 Input: ${inputTotal.toLocaleString()} roots`;
    loadStatus.className = "badge";
    updateProgress();
  }
  function setLogText(text, name){
    parsedLogState = parseScannerLog(text);
    scannerPosition = parsedLogState.latest;
    scannerLastDomain = parsedLogState.lastDomain || "";
    logLoadedAt = Date.now();
    logFile = { name, size: String(text || "").length, lastModified: Date.now(), text, readAt: Date.now() };
    if(scannerPosition){
      loadStatus.textContent = `📜 Scanner: ${scannerPosition.current.toLocaleString()} / ${scannerPosition.total.toLocaleString()} · terminal ${parsedLogState.terminal.toLocaleString()} · partial ${parsedLogState.counts.partial.toLocaleString()} · failed ${parsedLogState.counts.failed.toLocaleString()}`;
      loadStatus.className = "badge";
    } else {
      loadStatus.textContent = "⚠️ scanner.log position not found";
      loadStatus.className = "badge red";
    }
    updateProgress();
  }
  async function openAuxFile(kind){
    const picker = kind === "input" ? inputFileInput : logFileInput;
    picker.click();
  }
  function readAuxFile(file, kind){
    if(!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      if(kind === "input"){ inputSourceFile = file; setInputText(reader.result, file.name); }
      else { logSourceFile = file; setLogText(reader.result, file.name); }
    };
    reader.onerror = () => showError(`Could not read ${kind === "input" ? "input file" : "scanner log"}.`);
    reader.readAsText(file);
  }

  function renderOverviewPanels(records){
    const stats = calcStats(records);

    if(threatBadge){
      if(!records.length){
        threatBadge.textContent = "⚠ Awaiting data";
        threatBadge.className = "badge yellow";
      } else if(stats.expired > 0 || stats.expiring7 > 5){
        threatBadge.textContent = "🔴 High";
        threatBadge.className = "badge red";
      } else if(stats.expiring30 > 0 || stats.failed > 0){
        threatBadge.textContent = "🟡 Elevated";
        threatBadge.className = "badge yellow";
      } else {
        threatBadge.textContent = "🟢 Normal";
        threatBadge.className = "badge green";
      }
    }

    const covBadge = $("coverageBadge");
    if(covBadge){
      covBadge.textContent = records.length ? "Live" : "Awaiting";
      covBadge.className = "status-badge " + (records.length ? "registered" : "unknown");
    }
    $("coverageBody").innerHTML = records.length ? `
      <div class="coverage-grid">
        <div class="coverage-item"><strong>${stats.total.toLocaleString()}</strong><span>Records</span></div>
        <div class="coverage-item"><strong>${stats.rootDomains.toLocaleString()}</strong><span>Root domains</span></div>
        <div class="coverage-item"><strong>${stats.subdomains.toLocaleString()}</strong><span>Subdomains</span></div>
        <div class="coverage-item"><strong>${stats.cnameRoots.toLocaleString()}</strong><span>CNAME roots</span></div>
        <div class="coverage-item"><strong>${stats.cnameFound.toLocaleString()}</strong><span>CNAME found</span></div>
        <div class="coverage-item"><strong>${stats.highConfidence.toLocaleString()}</strong><span>HIGH confidence</span></div>
      </div>` : `<div class="empty-state small"><p>Load FINAL_RESULTS.jsonl to see coverage.</p></div>`;

    const statuses = [
      { key: "REGISTERED", count: stats.registered + stats.active, color: "green" },
      { key: "EXPIRED", count: stats.expiredStatus, color: "red" },
      { key: "PENDING_DELETE", count: stats.pendingDelete, color: "yellow" },
      { key: "REDEMPTION", count: stats.redemptionPeriod, color: "yellow" },
      { key: "AVAILABLE", count: stats.available, color: "red" },
      { key: "NOT_REGISTERED", count: stats.notRegistered, color: "red" },
      { key: "DROPPED", count: stats.dropped, color: "red" },
      { key: "UNKNOWN", count: stats.unknown, color: "gray" },
      { key: "ERROR", count: stats.error, color: "yellow" }
    ].filter(s => s.count > 0);
    $("statusBody").innerHTML = records.length && statuses.length ? statuses.map(s => {
      const pct = stats.total ? (s.count / stats.total * 100) : 0;
      return `<div class="status-bar-row"><span class="status-bar-label" title="${escapeHTML(s.key)}">${escapeHTML(s.key)}</span><div class="status-bar-track"><div class="status-bar-fill ${s.color}" style="width:${pct}%"></div></div><span class="status-bar-value">${s.count.toLocaleString()}</span></div>`;
    }).join("") : `<div class="empty-state small"><p>Registration status breakdown appears here.</p></div>`;

    $("lifecycleBody").innerHTML = records.length ? `
      <div class="lifecycle-list">
        <div class="lifecycle-row danger"><span>🔴 Expired</span><strong>${stats.expired.toLocaleString()}</strong></div>
        <div class="lifecycle-row warn"><span>🟠 Expires ≤ 7 days</span><strong>${stats.expiring7.toLocaleString()}</strong></div>
        <div class="lifecycle-row warn"><span>🟡 Expires ≤ 30 days</span><strong>${stats.expiring30.toLocaleString()}</strong></div>
        <div class="lifecycle-row safe"><span>🟢 Registered</span><strong>${(stats.registered + stats.active).toLocaleString()}</strong></div>
      </div>` : `<div class="empty-state small"><p>Expired and expiring domains will appear here.</p></div>`;
  }

  function renderLifecycleMonitor(records){
    const stats = calcStats(records);
    const el = $("lifecycleMonitor");
    if(!el) return;
    el.innerHTML = `
      <div class="lifecycle-alert danger" data-life="expired">
        <div class="la-top"><span>🔴</span><span class="la-count">${stats.expired.toLocaleString()}</span></div>
        <div class="la-label">Expired</div>
      </div>
      <div class="lifecycle-alert warn" data-life="expiring7">
        <div class="la-top"><span>🟠</span><span class="la-count">${stats.expiring7.toLocaleString()}</span></div>
        <div class="la-label">Expires within 7 days</div>
      </div>
      <div class="lifecycle-alert warn" data-life="expiring30">
        <div class="la-top"><span>🟡</span><span class="la-count">${stats.expiring30.toLocaleString()}</span></div>
        <div class="la-label">Expires within 30 days</div>
      </div>
      <div class="lifecycle-alert safe" data-life="registered">
        <div class="la-top"><span>🟢</span><span class="la-count">${(stats.registered + stats.active).toLocaleString()}</span></div>
        <div class="la-label">Registered</div>
      </div>`;
    el.querySelectorAll("[data-life]").forEach(card => {
      card.addEventListener("click", () => {
        const mode = card.dataset.life;
        document.querySelectorAll("[data-quick]").forEach(b => b.classList.remove("active"));
        globalSearchInput.value = ""; fRegStatus.value = ""; fConfidence.value = ""; fDnsStatus.value = ""; fLifecycle.value = "";
        if(mode === "registered") fRegStatus.value = "REGISTERED";
        else if(mode === "expired") fLifecycle.value = "EXPIRED";
        else if(mode === "expiring7") fLifecycle.value = "EXPIRING_7";
        else if(mode === "expiring30") fLifecycle.value = "EXPIRING_30";
        currentPage = 0;
        applyFiltersAndRender();
        document.querySelector('.nav-item[data-page="domains"]')?.click();
      });
    });
  }

  function updateStats(records){
    const stats = calcStats(records);
    updateProgress();
    kpiGrid.innerHTML = records.length ? `
      <div class="kpi-card"><div class="value">${stats.total.toLocaleString()}</div><div class="label">Unique records</div></div>
      <div class="kpi-card"><div class="value">${stats.rootDomains.toLocaleString()}</div><div class="label">Root domains</div></div>
      <div class="kpi-card"><div class="value">${stats.subdomains.toLocaleString()}</div><div class="label">Subdomains</div></div>
      <div class="kpi-card"><div class="value">${stats.cnameRoots.toLocaleString()}</div><div class="label">CNAME roots</div></div>
      <div class="kpi-card accent-green"><div class="value">${(stats.registered + stats.active).toLocaleString()}</div><div class="label">REGISTERED</div></div>
      <div class="kpi-card accent-red"><div class="value">${stats.expiredStatus.toLocaleString()}</div><div class="label">EXPIRED</div></div>
      <div class="kpi-card accent-yellow"><div class="value">${stats.available.toLocaleString()}</div><div class="label">AVAILABLE</div></div>
      <div class="kpi-card accent-blue"><div class="value">${stats.highConfidence.toLocaleString()}</div><div class="label">HIGH confidence</div></div>
      <div class="kpi-card"><div class="value">${stats.cnameFound.toLocaleString()}</div><div class="label">CNAME found</div></div>
      <div class="kpi-card accent-yellow"><div class="value">${stats.expiring7.toLocaleString()}</div><div class="label">Expiring ≤ 7d</div></div>
      <div class="kpi-card accent-red"><div class="value">${stats.expired.toLocaleString()}</div><div class="label">Expired</div></div>` : "";
  }

  const columns = ["RootDomain","Subdomain","CNAME","CNAME_ROOT","RegistrationStatus","LifecycleConfidence","ExpiryDate","DaysLeft","IPs","DNSStatus","CheckedAt"];
  const labels = ["Root","Subdomain","CNAME","CNAME Root","Reg Status","Confidence","Expiry","Days Left","IPs","DNS","Checked At"];

  function renderTable(){
    const total = filtered.length;
    const totalPages = Math.max(1, Math.ceil(total / pageSize));
    if(currentPage >= totalPages) currentPage = totalPages - 1;
    if(currentPage < 0) currentPage = 0;
    const start = currentPage * pageSize;
    const end = Math.min(start + pageSize, total);
    const pageData = filtered.slice(start, end);

    let head = "<tr>";
    columns.forEach((col, index) => {
      const arrow = sortKey === col ? (sortAsc ? " ↑" : " ↓") : "";
      head += `<th data-col="${escapeHTML(col)}" title="Sort by ${escapeHTML(labels[index])}">${escapeHTML(labels[index])}${arrow}</th>`;
    });
    head += "</tr>";
    tableHead.innerHTML = head;
    document.querySelectorAll("#tableHead th").forEach(th => {
      th.addEventListener("click", () => {
        const col = th.dataset.col;
        if(sortKey === col) sortAsc = !sortAsc;
        else { sortKey = col; sortAsc = true; }
        applyFiltersAndRender();
      });
    });

    if(!pageData.length){
      tableBody.innerHTML = `<tr><td colspan="${columns.length}"><div class="empty-state">No records match the current filters.</div></td></tr>`;
    } else {
      let body = "";
      pageData.forEach(rec => {
        const index = allRecords.indexOf(rec);
        body += `<tr class="clickable" data-index="${index}" title="Open domain details">`;
        columns.forEach(col => {
          let value = col === "DaysLeft" ? (() => {
            const d = parseDateValue(rec.ExpiryDate);
            if(!d) return "—";
            const days = Math.floor((d.getTime() - Date.now()) / 86400000);
            return days < 0 ? `${Math.abs(days)}d overdue` : `${days}d`;
          })() : getVal(rec, col);
          let cls = "";
          if(col === "RegistrationStatus") cls = "status-badge " + statusClass(value);
          else if(col === "LifecycleConfidence") cls = "status-badge " + confidenceClass(value);
          const safeValue = escapeHTML(value || "—");
          body += `<td><span class="${cls} ${cls ? "" : "cell-text"}" title="${safeValue}">${safeValue}</span></td>`;
        });
        body += "</tr>";
      });
      tableBody.innerHTML = body;
      document.querySelectorAll("#tableBody tr.clickable").forEach(row => {
        row.addEventListener("click", () => {
          const index = Number(row.dataset.index);
          if(Number.isInteger(index) && allRecords[index]) showDetails(allRecords[index]);
        });
      });
    }

    pageInfo.textContent = `${total ? start + 1 : 0}-${end} / ${total.toLocaleString()}`;
    prevBtn.disabled = currentPage === 0;
    nextBtn.disabled = currentPage >= totalPages - 1;
  }

  function renderCharts(records){
    const registration = { REGISTERED: 0, EXPIRED: 0, PENDING_DELETE: 0, REDEMPTION_PERIOD: 0, AVAILABLE: 0, NOT_REGISTERED: 0, DROPPED: 0, UNKNOWN: 0, ERROR: 0 };
    const confidence = { HIGH: 0, MEDIUM: 0, LOW: 0 };
    const cnameRoots = {}, rootDomains = {}, dnsAgreement = {};
    records.forEach(r => {
      const status = String(r.RegistrationStatus || "").toUpperCase();
      if(registration[status] !== undefined) registration[status]++;
      const conf = String(r.LifecycleConfidence || "").toUpperCase();
      if(confidence[conf] !== undefined) confidence[conf]++;
      const cname = r.CNAME_ROOT || "unknown";
      cnameRoots[cname] = (cnameRoots[cname] || 0) + 1;
      const root = r.RootDomain || "unknown";
      rootDomains[root] = (rootDomains[root] || 0) + 1;
      const agreement = String(r.DNSAgreement ?? "unknown");
      dnsAgreement[agreement] = (dnsAgreement[agreement] || 0) + 1;
    });
    const topCname = Object.entries(cnameRoots).sort((a, b) => b[1] - a[1]).slice(0, 10);
    const topRoot = Object.entries(rootDomains).sort((a, b) => b[1] - a[1]).slice(0, 10);
    const container = $("chartContainer");
    if(!container) return;
    container.innerHTML = `
      <div class="chart-card"><h4>Registration</h4>${renderBar(registration, { REGISTERED:"green", EXPIRED:"red", PENDING_DELETE:"yellow", REDEMPTION_PERIOD:"yellow", AVAILABLE:"red", NOT_REGISTERED:"red", DROPPED:"red", UNKNOWN:"yellow", ERROR:"yellow" })}</div>
      <div class="chart-card"><h4>Confidence</h4>${renderBar(confidence, { HIGH:"green", MEDIUM:"yellow", LOW:"red" })}</div>
      <div class="chart-card"><h4>DNS Agreement</h4>${renderBar(dnsAgreement, {})}</div>
      <div class="chart-card"><h4>Top CNAME Roots</h4>${renderTop(topCname)}</div>
      <div class="chart-card"><h4>Top Root Domains</h4>${renderTop(topRoot)}</div>`;
  }
  function renderBar(map, colorMap){
    const total = Object.values(map).reduce((a, b) => a + b, 0) || 1;
    return Object.entries(map).map(([key, value]) => {
      const pct = value / total * 100;
      const cls = colorMap[key] ? "fill-" + colorMap[key] : "fill-blue";
      return `<div class="chart-bar"><span class="label">${escapeHTML(key)}</span><div class="bar"><div class="fill ${cls}" style="width:${pct}%"></div></div><span>${value.toLocaleString()}</span></div>`;
    }).join("");
  }
  function renderTop(entries){
    if(!entries.length) return `<div class="text-muted">No data</div>`;
    const max = entries[0][1] || 1;
    return entries.map(([key, value]) => {
      const pct = Math.min(100, value / max * 100);
      return `<div class="chart-bar"><span class="label" title="${escapeHTML(key)}">${escapeHTML(key)}</span><div class="bar"><div class="fill fill-blue" style="width:${pct}%"></div></div><span>${value.toLocaleString()}</span></div>`;
    }).join("");
  }

  function detailField(key, value, full = false){
    if(value === undefined || value === null || value === "") return "";
    return `<div class="field-card ${full ? "full" : ""}"><span class="key">${escapeHTML(key)}</span><span class="val">${escapeHTML(displayValue(value))}</span></div>`;
  }
  function showDetails(rec){
    const root = rec.RootDomain || "Record";
    const sub = rec.Subdomain || "";
    drawerTitle.textContent = "📄 " + root;
    drawerSubtitle.textContent = sub || "Domain record";
    const reg = String(rec.RegistrationStatus || "UNKNOWN").toUpperCase();
    const conf = String(rec.LifecycleConfidence || "UNKNOWN").toUpperCase();
    const dns = String(rec.DNSStatus || "UNKNOWN").toUpperCase();
    detailSummary.innerHTML = `
      <span class="detail-pill ${statusClass(reg)}">● ${escapeHTML(reg)}</span>
      <span class="detail-pill ${conf === "HIGH" ? "green" : conf === "MEDIUM" ? "yellow" : conf === "LOW" ? "red" : "blue"}">◉ ${escapeHTML(conf)}</span>
      <span class="detail-pill blue">◇ ${escapeHTML(dns)}</span>
      ${rec.DNSAgreement !== undefined && rec.DNSAgreement !== null ? `<span class="detail-pill blue">DNS ${escapeHTML(rec.DNSAgreement)}/3</span>` : ""}`;
    let html = "";
    html += `<div class="drawer-section"><h3>Domain</h3><div class="field-grid">
      ${detailField("Root Domain", rec.RootDomain)}${detailField("Subdomain", rec.Subdomain)}
      ${detailField("CNAME", rec.CNAME, true)}${detailField("CNAME Root", rec.CNAME_ROOT)}</div></div>`;
    html += `<div class="drawer-section"><h3>DNS / CNAME</h3><div class="field-grid">
      ${detailField("DNS Status", rec.DNSStatus)}
      ${detailField("DNS Agreement", rec.DNSAgreement !== undefined ? rec.DNSAgreement + " / 3" : "")}
      ${detailField("DNS Providers", rec.DNSProviders, true)}${detailField("IPs", rec.IPs, true)}</div></div>`;
    html += `<div class="drawer-section"><h3>Lifecycle / RDAP</h3><div class="field-grid">
      ${detailField("Registration Status", rec.RegistrationStatus)}
      ${detailField("Raw Registry Status", rec.RawRegistryStatus)}
      ${detailField("Lifecycle Provider", rec.LifecycleProvider)}
      ${detailField("Lifecycle Confidence", rec.LifecycleConfidence)}
      ${detailField("Expiry Date", rec.ExpiryDate)}
      ${detailField("Checked At", rec.CheckedAt)}</div></div>`;
    html += `<div class="drawer-section"><details class="raw-details"><summary>🧾 Raw JSON</summary><pre>${escapeHTML(JSON.stringify(rec, null, 2))}</pre></details></div>`;
    drawerBody.innerHTML = html;
    drawerOverlay.classList.add("open");
    document.body.style.overflow = "hidden";
  }
  function closeDrawer(){
    drawerOverlay.classList.remove("open");
    document.body.style.overflow = "";
  }

  let clockTimer = null;
  function refreshLiveLifecycle(){
    if(!allRecords.length) return;
    updateStats(filtered);
    renderLifecycleMonitor(filtered);
    renderTable();
    renderProHealth();
    renderOverviewPanels(filtered);
  }
  function startClock(){
    if(clockTimer) clearInterval(clockTimer);
    clockTimer = setInterval(refreshLiveLifecycle, 30000);
  }

  function excelSafeValue(value){
    if(value === null || value === undefined) return "";
    let text = "";
    if(Array.isArray(value)){
      text = value.map(item => item === null || item === undefined ? "" : String(item)).join(", ");
    } else if(typeof value === "object"){
      try { text = JSON.stringify(value); } catch(_) { text = String(value); }
    } else { text = String(value); }
    if(/^[=+\-@]/.test(text)) return "'" + text;
    return text;
  }
  function getExportValue(record, col){
    if(col === "DaysLeft"){
      const d = parseDateValue(record.ExpiryDate);
      if(!d) return "";
      const days = Math.floor((d.getTime() - Date.now()) / 86400000);
      return days < 0 ? `${Math.abs(days)}d overdue` : `${days}d`;
    }
    return getVal(record, col);
  }
  function buildExcelChunkSheet(records, start, end){
    const rowCount = end - start;
    const rows = new Array(rowCount + 1);
    rows[0] = columns.slice();
    for(let i=start; i<end; i++){
      const record = records[i];
      const row = new Array(columns.length);
      for(let c=0; c<columns.length; c++){
        row[c] = excelSafeValue(getExportValue(record, columns[c]));
      }
      rows[i - start + 1] = row;
    }
    const ws = XLSX.utils.aoa_to_sheet(rows);
    ws["!cols"] = [{wch:30},{wch:42},{wch:42},{wch:32},{wch:20},{wch:20},{wch:24},{wch:18},{wch:35},{wch:18},{wch:25}];
    return ws;
  }
  function buildSummarySheet(){
    const stats = calcStats(filtered);
    const rows = [
      ["Z Scanner Dashboard V4", ""],
      ["Exported At", new Date().toISOString()],
      ["Records Exported", stats.total],
      ["Root Domains", stats.rootDomains],
      ["Subdomains", stats.subdomains],
      ["CNAME Roots", stats.cnameRoots],
      ["REGISTERED", stats.registered + stats.active],
      ["EXPIRED", stats.expiredStatus],
      ["PENDING_DELETE", stats.pendingDelete],
      ["REDEMPTION_PERIOD", stats.redemptionPeriod],
      ["AVAILABLE", stats.available],
      ["NOT_REGISTERED", stats.notRegistered],
      ["DROPPED", stats.dropped],
      ["UNKNOWN", stats.unknown],
      ["ERROR", stats.error],
      ["HIGH Confidence", stats.highConfidence],
      ["CNAME Found", stats.cnameFound],
      ["Expired", stats.expired],
      ["Expiring ≤ 7 Days", stats.expiring7],
      ["Expiring ≤ 30 Days", stats.expiring30],
      ["", ""], ["Filters", ""],
      ["Search", globalSearchInput.value || "All"],
      ["Registration Status", fRegStatus.value || "All"],
      ["Lifecycle Confidence", fConfidence.value || "All"],
      ["DNS Status", fDnsStatus.value || "All"],
      ["Lifecycle", fLifecycle.value || "All"],
      ["", ""],
      ["Scanner Position", scannerPosition ? `${scannerPosition.current} / ${scannerPosition.total}` : "Not loaded"],
      ["Scanner Last Domain", scannerLastDomain || ""],
      ["Input Total", inputTotal || "Not loaded"],
      ["Invalid JSONL Lines", invalidCount]
    ];
    const ws = XLSX.utils.aoa_to_sheet(rows);
    ws["!cols"] = [{wch:28},{wch:55}];
    return ws;
  }
  function buildCnameRootsSheet(){
    const counts = new Map();
    for(let i=0; i<filtered.length; i++){
      const root = String(filtered[i].CNAME_ROOT || "").trim();
      if(!root) continue;
      counts.set(root, (counts.get(root) || 0) + 1);
    }
    const rows = [["CNAME_ROOT","Records"]];
    const entries = Array.from(counts.entries()).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
    for(const [root, count] of entries) rows.push([excelSafeValue(root), count]);
    const ws = XLSX.utils.aoa_to_sheet(rows);
    ws["!cols"] = [{wch:42},{wch:14}];
    return ws;
  }
  function buildRootDomainsSheet(){
    const counts = new Map();
    for(let i=0; i<filtered.length; i++){
      const root = String(filtered[i].RootDomain || "").trim();
      if(!root) continue;
      counts.set(root, (counts.get(root) || 0) + 1);
    }
    const rows = [["RootDomain","Records"]];
    const entries = Array.from(counts.entries()).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
    for(const [root, count] of entries) rows.push([excelSafeValue(root), count]);
    const ws = XLSX.utils.aoa_to_sheet(rows);
    ws["!cols"] = [{wch:42},{wch:14}];
    return ws;
  }
  function exportCSVFallback(){
    if(!filtered.length){ showError("No filtered records to export."); return; }
    const cols = [...new Set(filtered.flatMap(r => Object.keys(r)))];
    const csvCell = v => {
      let x = v == null ? "" : String(v);
      if(/^[=+@\-\t\r]/.test(x)) x = "'" + x;
      return '"' + x.replace(/"/g, '""') + '"';
    };
    const csv = [cols.map(csvCell).join(","), ...filtered.map(r => cols.map(k => csvCell(r[k])).join(","))].join("\r\n");
    const blob = new Blob(["\uFEFF", csv], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = "CNAME-SCANNER-RESULTS.csv";
    document.body.appendChild(a); a.click(); a.remove();
    URL.revokeObjectURL(url);
    loadStatus.textContent = "CSV exported · XLSX library unavailable";
    loadStatus.className = "badge";
  }
  function exportXLSX(){
    if(typeof XLSX === "undefined"){ exportCSVFallback(); return; }
    if(!filtered || !filtered.length){ showError("No filtered records to export."); return; }
    hideError();
    exportXlsxBtn.disabled = true;
    const originalText = exportXlsxBtn.textContent;
    exportXlsxBtn.textContent = "⏳ Excel…";
    setTimeout(function(){
      try {
        const workbook = XLSX.utils.book_new();
        XLSX.utils.book_append_sheet(workbook, buildSummarySheet(), "Summary");
        const total = filtered.length;
        const CHUNK = 50000;
        const sheetCount = Math.ceil(total / CHUNK);
        for(let sheetIndex = 0; sheetIndex < sheetCount; sheetIndex++){
          const start = sheetIndex * CHUNK;
          const end = Math.min(start + CHUNK, total);
          const ws = buildExcelChunkSheet(filtered, start, end);
          const sheetName = sheetCount === 1 ? "Results" : `Results_${sheetIndex + 1}`;
          XLSX.utils.book_append_sheet(workbook, ws, sheetName);
          exportXlsxBtn.textContent = `⏳ Excel ${sheetIndex + 1}/${sheetCount}…`;
        }
        XLSX.utils.book_append_sheet(workbook, buildCnameRootsSheet(), "CNAME Roots");
        XLSX.utils.book_append_sheet(workbook, buildRootDomainsSheet(), "Root Domains");
        const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
        const filename = "cname_dashboard_filtered_" + timestamp + ".xlsx";
        XLSX.writeFile(workbook, filename, { bookType: "xlsx", compression: true });
        loadStatus.textContent = "⬇ Excel exported · " + filtered.length.toLocaleString() + " records · " + sheetCount + (sheetCount === 1 ? " result sheet" : " result sheets");
        loadStatus.className = "badge green";
      } catch(error){
        console.error("XLSX export error:", error);
        showError("Excel export failed: " + (error && error.message ? error.message : String(error)));
        loadStatus.textContent = "⚠️ Excel export failed";
        loadStatus.className = "badge red";
      } finally {
        exportXlsxBtn.disabled = false;
        exportXlsxBtn.textContent = originalText;
      }
    }, 50);
  }

  loadInputBtn.addEventListener("click", () => openAuxFile("input"));
  loadLogBtn.addEventListener("click", () => openAuxFile("log"));
  inputFileInput.addEventListener("change", () => readAuxFile(inputFileInput.files && inputFileInput.files[0], "input"));
  logFileInput.addEventListener("change", () => readAuxFile(logFileInput.files && logFileInput.files[0], "log"));
  loadFileBtn.addEventListener("click", () => openLocalFile());
  fileInput.addEventListener("change", () => readLocalFile(fileInput.files && fileInput.files[0]));
  liveBtn.addEventListener("click", () => {
    if(!selectedFileHandle){
      loadStatus.textContent = "📂 Load JSONL with the Live watcher enabled";
      loadStatus.className = "badge";
      openLocalFile();
      return;
    }
    setLiveMode(!liveMode);
  });
  refreshBtn.addEventListener("click", () => loadData());
  exportXlsxBtn.addEventListener("click", exportXLSX);
  pageSizeSelect.addEventListener("change", () => {
    pageSize = Number(pageSizeSelect.value);
    currentPage = 0;
    renderTable();
  });
  prevBtn.addEventListener("click", () => {
    if(currentPage > 0){ currentPage--; renderTable(); window.scrollTo({ top: 0, behavior: "smooth" }); }
  });
  nextBtn.addEventListener("click", () => {
    const pages = Math.ceil(filtered.length / pageSize);
    if(currentPage < pages - 1){ currentPage++; renderTable(); window.scrollTo({ top: 0, behavior: "smooth" }); }
  });
  [globalSearchInput, fRegStatus, fConfidence, fDnsStatus, fLifecycle].forEach(element => {
    element.addEventListener("input", () => { currentPage = 0; applyFiltersAndRender(); });
    element.addEventListener("change", () => { currentPage = 0; applyFiltersAndRender(); });
  });

  let topbarSearchTimer;
  globalSearch.addEventListener("input", () => {
    clearTimeout(topbarSearchTimer);
    topbarSearchTimer = setTimeout(() => {
      const v = globalSearch.value;
      if(!v.trim()) return;
      const navBtn = document.querySelector('.nav-item[data-page="domains"]');
      if(!navBtn) return;
      if(!document.getElementById("domainsPage").classList.contains("active")) navBtn.click();
      globalSearchInput.value = v;
      currentPage = 0;
      applyFiltersAndRender();
    }, 250);
  });

  document.querySelectorAll("[data-quick]").forEach(button => {
    button.addEventListener("click", () => {
      const mode = button.dataset.quick;
      document.querySelectorAll("[data-quick]").forEach(b => b.classList.remove("active"));
      button.classList.add("active");
      globalSearchInput.value = ""; fRegStatus.value = ""; fConfidence.value = ""; fDnsStatus.value = ""; fLifecycle.value = "";
      if(mode === "registered") fRegStatus.value = "REGISTERED";
      else if(mode === "pending_delete") fRegStatus.value = "PENDING_DELETE";
      else if(mode === "redemption") fRegStatus.value = "REDEMPTION_PERIOD";
      else if(mode === "available") fRegStatus.value = "AVAILABLE";
      else if(mode === "unknown") fRegStatus.value = "UNKNOWN";
      else if(mode === "high") fConfidence.value = "HIGH";
      else if(mode === "expiring") fLifecycle.value = "EXPIRING_7";
      else if(mode === "expired") fLifecycle.value = "EXPIRED";
      currentPage = 0;
      applyFiltersAndRender();
    });
  });
  $("drawerClose").addEventListener("click", closeDrawer);
  drawerOverlay.addEventListener("click", event => { if(event.target === drawerOverlay) closeDrawer(); });
  document.addEventListener("keydown", event => {
    if(event.key === "Escape" && drawerOverlay.classList.contains("open")) closeDrawer();
  });

  function checkMonitorFiles(){ renderProHealth(); updateProgress(); }
  $("snapshotModeSelect")?.addEventListener("change", async e => {
    snapshotMode = e.target.value === "all" ? "all" : "latest";
    if(selectedFile){
      try { await loadJSONLBlob(selectedFile, selectedFile.name); }
      catch(err) { showError("Could not reload JSONL under the selected snapshot policy: " + err.message); }
    } else {
      loadStatus.textContent = "Snapshot policy set to " + snapshotMode + "; select results to apply it.";
      loadStatus.className = "badge";
    }
  });
  $("monitorRefreshBtn")?.addEventListener("click", () => checkMonitorFiles());
  $("autoRefreshToggle")?.addEventListener("click", () => {
    autoMonitorOn = !autoMonitorOn;
    $("autoRefreshToggle").textContent = autoMonitorOn ? "Auto: On" : "Auto: Off";
    if(autoMonitorTimer) clearInterval(autoMonitorTimer);
    autoMonitorTimer = null;
    if(autoMonitorOn){
      const ms = Number($("autoRefreshInterval").value || 10) * 1000;
      autoMonitorTimer = setInterval(async () => {
        try {
          await refreshLocalFile();
          if(inputSourceFile){ const txt = await inputSourceFile.text(); setInputText(txt, inputSourceFile.name); }
          if(logSourceFile){ const txt = await logSourceFile.text(); setLogText(txt, logSourceFile.name); }
          checkMonitorFiles();
        } catch(e) { console.warn("Auto refresh check failed", e); }
      }, ms);
    }
  });
  $("autoRefreshInterval")?.addEventListener("change", () => {
    if(autoMonitorOn){ $("autoRefreshToggle").click(); $("autoRefreshToggle").click(); }
  });

  if(exportXlsxBtn){
    exportXlsxBtn.textContent = typeof XLSX !== "undefined" ? "⬇ Export XLSX" : "⬇ Export CSV";
  }
  startClock();
  updateLiveIndicator();
  updateLiveMeta();
  if(document.readyState === "loading"){
    document.addEventListener("DOMContentLoaded", loadData);
  } else {
    loadData();
  }
})();