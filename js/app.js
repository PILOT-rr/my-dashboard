"use strict";
(() => {
 const LOGIN_EMAIL="ziadmabrouki@scanner.gov", LOGIN_PASSWORD="scanner2002";
 const DB_NAME="z-scanner-ultra", DB_VERSION=1; let db=null;
 const $=id=>document.getElementById(id), loginScreen=$("loginScreen"), app=$("app"), toast=$("toast");

 function notify(message,isError=false){toast.textContent=message;toast.classList.toggle("error",isError);toast.classList.add("show");clearTimeout(notify.timer);notify.timer=setTimeout(()=>toast.classList.remove("show"),3600)}

 function openDB(){return new Promise((resolve,reject)=>{if(!window.indexedDB)return reject(new Error("IndexedDB is unavailable in this browser."));const req=indexedDB.open(DB_NAME,DB_VERSION);req.onupgradeneeded=()=>{const d=req.result;if(!d.objectStoreNames.contains("snapshots")){const s=d.createObjectStore("snapshots",{keyPath:"id"});s.createIndex("createdAt","createdAt")}if(!d.objectStoreNames.contains("settings"))d.createObjectStore("settings",{keyPath:"key"})};req.onsuccess=()=>{db=req.result;db.onversionchange=()=>{db.close();db=null;notify("Database schema changed in another tab. Reload this app.",true)};resolve(db)};req.onerror=()=>reject(req.error||new Error("Database open failed."));req.onblocked=()=>reject(new Error("Close other Z Scanner tabs, then retry."))})}
 function transaction(storeName,mode="readonly"){if(!db)throw new Error("Local database is not open.");return db.transaction(storeName,mode)}
 function request(req){return new Promise((resolve,reject)=>{req.onsuccess=()=>resolve(req.result);req.onerror=()=>reject(req.error||new Error("Database request failed."))})}
 async function getAllSnapshots(){return request(transaction("snapshots").objectStore("snapshots").getAll())}
 async function getAllSettings(){return request(transaction("settings").objectStore("settings").getAll())}
 async function put(name,value){return new Promise((resolve,reject)=>{const tx=transaction(name,"readwrite");tx.objectStore(name).put(value);tx.oncomplete=()=>resolve();tx.onerror=()=>reject(tx.error||new Error("Database write failed."));tx.onabort=()=>reject(tx.error||new Error("Database write aborted."))})}
 async function getSetting(key){const row=await request(transaction("settings").objectStore("settings").get(key));return row?.value}
 function escapeHTML(v){return String(v??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]))}

 function setTheme(theme){
   const value = theme === "light" ? "light" : "dark";
   document.documentElement.dataset.theme = value;
   const themeBtn = $("themeBtn");
   if(themeBtn) themeBtn.textContent = value === "dark" ? "☀️" : "🌙";
   const themeSelect = $("themeSelect");
   if(themeSelect) themeSelect.value = value;
 }
 async function saveTheme(){
   try { await put("settings",{key:"theme",value:document.documentElement.dataset.theme}) } catch(_){}
 }

 function showApp(){loginScreen.hidden=true;app.hidden=false}
 function go(page){
   if(!page) return;
   document.querySelectorAll(".page").forEach(p=>p.classList.toggle("active",p.id===page+"Page"));
   document.querySelectorAll(".nav-item[data-page]").forEach(b=>b.classList.toggle("active",b.dataset.page===page));
   if(page==="history")renderHistory().catch(e=>notify("History load failed: "+e.message,true));
   window.scrollTo({top:0,behavior:"auto"});
 }

 document.querySelectorAll(".nav-item[data-page]").forEach(b=>b.addEventListener("click",()=>go(b.dataset.page)));

 $("themeBtn").addEventListener("click", async () => {
   const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
   setTheme(next);
   try { await saveTheme() } catch(e){ notify("Theme save failed: "+e.message,true) }
 });

 $("loginForm").addEventListener("submit",async e=>{
   e.preventDefault();
   const email=$("username").value.trim().toLowerCase(),password=$("password").value;
   if(email!==LOGIN_EMAIL||password!==LOGIN_PASSWORD){$("loginError").hidden=false;return}
   $("loginError").hidden=true;
   try{await openDB();await loadSettings();sessionStorage.setItem("zsu-session","active");showApp();go("overview");notify("Workspace ready. Load your scanner result files.")}
   catch(err){notify("Local storage unavailable: "+err.message,true)}
 });

 $("logoutBtn").addEventListener("click",()=>{sessionStorage.removeItem("zsu-session");app.hidden=true;loginScreen.hidden=false;$("password").value=""});

 async function loadSettings(){
   const theme=await getSetting("theme");
   if(theme==="light"||theme==="dark") setTheme(theme);
   const name=await getSetting("profileName");
   if(name)$("profileName").value=name;
   const policy=await getSetting("snapshotPolicy");
   if(policy==="all"||policy==="latest"){
     $("snapshotPolicy").value=policy;
     const engineSelect=$("snapshotModeSelect");
     if(engineSelect){ engineSelect.value=policy; engineSelect.dispatchEvent(new Event("change")); }
   }
 }

 $("themeSelect").addEventListener("change",async()=>{setTheme($("themeSelect").value);try{await saveTheme()}catch(e){notify("Theme save failed: "+e.message,true)}});

 $("saveProfile").addEventListener("click",async()=>{const name=$("profileName").value.trim();if(!name){notify("Display name cannot be empty.",true);$("profileName").focus();return}try{await put("settings",{key:"profileName",value:name});notify("Profile saved locally.")}catch(e){notify("Profile save failed: "+e.message,true)}});

 $("saveSettings").addEventListener("click",async()=>{try{await saveTheme();await put("settings",{key:"snapshotPolicy",value:$("snapshotPolicy").value});const engineSelect=$("snapshotModeSelect");if(engineSelect){engineSelect.value=$("snapshotPolicy").value;engineSelect.dispatchEvent(new Event("change"))}notify("Settings saved locally.")}catch(e){notify("Settings save failed: "+e.message,true)}});

 function currentMetrics(){
   const status=$("loadStatus")?.textContent?.trim()||"Not loaded";
   const loaded=/loaded|records|streaming|exported/i.test(status)&&!/failed|select final|loading…/i.test(status);
   const value=$("kpiGrid")?.querySelector(".kpi-card .value")?.textContent?.replace(/,/g,"");
   const records=value!==undefined&&value!==""&&Number.isFinite(Number(value))?Number(value):null;
   const completed=Number($("statusCompleted")?.textContent?.replace(/,/g,""));
   const invalidMatch=$("dataDetail")?.textContent?.match(/([\d,]+)\s+invalid/i);
   return {records,completed:Number.isFinite(completed)?completed:null,invalid:invalidMatch?Number(invalidMatch[1].replace(/,/g,"")):null,progress:$("progressText")?.textContent?.trim()||"Unknown",integrity:$("integrityMeta")?.textContent?.trim()||"Unknown",sourceStatus:status,loaded,createdAt:new Date().toISOString()};
 }

 async function makeSnapshot(){
   const metrics=currentMetrics();
   if(!metrics.loaded){notify("Load FINAL_RESULTS.jsonl before saving a snapshot.",true);return}
   const snapshot={id:crypto.randomUUID?crypto.randomUUID():Date.now()+"-"+Math.random().toString(16).slice(2),createdAt:new Date().toISOString(),metrics,manual:true,source:"Z Scanner Ultra V2.0"};
   const all=await getAllSnapshots();
   if($("snapshotPolicy").value==="latest"&&all.some(s=>JSON.stringify({...s.metrics,createdAt:undefined})===JSON.stringify({...metrics,createdAt:undefined}))){notify("Duplicate snapshot skipped: metrics match an existing snapshot.");return}
   await put("snapshots",snapshot);await renderHistory();notify("Snapshot saved locally.");
 }
 $("createSnapshot").addEventListener("click",()=>makeSnapshot().catch(e=>notify("Snapshot failed: "+e.message,true)));

 function showSnapshotDetails(s){$("snapshotDialogTitle").textContent="Snapshot · "+new Date(s.createdAt).toLocaleString();$("snapshotDialogBody").textContent=JSON.stringify(s,null,2);$("snapshotDialog").hidden=false;$("closeSnapshotDialog").focus()}

 function compareSnapshots(newer,older){
   const fields=[["Records","records"],["Completed","completed"],["Invalid lines","invalid"]];
   const rows=fields.map(([label,key])=>{const a=newer.metrics?.[key],b=older.metrics?.[key],valid=Number.isFinite(a)&&Number.isFinite(b),delta=valid?a-b:null;return `<tr><td>${escapeHTML(label)}</td><td>${valid?b.toLocaleString():"Unknown"}</td><td>${valid?a.toLocaleString():"Unknown"}</td><td>${delta===null?"Unknown":(delta>0?"+":"")+delta.toLocaleString()}</td></tr>`}).join("");
   $("snapshotCompare").innerHTML=`<h3>Snapshot comparison</h3><p class="muted">Newer: ${escapeHTML(new Date(newer.createdAt).toLocaleString())} · Older: ${escapeHTML(new Date(older.createdAt).toLocaleString())}</p><div class="table-panel"><table class="history-table"><thead><tr><th>Metric</th><th>Older</th><th>Newer</th><th>Change</th></tr></thead><tbody>${rows}</tbody></table></div><p class="muted small-text">Unknown values are not converted to zero.</p>`;
   $("snapshotCompare").hidden=false;$("snapshotCompare").scrollIntoView({behavior:"smooth",block:"start"});
 }

 async function renderHistory(){
   if(!db)return;
   const items=(await getAllSnapshots()).sort((a,b)=>String(b.createdAt).localeCompare(String(a.createdAt)));
   $("snapshotCount").textContent=items.length.toLocaleString();
   $("latestSnapshot").textContent=items[0]?new Date(items[0].createdAt).toLocaleString():"—";
   $("historyRows").innerHTML=items.length?items.map((s,i)=>`<tr><td>${escapeHTML(new Date(s.createdAt).toLocaleString())}</td><td>${s.metrics?.records==null?"Unknown":Number(s.metrics.records).toLocaleString()}</td><td>${s.metrics?.completed==null?"Unknown":Number(s.metrics.completed).toLocaleString()}</td><td>${escapeHTML(s.metrics?.integrity||"Unknown")}</td><td><button data-view="${escapeHTML(s.id)}">Details</button><button data-compare="${escapeHTML(s.id)}" ${i===items.length-1?'disabled title="No older snapshot"':''}>Compare</button><button data-delete="${escapeHTML(s.id)}">Delete</button></td></tr>`).join(""):'<tr><td colspan="5" class="empty">No history available.</td></tr>';
   $("historyRows").querySelectorAll("[data-view]").forEach(b=>b.addEventListener("click",()=>{const s=items.find(x=>x.id===b.dataset.view);if(s)showSnapshotDetails(s)}));
   $("historyRows").querySelectorAll("[data-compare]").forEach(b=>b.addEventListener("click",()=>{const i=items.findIndex(x=>x.id===b.dataset.compare);if(i>=0&&items[i+1])compareSnapshots(items[i],items[i+1])}));
   $("historyRows").querySelectorAll("[data-delete]").forEach(b=>b.addEventListener("click",async()=>{if(!confirm("Delete this snapshot?"))return;try{const tx=transaction("snapshots","readwrite");tx.objectStore("snapshots").delete(b.dataset.delete);tx.oncomplete=()=>renderHistory().then(()=>notify("Snapshot deleted.")).catch(e=>notify(e.message,true));tx.onerror=()=>notify("Delete failed: "+tx.error.message,true)}catch(e){notify("Delete failed: "+e.message,true)}}));
   $("historyMessage").textContent=items.length?"Snapshots are stored locally in IndexedDB.":"No snapshots saved yet. Load scanner files, then save a snapshot.";
 }

 $("closeSnapshotDialog").addEventListener("click",()=>$("snapshotDialog").hidden=true);
 $("snapshotDialog").addEventListener("click",e=>{if(e.target===$("snapshotDialog"))$("snapshotDialog").hidden=true});
 document.addEventListener("keydown",e=>{if(e.key==="Escape")$("snapshotDialog").hidden=true});

 function downloadJSON(obj,name){const blob=new Blob([JSON.stringify(obj,null,2)],{type:"application/json"}),url=URL.createObjectURL(blob),a=document.createElement("a");a.href=url;a.download=name;document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1500)}
 $("exportBackup").addEventListener("click",async()=>{try{downloadJSON({app:"Z Scanner Ultra",schemaVersion:2,exportedAt:new Date().toISOString(),snapshots:await getAllSnapshots(),settings:await getAllSettings()},"z-scanner-ultra-backup-"+new Date().toISOString().slice(0,10)+".json");notify("Backup exported.")}catch(e){notify("Backup export failed: "+e.message,true)}});
 $("importBackup").addEventListener("change",async e=>{const file=e.target.files?.[0];if(!file)return;try{const b=JSON.parse(await file.text());if(!b||b.app!=="Z Scanner Ultra"||![1,2].includes(b.schemaVersion)||!Array.isArray(b.snapshots)||!Array.isArray(b.settings))throw new Error("Unsupported backup format or schema.");if(b.snapshots.length>100000||b.settings.length>100)throw new Error("Backup exceeds import limits.");if(!confirm(`Import ${b.snapshots.length} snapshots? Existing data will be preserved.`))return;const existing=await getAllSnapshots(),ids=new Set(existing.map(s=>s.id));let added=0;for(const s of b.snapshots){if(!s||typeof s.id!=="string"||!s.id||!Number.isFinite(Date.parse(s.createdAt))||!s.metrics||typeof s.metrics!=="object"||Array.isArray(s.metrics)||ids.has(s.id))continue;await put("snapshots",s);ids.add(s.id);added++}for(const s of b.settings){if(s&&["theme","profileName","snapshotPolicy"].includes(s.key)&&Object.prototype.hasOwnProperty.call(s,"value"))await put("settings",s)}await loadSettings();await renderHistory();notify(`Import complete: ${added} snapshots added; existing records preserved.`)}catch(err){notify("Backup rejected: "+err.message,true)}finally{e.target.value=""}});
 $("clearHistory").addEventListener("click",()=>{if(!confirm("Delete all saved snapshots? Settings will be preserved."))return;try{const tx=transaction("snapshots","readwrite");tx.objectStore("snapshots").clear();tx.oncomplete=()=>renderHistory().then(()=>notify("Saved snapshots cleared.")).catch(e=>notify(e.message,true));tx.onerror=()=>notify("Clear failed: "+tx.error.message,true)}catch(e){notify("Clear failed: "+e.message,true)}});

 async function boot(){
   if(sessionStorage.getItem("zsu-session")==="active"){
     try{await openDB();await loadSettings();showApp();go("overview");}
     catch(e){sessionStorage.removeItem("zsu-session");notify("Could not restore local session: "+e.message,true)}
   }
 }
 boot();
})();