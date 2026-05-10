let speedInterval = null; let lastStats = {}; let lastTime = 0;

document.addEventListener('DOMContentLoaded', () => {
    if(typeof CURRENT_NODE_ID !== 'undefined') {
        if(localStorage.getItem('speedToggleState_' + CURRENT_NODE_ID) === 'true') {
            const cb = document.getElementById('speedToggle');
            if(cb) { cb.checked = true; toggleSpeedMonitor(); }
        }
        checkXrayStatus();
        if(new URLSearchParams(window.location.search).get('newly_added') === 'yes') {
            const m = document.getElementById('installPromptModal');
            if(m) m.classList.remove('hidden');
            window.history.replaceState({}, document.title, window.location.pathname);
            checkSSH();
        }
    }
});

async function checkXrayStatus() {
    if(typeof CURRENT_NODE_ID === 'undefined') return;
    try {
        const res = await fetch('/api/check_xray/' + CURRENT_NODE_ID); const json = await res.json();
        const b = document.getElementById('xrayStatusBadge'); if(!b) return;
        if(json.status === 'active') {
            b.className = "bg-emerald-100 text-emerald-600 border border-emerald-200 px-3 py-2 rounded-xl font-bold shadow-sm text-[10px] uppercase tracking-widest flex items-center gap-1.5";
            b.innerHTML = '<i class="fa-solid fa-circle-check"></i> Xray Active';
        } else {
            b.className = "bg-red-100 text-red-600 border border-red-200 px-3 py-2 rounded-xl font-bold shadow-sm text-[10px] uppercase tracking-widest flex items-center gap-1.5";
            b.innerHTML = '<i class="fa-solid fa-circle-xmark"></i> Xray Inactive';
        }
    } catch(e) {}
}

async function checkSSH() {
    if(typeof CURRENT_NODE_ID === 'undefined') return;
    const s = document.getElementById('sshStatusText'); const i = document.getElementById('sshInstructions'); 
    const b = document.getElementById('installBtn'); const a = document.getElementById('sshCheckArea');
    s.innerHTML = '<i class="fa-solid fa-spinner fa-spin mr-2"></i> Checking SSH...'; s.classList.remove('hidden'); i.classList.add('hidden'); b.disabled = true; b.classList.add('opacity-50','cursor-not-allowed');
    try {
        const res = await fetch('/api/check_ssh/' + CURRENT_NODE_ID); const json = await res.json();
        if(json.status === 'success'){
            a.classList.replace('bg-slate-50','bg-emerald-50'); a.classList.replace('border-slate-200','border-emerald-200');
            s.innerHTML = '<span class="text-emerald-600"><i class="fa-solid fa-check-circle mr-2"></i> SSH Connected!</span>';
            b.disabled = false; b.classList.remove('opacity-50','cursor-not-allowed');
        } else { s.classList.add('hidden'); i.classList.remove('hidden'); }
    } catch(e) { s.classList.add('hidden'); i.classList.remove('hidden'); }
}

function toggleSpeedMonitor() {
    const e = document.getElementById('speedToggle').checked; localStorage.setItem('speedToggleState_' + CURRENT_NODE_ID, e);
    const tags = document.querySelectorAll('.live-speed-tag');
    if(e) { tags.forEach(el => el.classList.remove('hidden')); lastTime = Date.now(); fetchStats(); speedInterval = setInterval(fetchStats, 2000); } 
    else { tags.forEach(el => el.classList.add('hidden')); clearInterval(speedInterval); lastStats = {}; }
}

async function fetchStats() {
    try {
        const res = await fetch('/api/stats/' + CURRENT_NODE_ID); const json = await res.json();
        if(json.status === 'ok'){
            const now = Date.now(); const td = (now - lastTime) / 1000; const cs = json.data;
            for(const u in cs) {
                if(lastStats[u] !== undefined) {
                    const bd = cs[u] - lastStats[u]; let s = 0; if(bd > 0 && td > 0) s = bd / td;
                    let str = "0 B/s"; if(s > 1024*1024) str = (s/(1024*1024)).toFixed(2) + " MB/s"; else if(s > 1024) str = (s/1024).toFixed(2) + " KB/s"; else if(s > 0) str = s.toFixed(0) + " B/s";
                    const el = document.getElementById('speed_'+u);
                    if(el) { el.innerText = str; el.classList.add('animate-pulse'); setTimeout(() => el.classList.remove('animate-pulse'), 500); }
                }
            }
            lastStats = cs; lastTime = now;
        }
    } catch(e){}
}

function copyK(id) { var t = document.getElementById(id); if(!t.value){ alert("Error!"); return; } var d = document.createElement("textarea"); document.body.appendChild(d); d.value = t.value; d.select(); document.execCommand("copy"); document.body.removeChild(d); alert("✅ Copied!"); }
function toggleMode() { let m = document.getElementById('creation_mode').value; document.getElementById('mode_single').classList.toggle('hidden', m !== 'single'); document.getElementById('mode_list').classList.toggle('hidden', m !== 'list'); document.getElementById('mode_pattern').classList.toggle('hidden', m !== 'pattern'); }
function openM(u, g, d) { document.getElementById('mu').innerText = "Edit: " + u; document.getElementById('mg').value = g; document.getElementById('md').value = d; document.getElementById('ef').action = "/edit_user/" + u; document.getElementById('m').classList.remove('hidden'); }
function closeM() { document.getElementById('m').classList.add('hidden'); }
function openRenew(u) { document.getElementById('ru').innerText = u; document.getElementById('rf').action = "/renew_user/" + u; document.getElementById('rm').classList.remove('hidden'); }
function closeRenew() { document.getElementById('rm').classList.add('hidden'); }
function submitToggle(u) { let f = document.getElementById('actionToggleForm'); f.action = '/toggle_user/' + u; f.submit(); }
function submitDelete(u) { let f = document.getElementById('actionDeleteForm'); f.action = '/delete_user/' + u; f.submit(); }
