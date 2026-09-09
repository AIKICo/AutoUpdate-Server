#include "admin.h"
#include "utils.h"
#include "sha256.h"
#include "md5.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>

int admin_is_authorized(const http_request_t *req, const server_ctx_t *ctx) {
    if (strlen(ctx->admin_pass) == 0) {
        return 1; /* No password set */
    }

    if (strlen(req->auth_header) == 0) {
        return 0;
    }

    if (strncasecmp(req->auth_header, "Basic ", 6) != 0) {
        return 0;
    }

    char decoded[256];
    if (base64_decode(req->auth_header + 6, decoded, sizeof(decoded)) < 0) {
        return 0;
    }

    char expected[256];
    snprintf(expected, sizeof(expected), "%s:%s", ctx->admin_user, ctx->admin_pass);

    return (strcmp(decoded, expected) == 0);
}

static void send_auth_required(socket_t sock) {
    const char *header = "WWW-Authenticate: Basic realm=\"AutoUpdate-Server Admin\"\r\n";
    http_send_response(sock, 401, "Unauthorized", "text/plain", header, "Authentication Required\n", 24);
}

static int sanitize_name(const char *name) {
    if (!name || strlen(name) == 0 || strlen(name) > 128) return 0;
    if (strstr(name, "..") || strchr(name, '/') || strchr(name, '\\')) return 0;
    for (size_t i = 0; i < strlen(name); i++) {
        char c = name[i];
        if (!isalnum(c) && c != '-' && c != '_' && c != '.') return 0;
    }
    return 1;
}

static void get_form_param(const char *body, const char *key, char *out, size_t out_len) {
    out[0] = '\0';
    if (!body || !key) return;

    size_t klen = strlen(key);
    const char *p = body;
    while (p && *p) {
        if (strncmp(p, key, klen) == 0 && p[klen] == '=') {
            const char *val = p + klen + 1;
            const char *amp = strchr(val, '&');
            size_t vlen = amp ? (size_t)(amp - val) : strlen(val);
            char enc[1024];
            if (vlen >= sizeof(enc)) vlen = sizeof(enc) - 1;
            memcpy(enc, val, vlen);
            enc[vlen] = '\0';
            url_decode(enc, out, out_len);
            return;
        }
        p = strchr(p, '&');
        if (p) p++;
    }
}

static void get_query_param(const char *query, const char *key, char *out, size_t out_len) {
    out[0] = '\0';
    if (!query || !key) return;

    char search_key[128];
    snprintf(search_key, sizeof(search_key), "%s=", key);
    const char *p = strstr(query, search_key);
    if (!p) {
        /* try key at start of query */
        if (strncmp(query, search_key, strlen(search_key)) == 0) p = query;
        else return;
    }
    const char *val = p + strlen(search_key);
    const char *amp = strchr(val, '&');
    size_t vlen = amp ? (size_t)(amp - val) : strlen(val);
    char enc[512];
    if (vlen >= sizeof(enc)) vlen = sizeof(enc) - 1;
    memcpy(enc, val, vlen);
    enc[vlen] = '\0';
    url_decode(enc, out, out_len);
}

/* Fallback Embedded HTML Dashboard */
const char *admin_get_embedded_html(void) {
    return "<!DOCTYPE html>\n"
           "<html lang=\"en\" dir=\"ltr\">\n"
           "<head>\n"
           "<meta charset=\"UTF-8\">\n"
           "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n"
           "<title>AutoUpdater.NET - Multi-Application Web Server</title>\n"
           "<style>\n"
           ":root { --bg: #0f172a; --card: #1e293b; --text: #f8fafc; --accent: #38bdf8; --border: #334155; --success: #22c55e; --btn: #0284c7; --danger: #ef4444; }\n"
           "* { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }\n"
           "body { background: var(--bg); color: var(--text); padding: 20px; line-height: 1.6; }\n"
           ".container { max-width: 1100px; margin: 0 auto; }\n"
           "header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 15px; margin-bottom: 20px; flex-wrap:wrap; gap:10px; }\n"
           "h1 { font-size: 1.4rem; color: var(--accent); display: flex; align-items: center; gap: 10px; }\n"
           ".badge { background: #065f46; color: #34d399; font-size: 0.8rem; padding: 4px 10px; border-radius: 9999px; font-weight: bold; }\n"
           ".grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }\n"
           ".card { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 16px; }\n"
           ".card-title { font-size: 0.85rem; color: #94a3b8; margin-bottom: 6px; }\n"
           ".card-value { font-size: 1.5rem; font-weight: bold; color: var(--text); }\n"
           ".section { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 20px; margin-bottom: 20px; }\n"
           "h2 { font-size: 1.15rem; margin-bottom: 15px; border-bottom: 1px solid var(--border); padding-bottom: 8px; color: var(--accent); }\n"
           ".app-selector-bar { display: flex; align-items: center; gap: 12px; background: #132742; padding: 12px 18px; border-radius: 8px; margin-bottom: 20px; flex-wrap: wrap; }\n"
           "select, input, textarea { background: #0f172a; border: 1px solid var(--border); border-radius: 6px; padding: 9px 12px; color: #fff; font-size: 0.9rem; }\n"
           "button { background: var(--btn); color: #fff; border: none; padding: 9px 18px; border-radius: 6px; cursor: pointer; font-weight: bold; transition: 0.2s; }\n"
           "button:hover { opacity: 0.9; }\n"
           ".btn-danger { background: var(--danger); padding: 5px 10px; font-size: 0.8rem; }\n"
           ".btn-secondary { background: #334155; padding: 5px 10px; font-size: 0.8rem; }\n"
           "table { width: 100%; border-collapse: collapse; margin-top: 10px; text-align: left; font-size: 0.88rem; }\n"
           "th, td { padding: 10px 12px; border-bottom: 1px solid var(--border); }\n"
           "th { background: #182234; color: #94a3b8; }\n"
           "code { background: #0f172a; padding: 2px 6px; border-radius: 4px; font-family: Consolas, monospace; display: inline-block; font-size: 0.85rem; }\n"
           "pre { background: #0f172a; border: 1px solid var(--border); padding: 15px; border-radius: 8px; overflow-x: auto; color: #38bdf8; font-family: Consolas, monospace; margin-top: 10px; }\n"
           "</style>\n"
           "</head>\n"
           "<body>\n"
           "<div class=\"container\">\n"
           "<header>\n"
           "  <h1><span>⚡</span> AutoUpdater.NET Server</h1>\n"
           "  <span class=\"badge\">● Online (Multi-App Enabled)</span>\n"
           "</header>\n"
           "\n"
           "<div class=\"app-selector-bar\">\n"
           "  <label style=\"font-weight:bold;\">📁 Current Application / Folder:</label>\n"
           "  <select id=\"currentApp\" onchange=\"onAppChange()\" style=\"min-width:200px;\">\n"
           "    <option value=\"\">Root Repository</option>\n"
           "  </select>\n"
           "  <button type=\"button\" onclick=\"promptNewApp()\">➕ New App Folder</button>\n"
           "</div>\n"
           "\n"
           "<div class=\"grid\">\n"
           "  <div class=\"card\"><div class=\"card-title\">Server Status</div><div class=\"card-value\" id=\"st-status\">Active</div></div>\n"
           "  <div class=\"card\"><div class=\"card-title\">Uptime</div><div class=\"card-value\" id=\"st-uptime\">...</div></div>\n"
           "  <div class=\"card\"><div class=\"card-title\">Total Requests</div><div class=\"card-value\" id=\"st-requests\">0</div></div>\n"
           "  <div class=\"card\"><div class=\"card-title\">Total Data Sent</div><div class=\"card-value\" id=\"st-bytes\">0 MB</div></div>\n"
           "</div>\n"
           "\n"
           "<div class=\"section\">\n"
           "  <h2>🚀 Publish Update for Selected App</h2>\n"
           "  <form id=\"genForm\" onsubmit=\"generateConfig(event)\" style=\"display:grid; grid-template-columns:1fr 1fr; gap:12px;\">\n"
           "    <div>\n"
           "      <label>Application / Subfolder Name:</label>\n"
           "      <input type=\"text\" id=\"appName\" required>\n"
           "    </div>\n"
           "    <div>\n"
           "      <label>Release Version:</label>\n"
           "      <input type=\"text\" id=\"appVer\" value=\"1.0.0.0\" required>\n"
           "    </div>\n"
           "    <div>\n"
           "      <label>Package File (Setup.zip or Setup.exe):</label>\n"
           "      <input type=\"text\" id=\"fileUrl\" required>\n"
           "    </div>\n"
           "    <div>\n"
           "      <label>Checksum Algorithm:</label>\n"
           "      <select id=\"hashAlgo\">\n"
           "        <option value=\"SHA256\">SHA256 (Recommended)</option>\n"
           "        <option value=\"MD5\">MD5</option>\n"
           "      </select>\n"
           "    </div>\n"
           "    <div style=\"grid-column: span 2;\">\n"
           "      <label>Checksum Hash Value:</label>\n"
           "      <input type=\"text\" id=\"hashVal\" placeholder=\"Auto-filled when selecting a file below\">\n"
           "    </div>\n"
           "    <div style=\"grid-column: span 2;\">\n"
           "      <label>Mandatory Update:</label>\n"
           "      <select id=\"mandatory\">\n"
           "        <option value=\"false\">No (Optional update)</option>\n"
           "        <option value=\"true\">Yes (Mandatory update)</option>\n"
           "      </select>\n"
           "    </div>\n"
           "    <div style=\"grid-column: span 2;\">\n"
           "      <label>Changelog / Release Notes:</label>\n"
           "      <textarea id=\"changelog\" rows=\"2\">- Performance improvements&#10;- Bug fixes</textarea>\n"
           "    </div>\n"
           "    <div style=\"grid-column: span 2;\">\n"
           "      <button type=\"submit\">Generate & Save AutoUpdater.xml & AutoUpdater.json</button>\n"
           "    </div>\n"
           "  </form>\n"
           "</div>\n"
           "\n"
           "<div class=\"section\">\n"
           "  <h2>📁 Files in Current Folder</h2>\n"
           "  <input type=\"file\" id=\"tableReplaceInput\" style=\"display:none;\" onchange=\"executeTableFileReplace(event)\">\n"
           "  <div style=\"margin-bottom: 12px; display:flex; gap:10px; flex-wrap:wrap; align-items:center;\">\n"
           "    <input type=\"file\" id=\"uploadFile\" style=\"max-width:320px;\">\n"
           "    <select id=\"uploadTargetOverride\" style=\"max-width:240px;\"><option value=\"\">-- Upload as New File --</option></select>\n"
           "    <button type=\"button\" onclick=\"uploadSelectedFile()\">⬆️ Upload / Replace</button>\n"
           "  </div>\n"
           "  <table id=\"filesTable\">\n"
           "    <thead><tr><th>File Name</th><th>Folder</th><th>Size</th><th>SHA-256 Checksum</th><th>Download</th><th>Action</th></tr></thead>\n"
           "    <tbody><tr><td colspan=\"6\" style=\"text-align:center;\">Loading...</td></tr></tbody>\n"
           "  </table>\n"
           "</div>\n"
           "\n"
           "<div class=\"section\" id=\"editorSection\">\n"
           "  <h2>📝 AutoUpdater.xml &amp; Config Editor</h2>\n"
           "  <div style=\"display:flex; gap:10px; margin-bottom:10px; flex-wrap:wrap; align-items:center;\">\n"
           "    <select id=\"editorTargetFile\" onchange=\"loadEditorFile()\">\n"
           "      <option value=\"AutoUpdater.xml\">AutoUpdater.xml</option>\n"
           "      <option value=\"AutoUpdater.json\">AutoUpdater.json</option>\n"
           "      <option value=\"changelog.html\">changelog.html</option>\n"
           "    </select>\n"
           "    <button type=\"button\" class=\"btn-secondary\" onclick=\"loadEditorFile()\">📥 Load Content</button>\n"
           "    <button type=\"button\" class=\"btn-secondary\" onclick=\"saveEditorFile()\">💾 Save Changes</button>\n"
           "    <span id=\"editorStatus\" style=\"font-size:0.85rem; color:#94a3b8;\"></span>\n"
           "  </div>\n"
           "  <textarea id=\"fileEditorText\" style=\"width:100%; min-height:240px; background:#080c14; color:#38bdf8; font-family:Consolas,monospace; font-size:0.9rem; padding:12px; border:1px solid #334155; border-radius:6px;\" placeholder=\"AutoUpdater.xml content will appear here...\"></textarea>\n"
           "</div>\n"
           "\n"
           "<div class=\"section\">\n"
           "  <h2>💻 C# Client Code Integration</h2>\n"
           "  <pre><code id=\"csharpCode\"></code></pre>\n"
           "</div>\n"
           "</div>\n"
           "\n"
           "<script>\n"
           "let targetReplaceApp = '', targetReplaceName = '';\n"
           "function promptReplaceFile(app, name) { targetReplaceApp = app; targetReplaceName = name; const inp = document.getElementById('tableReplaceInput'); inp.value=''; inp.click(); }\n"
           "function executeTableFileReplace(e) {\n"
           "  const fi = e.target; if (!fi.files || !fi.files[0]) return;\n"
           "  if (!confirm(`Replace ${targetReplaceName} with ${fi.files[0].name}? Existing file will be overwritten.`)) { fi.value=''; return; }\n"
           "  fetch('/api/upload?app=' + encodeURIComponent(targetReplaceApp) + '&name=' + encodeURIComponent(targetReplaceName), { method:'POST', body:fi.files[0] })\n"
           "  .then(r=>r.json()).then(res=>{\n"
           "    alert(`File replaced successfully!\\nSHA-256: ${res.sha256}`);\n"
           "    loadFiles(); fi.value='';\n"
           "    if (confirm('Update AutoUpdater.xml with this checksum?')) autoUpdateXmlChecksum(targetReplaceApp, res.sha256);\n"
           "  }).catch(e=>alert(e));\n"
           "}\n"
           "function autoUpdateXmlChecksum(app, sha) {\n"
           "  fetch('/api/get_file_content?app=' + encodeURIComponent(app) + '&name=AutoUpdater.xml')\n"
           "  .then(r=>r.text()).then(xml=>{\n"
           "    let updated = xml.replace(/<checksum\\b[^>]*>.*?<\\/checksum>/is, `<checksum algorithm=\"SHA256\">${sha}</checksum>`);\n"
           "    return fetch('/api/save_file_content?app=' + encodeURIComponent(app) + '&name=AutoUpdater.xml', { method:'POST', body:updated });\n"
           "  }).then(()=>{ alert('AutoUpdater.xml checksum updated!'); loadEditorFile(); }).catch(e=>alert(e));\n"
           "}\n"
           "function openInEditor(app, name) {\n"
           "  const sel = document.getElementById('editorTargetFile');\n"
           "  let f=false; for(let i=0;i<sel.options.length;i++) if(sel.options[i].value===name) f=true;\n"
           "  if(!f) { const opt=document.createElement('option'); opt.value=name; opt.text=name; sel.add(opt); }\n"
           "  sel.value = name; loadEditorFile(); document.getElementById('editorSection').scrollIntoView();\n"
           "}\n"
           "function loadEditorFile() {\n"
           "  const app = document.getElementById('currentApp').value, name = document.getElementById('editorTargetFile').value;\n"
           "  const st = document.getElementById('editorStatus'); st.innerText = 'Loading...';\n"
           "  fetch('/api/get_file_content?app=' + encodeURIComponent(app) + '&name=' + encodeURIComponent(name))\n"
           "  .then(r=>r.ok?r.text():'').then(txt=>{ document.getElementById('fileEditorText').value = txt; st.innerText = `Loaded (${txt.length} bytes)`; })\n"
           "  .catch(()=>{ st.innerText = 'File not found'; });\n"
           "}\n"
           "function saveEditorFile() {\n"
           "  const app = document.getElementById('currentApp').value, name = document.getElementById('editorTargetFile').value;\n"
           "  const body = document.getElementById('fileEditorText').value;\n"
           "  fetch('/api/save_file_content?app=' + encodeURIComponent(app) + '&name=' + encodeURIComponent(name), { method:'POST', body:body })\n"
           "  .then(r=>r.json()).then(res=>{ alert(res.message || 'Saved'); loadFiles(); }).catch(e=>alert(e));\n"
           "}\n"
           "function updateStats() {\n"
           "  fetch('/api/stats').then(r=>r.json()).then(d=>{\n"
           "    const sec = d.uptime_sec, h = Math.floor(sec/3600), m = Math.floor((sec%3600)/60), s = sec%60;\n"
           "    document.getElementById('st-uptime').innerText = `${h}h ${m}m ${s}s`;\n"
           "    document.getElementById('st-requests').innerText = d.total_requests;\n"
           "    document.getElementById('st-bytes').innerText = d.total_bytes_str;\n"
           "  }).catch(()=>{});\n"
           "}\n"
           "\n"
           "function loadApps() {\n"
           "  fetch('/api/apps').then(r=>r.json()).then(apps=>{\n"
           "    const sel = document.getElementById('currentApp');\n"
           "    const cur = sel.value;\n"
           "    sel.innerHTML = '<option value=\"\">Root Repository</option>' + apps.map(a => `<option value=\"${a}\">${a}</option>`).join('');\n"
           "    if (apps.includes(cur)) sel.value = cur;\n"
           "    onAppChange();\n"
           "  }).catch(()=>{});\n"
           "}\n"
           "\n"
           "function promptNewApp() {\n"
           "  const name = prompt('Enter new application / folder name (e.g. Accounting, CRM):');\n"
           "  if (!name || !name.trim()) return;\n"
           "  fetch('/api/create_app?name=' + encodeURIComponent(name.trim()), { method: 'POST' })\n"
           "  .then(r=>r.json()).then(res=>{\n"
           "    alert(res.message || 'Folder created successfully.');\n"
           "    loadApps();\n"
           "  }).catch(e=>alert('Error: ' + e));\n"
           "}\n"
           "\n"
           "function onAppChange() {\n"
           "  const app = document.getElementById('currentApp').value;\n"
           "  document.getElementById('appName').value = app || 'MyApplication';\n"
           "  loadFiles();\n"
           "  loadEditorFile();\n"
           "  updateCSharpCode();\n"
           "}\n"
           "\n"
           "function loadFiles() {\n"
           "  const app = document.getElementById('currentApp').value;\n"
           "  fetch('/api/files?app=' + encodeURIComponent(app)).then(r=>r.json()).then(files=>{\n"
           "    const ov = document.getElementById('uploadTargetOverride');\n"
           "    if(ov) ov.innerHTML = '<option value=\"\">-- Upload as New File --</option>' + files.map(f=>`<option value=\"${f.name}\">Replace: ${f.name}</option>`).join('');\n"
           "    const tbody = document.querySelector('#filesTable tbody');\n"
           "    if (!files || files.length === 0) {\n"
           "      tbody.innerHTML = '<tr><td colspan=\"6\" style=\"text-align:center;\">No files found in this folder.</td></tr>';\n"
           "      return;\n"
           "    }\n"
           "    tbody.innerHTML = files.map(f => {\n"
           "      const isText = f.name.endsWith('.xml')||f.name.endsWith('.json')||f.name.endsWith('.html');\n"
           "      return `<tr>\n"
           "        <td><strong>${f.name}</strong></td>\n"
           "        <td><code>${f.app ? f.app : 'Root'}</code></td>\n"
           "        <td>${f.size_str}</td>\n"
           "        <td><code title=\"${f.sha256}\">${f.sha256.substring(0,16)}...</code> <button class=\"btn-secondary\" onclick=\"useHash('${f.name}','${f.sha256}')\">Select</button></td>\n"
           "        <td><a href=\"${f.url}\" target=\"_blank\" style=\"color:var(--accent);\">Download</a></td>\n"
           "        <td>\n"
           "          <button class=\"btn-secondary\" onclick=\"promptReplaceFile('${f.app}','${f.name}')\" style=\"background:#d97706;\">🔁 Replace</button>\n"
           "          ${isText ? `<button class=\"btn-secondary\" onclick=\"openInEditor('${f.app}','${f.name}')\">✏️ Edit</button>` : ''}\n"
           "          <button class=\"btn-danger\" onclick=\"deleteFile('${f.app}','${f.name}')\">Delete</button>\n"
           "        </td>\n"
           "      </tr>`;\n"
           "    }).join('');\n"
           "  }).catch(()=>{});\n"
           "}\n"
           "\n"
           "function useHash(name, hash) {\n"
           "  document.getElementById('fileUrl').value = name;\n"
           "  document.getElementById('hashVal').value = hash;\n"
           "}\n"
           "\n"
           "function uploadSelectedFile() {\n"
           "  const fi = document.getElementById('uploadFile');\n"
           "  if (!fi.files || !fi.files[0]) { alert('Please select a file first.'); return; }\n"
           "  const app = document.getElementById('currentApp').value;\n"
           "  const f = fi.files[0];\n"
           "  const ov = document.getElementById('uploadTargetOverride').value;\n"
           "  const name = ov ? ov : f.name;\n"
           "  const url = '/api/upload?app=' + encodeURIComponent(app) + '&name=' + encodeURIComponent(name);\n"
           "  fetch(url, { method: 'POST', body: f }).then(r=>r.json()).then(res=>{\n"
           "    alert('Upload/Replace successful: ' + res.filename);\n"
           "    useHash(res.filename, res.sha256);\n"
           "    loadFiles();\n"
           "    fi.value = '';\n"
           "    if (confirm('Update AutoUpdater.xml with this checksum?')) autoUpdateXmlChecksum(app, res.sha256);\n"
           "  }).catch(e=>alert('Upload error: ' + e));\n"
           "}\n"
           "\n"
           "function generateConfig(e) {\n"
           "  e.preventDefault();\n"
           "  const app = document.getElementById('currentApp').value;\n"
           "  const body = new URLSearchParams({\n"
           "    app_name: app || document.getElementById('appName').value,\n"
           "    version: document.getElementById('appVer').value,\n"
           "    file_url: document.getElementById('fileUrl').value,\n"
           "    hash_algo: document.getElementById('hashAlgo').value,\n"
           "    hash_val: document.getElementById('hashVal').value,\n"
           "    mandatory: document.getElementById('mandatory').value,\n"
           "    changelog: document.getElementById('changelog').value\n"
           "  }).toString();\n"
           "  fetch('/api/generate_config', { method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body:body })\n"
           "  .then(r=>r.json()).then(res=>{\n"
           "    alert(res.message || 'Configurations saved successfully.');\n"
           "    loadFiles();\n"
           "    loadEditorFile();\n"
           "  }).catch(e=>alert('Error: ' + e));\n"
           "}\n"
           "\n"
           "function deleteFile(app, name) {\n"
           "  if (!confirm('Delete file ' + name + '?')) return;\n"
           "  fetch('/api/delete?app=' + encodeURIComponent(app) + '&name=' + encodeURIComponent(name), { method: 'POST' })\n"
           "  .then(r=>r.json()).then(()=>loadFiles()).catch(e=>alert(e));\n"
           "}\n"
           "\n"
           "function updateCSharpCode() {\n"
           "  const app = document.getElementById('currentApp').value;\n"
           "  const host = window.location.host || 'your-linux-server:8080';\n"
           "  const xmlPath = app ? `http://${host}/${app}/AutoUpdater.xml` : `http://${host}/AutoUpdater.xml`;\n"
           "  const jsonPath = app ? `http://${host}/${app}/AutoUpdater.json` : `http://${host}/AutoUpdater.json`;\n"
           "  document.getElementById('csharpCode').innerText =\n"
           "`// AutoUpdater.NET client code for \"${app || 'Root'}\":\\nusing AutoUpdaterDotNET;\\n\\nAutoUpdater.Start(\"${xmlPath}\");\\n\\n// Or JSON format:\\n// AutoUpdater.Start(\"${jsonPath}\");`;\n"
           "}\n"
           "\n"
           "loadApps();\n"
           "updateStats();\n"
           "setInterval(updateStats, 3000);\n"
           "</script>\n"
           "</body>\n"
           "</html>\n";
}

int admin_handle_request(socket_t sock, const http_request_t *req, server_ctx_t *ctx) {
    /* 1. Serve Web Admin Dashboard */
    if (strcmp(req->path, "/admin") == 0 || strcmp(req->path, "/admin/") == 0) {
        if (!admin_is_authorized(req, ctx)) {
            send_auth_required(sock);
            return 0;
        }

        /* Check if external index.html exists in webroot */
        char custom_path[1024];
        snprintf(custom_path, sizeof(custom_path), "%s/admin/index.html", ctx->webroot_dir);
        size_t sz = 0;
        char *custom_html = read_entire_file(custom_path, &sz);
        if (custom_html) {
            http_send_response(sock, 200, "OK", "text/html; charset=utf-8", NULL, custom_html, sz);
            free(custom_html);
            return 0;
        }

        /* Use embedded fallback */
        const char *embedded = admin_get_embedded_html();
        return http_send_response(sock, 200, "OK", "text/html; charset=utf-8", NULL, embedded, strlen(embedded));
    }

    /* 2. API: Server Statistics */
    if (strcmp(req->path, "/api/stats") == 0) {
        uint64_t now = (uint64_t)time(NULL);
        uint64_t uptime = (now >= ctx->start_time) ? (now - ctx->start_time) : 0;
        char bytes_str[32];
        format_bytes(ctx->total_bytes_sent, bytes_str, sizeof(bytes_str));

        char json[512];
        snprintf(json, sizeof(json),
            "{\"uptime_sec\": %llu, \"total_requests\": %llu, \"total_bytes\": %llu, "
            "\"total_bytes_str\": \"%s\", \"active_connections\": %d, \"port\": %d, \"version\": \"2.0.0\"}\n",
            (unsigned long long)uptime,
            (unsigned long long)ctx->total_requests,
            (unsigned long long)ctx->total_bytes_sent,
            bytes_str,
            ctx->active_connections,
            ctx->port
        );
        return http_send_json(sock, 200, json);
    }

    /* 3. API: List Application Folders */
    if (strcmp(req->path, "/api/apps") == 0) {
        DIR *d = opendir(ctx->updates_dir);
        if (!d) {
            return http_send_json(sock, 200, "[]\n");
        }

        char *resp = malloc(65536);
        if (!resp) { closedir(d); return http_send_error(sock, 500, "Out of memory"); }
        strcpy(resp, "[\n");
        int first = 1;

        struct dirent *dir;
        while ((dir = readdir(d)) != NULL) {
            if (strcmp(dir->d_name, ".") == 0 || strcmp(dir->d_name, "..") == 0 || dir->d_name[0] == '.') continue;

            char subpath[1024];
            snprintf(subpath, sizeof(subpath), "%s/%s", ctx->updates_dir, dir->d_name);

            struct stat st;
            if (stat(subpath, &st) == 0 && S_ISDIR(st.st_mode)) {
                char item[512];
                snprintf(item, sizeof(item), "%s  \"%s\"", first ? "" : ",\n", dir->d_name);
                strcat(resp, item);
                first = 0;
            }
        }
        closedir(d);
        strcat(resp, "\n]\n");

        int ret = http_send_json(sock, 200, resp);
        free(resp);
        return ret;
    }

    /* 4. API: Create New Application Folder */
    if (strcmp(req->path, "/api/create_app") == 0 && req->method == HTTP_METHOD_POST) {
        if (!admin_is_authorized(req, ctx)) { send_auth_required(sock); return 0; }

        char app_name[128] = {0};
        get_query_param(req->query, "name", app_name, sizeof(app_name));
        if (strlen(app_name) == 0) {
            get_form_param(req->body, "name", app_name, sizeof(app_name));
        }

        if (!sanitize_name(app_name)) {
            return http_send_error(sock, 400, "Invalid application folder name");
        }

        char app_dir[1024];
        snprintf(app_dir, sizeof(app_dir), "%s/%s", ctx->updates_dir, app_name);
        MKDIR(app_dir);

        log_msg("INFO", "Created application folder: %s", app_name);
        return http_send_json(sock, 200, "{\"success\": true, \"message\": \"Application folder created successfully.\"}\n");
    }

    /* 5. API: Delete Application Folder */
    if (strcmp(req->path, "/api/delete_app") == 0 && req->method == HTTP_METHOD_POST) {
        if (!admin_is_authorized(req, ctx)) { send_auth_required(sock); return 0; }

        char app_name[128] = {0};
        get_query_param(req->query, "name", app_name, sizeof(app_name));
        if (!sanitize_name(app_name)) {
            return http_send_error(sock, 400, "Invalid application folder name");
        }

        char app_dir[1024];
        snprintf(app_dir, sizeof(app_dir), "%s/%s", ctx->updates_dir, app_name);
#ifdef _WIN32
        _rmdir(app_dir);
#else
        rmdir(app_dir);
#endif

        log_msg("INFO", "Deleted application folder: %s", app_name);
        return http_send_json(sock, 200, "{\"success\": true, \"message\": \"Application folder deleted successfully.\"}\n");
    }

    /* 6. API: List Files in Updates Repository (Supports Filtering by App Folder) */
    if (strcmp(req->path, "/api/files") == 0) {
        char app_filter[128] = {0};
        get_query_param(req->query, "app", app_filter, sizeof(app_filter));

        char scan_dir[1024];
        if (strlen(app_filter) > 0 && sanitize_name(app_filter)) {
            snprintf(scan_dir, sizeof(scan_dir), "%s/%s", ctx->updates_dir, app_filter);
        } else {
            strncpy(scan_dir, ctx->updates_dir, sizeof(scan_dir) - 1);
        }

        DIR *d = opendir(scan_dir);
        if (!d) {
            return http_send_json(sock, 200, "[]\n");
        }

        char *resp = malloc(131072);
        if (!resp) { closedir(d); return http_send_error(sock, 500, "Out of memory"); }
        strcpy(resp, "[\n");
        int first = 1;

        struct dirent *dir;
        while ((dir = readdir(d)) != NULL) {
            if (strcmp(dir->d_name, ".") == 0 || strcmp(dir->d_name, "..") == 0) continue;
            if (dir->d_name[0] == '.') continue;

            char fpath[1024];
            snprintf(fpath, sizeof(fpath), "%s/%s", scan_dir, dir->d_name);

            struct stat st;
            if (stat(fpath, &st) != 0 || S_ISDIR(st.st_mode)) continue;

            char sha256_hex[65] = {0};
            char md5_hex[33] = {0};
            sha256_file(fpath, sha256_hex);
            md5_file(fpath, md5_hex);

            char sz_str[32];
            format_bytes((uint64_t)st.st_size, sz_str, sizeof(sz_str));

            char url_path[512];
            if (strlen(app_filter) > 0) {
                snprintf(url_path, sizeof(url_path), "/%s/%s", app_filter, dir->d_name);
            } else {
                snprintf(url_path, sizeof(url_path), "/%s", dir->d_name);
            }

            char item[2048];
            snprintf(item, sizeof(item),
                "%s  {\"name\": \"%s\", \"app\": \"%s\", \"url\": \"%s\", \"size\": %llu, \"size_str\": \"%s\", \"sha256\": \"%s\", \"md5\": \"%s\", \"mtime\": %ld}\n",
                first ? "" : ",\n",
                dir->d_name,
                app_filter,
                url_path,
                (unsigned long long)st.st_size,
                sz_str,
                sha256_hex,
                md5_hex,
                (long)st.st_mtime
            );

            strcat(resp, item);
            first = 0;
        }
        closedir(d);
        strcat(resp, "]\n");

        int ret = http_send_json(sock, 200, resp);
        free(resp);
        return ret;
    }

    /* 7. API: Generate AutoUpdater.xml and AutoUpdater.json for Specific App */
    if (strcmp(req->path, "/api/generate_config") == 0 && req->method == HTTP_METHOD_POST) {
        if (!admin_is_authorized(req, ctx)) {
            send_auth_required(sock);
            return 0;
        }

        char app_name[128] = {0};
        char version[64] = {0};
        char file_url[256] = {0};
        char hash_algo[32] = "SHA256";
        char hash_val[128] = {0};
        char mandatory[16] = "false";
        char changelog[1024] = {0};

        get_form_param(req->body, "app_name", app_name, sizeof(app_name));
        get_form_param(req->body, "version", version, sizeof(version));
        get_form_param(req->body, "file_url", file_url, sizeof(file_url));
        get_form_param(req->body, "hash_algo", hash_algo, sizeof(hash_algo));
        get_form_param(req->body, "hash_val", hash_val, sizeof(hash_val));
        get_form_param(req->body, "mandatory", mandatory, sizeof(mandatory));
        get_form_param(req->body, "changelog", changelog, sizeof(changelog));

        if (strlen(version) == 0 || strlen(file_url) == 0) {
            return http_send_error(sock, 400, "Missing required parameters (version, file_url)");
        }

        char target_dir[1024];
        char url_prefix[256] = "";
        if (strlen(app_name) > 0 && sanitize_name(app_name)) {
            snprintf(target_dir, sizeof(target_dir), "%s/%s", ctx->updates_dir, app_name);
            MKDIR(target_dir);
            snprintf(url_prefix, sizeof(url_prefix), "/%s", app_name);
        } else {
            strncpy(target_dir, ctx->updates_dir, sizeof(target_dir) - 1);
        }

        char download_url[512];
        if (strstr(file_url, "://") == NULL) {
            if (file_url[0] == '/') {
                strncpy(download_url, file_url, sizeof(download_url) - 1);
            } else {
                snprintf(download_url, sizeof(download_url), "%s/%s", url_prefix, file_url);
            }
        } else {
            strncpy(download_url, file_url, sizeof(download_url) - 1);
        }

        char changelog_url[256];
        snprintf(changelog_url, sizeof(changelog_url), "%s/changelog.html", url_prefix);

        /* 1) changelog.html */
        char changelog_path[1024];
        snprintf(changelog_path, sizeof(changelog_path), "%s/changelog.html", target_dir);
        FILE *fc = fopen(changelog_path, "w");
        if (fc) {
            fprintf(fc, "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Release Notes v%s</title>"
                        "<style>body{font-family:-apple-system,BlinkMacSystemFont,sans-serif;padding:24px;line-height:1.6;background:#0b0f19;color:#f1f5f9;}"
                        "h2{color:#38bdf8;border-bottom:1px solid #24324f;padding-bottom:8px;}"
                        "pre{background:#151d30;border:1px solid #24324f;padding:16px;border-radius:8px;font-family:Consolas,monospace;color:#38bdf8;overflow-x:auto;white-space:pre-wrap;}</style></head><body>"
                        "<h2>Release Notes v%s</h2><pre>%s</pre></body></html>\n",
                        version, version, changelog);
            fclose(fc);
        }

        /* 2) AutoUpdater.xml */
        char xml_path[1024];
        snprintf(xml_path, sizeof(xml_path), "%s/AutoUpdater.xml", target_dir);
        FILE *fx = fopen(xml_path, "w");
        if (fx) {
            fprintf(fx, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
            fprintf(fx, "<item>\n");
            fprintf(fx, "    <version>%s</version>\n", version);
            fprintf(fx, "    <url>%s</url>\n", download_url);
            fprintf(fx, "    <changelog>%s</changelog>\n", changelog_url);
            fprintf(fx, "    <mandatory>%s</mandatory>\n", (strcmp(mandatory, "true") == 0) ? "true" : "false");
            if (strlen(hash_val) > 0) {
                fprintf(fx, "    <checksum algorithm=\"%s\">%s</checksum>\n", hash_algo, hash_val);
            }
            fprintf(fx, "</item>\n");
            fclose(fx);
        }

        /* 3) AutoUpdater.json */
        char json_path[1024];
        snprintf(json_path, sizeof(json_path), "%s/AutoUpdater.json", target_dir);
        FILE *fj = fopen(json_path, "w");
        if (fj) {
            fprintf(fj, "{\n");
            fprintf(fj, "  \"version\": \"%s\",\n", version);
            fprintf(fj, "  \"url\": \"%s\",\n", download_url);
            fprintf(fj, "  \"changelog\": \"%s\",\n", changelog_url);
            fprintf(fj, "  \"mandatory\": {\n");
            fprintf(fj, "    \"mode\": %d\n", (strcmp(mandatory, "true") == 0) ? 1 : 0);
            fprintf(fj, "  }%s\n", (strlen(hash_val) > 0) ? "," : "");
            if (strlen(hash_val) > 0) {
                fprintf(fj, "  \"checksum\": {\n");
                fprintf(fj, "    \"value\": \"%s\",\n", hash_val);
                fprintf(fj, "    \"hashingAlgorithm\": \"%s\"\n", hash_algo);
                fprintf(fj, "  }\n");
            }
            fprintf(fj, "}\n");
            fclose(fj);
        }

        log_msg("INFO", "AutoUpdater config generated for app '%s' version %s", app_name, version);
        return http_send_json(sock, 200, "{\"success\": true, \"message\": \"AutoUpdater.xml and AutoUpdater.json generated successfully.\"}\n");
    }

    /* 8. API: File Upload into App Folder */
    if (strcmp(req->path, "/api/upload") == 0 && req->method == HTTP_METHOD_POST) {
        if (!admin_is_authorized(req, ctx)) {
            send_auth_required(sock);
            return 0;
        }

        char app_name[128] = {0};
        char filename[256] = {0};
        get_query_param(req->query, "app", app_name, sizeof(app_name));
        get_query_param(req->query, "name", filename, sizeof(filename));

        if (strlen(filename) == 0) {
            snprintf(filename, sizeof(filename), "update_%ld.bin", (long)time(NULL));
        }

        if (!sanitize_name(filename)) {
            return http_send_error(sock, 400, "Invalid filename");
        }

        char dest_dir[1024];
        if (strlen(app_name) > 0 && sanitize_name(app_name)) {
            snprintf(dest_dir, sizeof(dest_dir), "%s/%s", ctx->updates_dir, app_name);
            MKDIR(dest_dir);
        } else {
            strncpy(dest_dir, ctx->updates_dir, sizeof(dest_dir) - 1);
        }

        char dest_path[1024];
        snprintf(dest_path, sizeof(dest_path), "%s/%s", dest_dir, filename);
        int already_existed = (access(dest_path, 0) == 0);

        FILE *f = fopen(dest_path, "wb");
        if (!f) {
            return http_send_error(sock, 500, "Cannot write file to disk");
        }

        if (req->body && req->body_len > 0) {
            fwrite(req->body, 1, req->body_len, f);
        }
        fclose(f);

        char sha256_hex[65] = {0};
        char md5_hex[33] = {0};
        sha256_file(dest_path, sha256_hex);
        md5_file(dest_path, md5_hex);

        log_msg("INFO", "File %s [%s]: %s (%zu bytes) SHA256: %s",
                already_existed ? "replaced" : "uploaded",
                strlen(app_name) > 0 ? app_name : "Root", filename, req->body_len, sha256_hex);

        char resp[512];
        snprintf(resp, sizeof(resp), "{\"success\": true, \"replaced\": %s, \"app\": \"%s\", \"filename\": \"%s\", \"size\": %zu, \"sha256\": \"%s\", \"md5\": \"%s\"}\n",
                 already_existed ? "true" : "false",
                 app_name, filename, req->body_len, sha256_hex, md5_hex);
        return http_send_json(sock, 200, resp);
    }

    /* 9. API: Delete File from App Folder */
    if (strcmp(req->path, "/api/delete") == 0 && req->method == HTTP_METHOD_POST) {
        if (!admin_is_authorized(req, ctx)) {
            send_auth_required(sock);
            return 0;
        }

        char app_name[128] = {0};
        char filename[256] = {0};
        get_query_param(req->query, "app", app_name, sizeof(app_name));
        get_query_param(req->query, "name", filename, sizeof(filename));

        if (!sanitize_name(filename)) {
            return http_send_error(sock, 400, "Invalid filename");
        }

        char target_path[1024];
        if (strlen(app_name) > 0 && sanitize_name(app_name)) {
            snprintf(target_path, sizeof(target_path), "%s/%s/%s", ctx->updates_dir, app_name, filename);
        } else {
            snprintf(target_path, sizeof(target_path), "%s/%s", ctx->updates_dir, filename);
        }

        unlink(target_path);

        log_msg("INFO", "File deleted: %s", target_path);
        return http_send_json(sock, 200, "{\"success\": true, \"message\": \"File deleted successfully.\"}\n");
    }

    /* 10. API: Get File Content (for in-browser XML/JSON/HTML editing) */
    if (strcmp(req->path, "/api/get_file_content") == 0) {
        if (!admin_is_authorized(req, ctx)) {
            send_auth_required(sock);
            return 0;
        }

        char app_name[128] = {0};
        char filename[128] = {0};
        get_query_param(req->query, "app", app_name, sizeof(app_name));
        get_query_param(req->query, "name", filename, sizeof(filename));

        if (strlen(filename) == 0) {
            strncpy(filename, "AutoUpdater.xml", sizeof(filename) - 1);
        }

        if (!sanitize_name(filename) || (strlen(app_name) > 0 && !sanitize_name(app_name))) {
            return http_send_error(sock, 400, "Invalid file or application name");
        }

        char fpath[1024];
        if (strlen(app_name) > 0) {
            snprintf(fpath, sizeof(fpath), "%s/%s/%s", ctx->updates_dir, app_name, filename);
        } else {
            snprintf(fpath, sizeof(fpath), "%s/%s", ctx->updates_dir, filename);
        }

        size_t file_sz = 0;
        char *content = read_entire_file(fpath, &file_sz);
        if (!content) {
            return http_send_error(sock, 404, "File not found");
        }

        const char *content_type = "text/plain; charset=utf-8";
        if (strstr(filename, ".xml")) content_type = "application/xml; charset=utf-8";
        else if (strstr(filename, ".json")) content_type = "application/json; charset=utf-8";
        else if (strstr(filename, ".html")) content_type = "text/html; charset=utf-8";

        http_send_response(sock, 200, "OK", content_type, NULL, content, file_sz);
        free(content);
        return 0;
    }

    /* 11. API: Save File Content (for in-browser XML/JSON/HTML editing) */
    if (strcmp(req->path, "/api/save_file_content") == 0 && req->method == HTTP_METHOD_POST) {
        if (!admin_is_authorized(req, ctx)) {
            send_auth_required(sock);
            return 0;
        }

        char app_name[128] = {0};
        char filename[128] = {0};
        get_query_param(req->query, "app", app_name, sizeof(app_name));
        get_query_param(req->query, "name", filename, sizeof(filename));

        if (strlen(filename) == 0) {
            strncpy(filename, "AutoUpdater.xml", sizeof(filename) - 1);
        }

        if (!sanitize_name(filename) || (strlen(app_name) > 0 && !sanitize_name(app_name))) {
            return http_send_error(sock, 400, "Invalid file or application name");
        }

        char target_dir[1024];
        if (strlen(app_name) > 0) {
            snprintf(target_dir, sizeof(target_dir), "%s/%s", ctx->updates_dir, app_name);
            MKDIR(target_dir);
        } else {
            strncpy(target_dir, ctx->updates_dir, sizeof(target_dir) - 1);
        }

        char fpath[1024];
        snprintf(fpath, sizeof(fpath), "%s/%s", target_dir, filename);

        FILE *f = fopen(fpath, "wb");
        if (!f) {
            return http_send_error(sock, 500, "Cannot write file to disk");
        }

        if (req->body && req->body_len > 0) {
            fwrite(req->body, 1, req->body_len, f);
        }
        fclose(f);

        log_msg("INFO", "Saved file content: %s (%zu bytes)", fpath, req->body_len);
        return http_send_json(sock, 200, "{\"success\": true, \"message\": \"File saved successfully.\"}\n");
    }

    return -1;
}
