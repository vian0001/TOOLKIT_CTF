/* ═══════════════════════════════════════════════════════════════
   APK Decoder — CTF Reverse Engineering Web Tool
   Core Application Logic
   ═══════════════════════════════════════════════════════════════ */

// ─── Global State ───
const APP = {
    zip: null,
    files: {},
    fileTree: [],
    currentFile: null,
    currentData: null,
    currentTab: 'hex',
    bookmarks: [],
    allStrings: new Map(),
    manifest: null,
};

// ─── DOM References ───
const $ = id => document.getElementById(id);
const $$ = sel => document.querySelectorAll(sel);

// ─── Utility Functions ───
function formatSize(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024, units = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + units[i];
}

function toast(msg, type = 'info') {
    const el = document.createElement('div');
    el.className = `toast ${type}`;
    el.textContent = msg;
    $('toastContainer').appendChild(el);
    setTimeout(() => { el.classList.add('toast-exit'); setTimeout(() => el.remove(), 300); }, 3000);
}

function showLoading(text, detail = '') {
    $('loadingText').textContent = text;
    $('loadingDetail').textContent = detail;
    $('loadingOverlay').classList.remove('hidden');
}

function hideLoading() { $('loadingOverlay').classList.add('hidden'); }

function setProgress(pct) { $('progressFill').style.width = pct + '%'; }

function getFileIcon(name) {
    const ext = name.split('.').pop().toLowerCase();
    const icons = {
        dex: '🧩', xml: '📋', png: '🖼️', jpg: '🖼️', jpeg: '🖼️', webp: '🖼️', gif: '🖼️',
        so: '⚙️', arsc: '🗃️', mf: '📜', sf: '📜', rsa: '🔐', dsa: '🔐', txt: '📝',
        json: '📦', js: '📜', html: '🌐', css: '🎨', properties: '⚙️', pro: '⚙️',
        kt: '🟣', java: '☕', smali: '🧩', zip: '📦', jar: '📦',
    };
    return icons[ext] || '📄';
}

function isImageFile(name) {
    return /\.(png|jpg|jpeg|gif|webp|bmp|ico|svg)$/i.test(name);
}

function isTextFile(name) {
    return /\.(xml|txt|json|html|css|js|properties|pro|mf|sf|smali|kt|java|md|cfg|ini|yml|yaml)$/i.test(name);
}

// ─── APK Loading ───
async function loadAPK(file) {
    showLoading('Reading APK file...', file.name);
    setProgress(10);

    try {
        const data = await file.arrayBuffer();
        setProgress(20);
        showLoading('Extracting ZIP contents...', `${formatSize(data.byteLength)}`);

        APP.zip = await JSZip.loadAsync(data);
        APP.files = {};
        APP.allStrings.clear();
        let entries = Object.keys(APP.zip.files);
        let total = entries.length;
        let idx = 0;

        showLoading(`Processing ${total} files...`);

        for (const path of entries) {
            const entry = APP.zip.files[path];
            APP.files[path] = {
                name: path,
                dir: entry.dir,
                size: entry._data ? entry._data.uncompressedSize || 0 : 0,
                compressedSize: entry._data ? entry._data.compressedSize || 0 : 0,
                date: entry.date,
            };
            idx++;
            if (idx % 50 === 0) {
                setProgress(20 + (idx / total) * 60);
                showLoading(`Processing files...`, `${idx}/${total}`);
                await new Promise(r => setTimeout(r, 0));
            }
        }

        setProgress(85);
        showLoading('Parsing manifest...');
        await parseManifest();

        setProgress(95);
        showLoading('Building file tree...');
        buildFileTree();
        updateUI();

        setProgress(100);
        hideLoading();

        $('welcomeScreen').classList.add('hidden');
        $('appWorkspace').classList.remove('hidden');
        $('headerInfo').classList.remove('hidden');
        $('btnShortcuts').classList.remove('hidden');
        $('btnAdb').classList.remove('hidden');
        $('hdrFileName').textContent = file.name;
        $('hdrFileMeta').textContent = `${formatSize(data.byteLength)} • ${total} files`;

        toast(`Loaded ${file.name} — ${total} files`, 'success');

        // Auto-select AndroidManifest.xml or first .dex
        if (APP.files['AndroidManifest.xml']) {
            selectFile('AndroidManifest.xml');
        } else {
            const firstDex = entries.find(e => e.endsWith('.dex'));
            if (firstDex) selectFile(firstDex);
        }

    } catch (err) {
        hideLoading();
        toast('Error loading APK: ' + err.message, 'error');
        console.error(err);
    }
}

// ─── Manifest Parsing (Binary XML basic decode) ───
async function parseManifest() {
    APP.manifest = { package: '—', versionName: '—', versionCode: '—', minSdk: '—', targetSdk: '—', permissions: [] };
    try {
        const entry = APP.zip.files['AndroidManifest.xml'];
        if (!entry) return;
        const buf = await entry.async('arraybuffer');
        const bytes = new Uint8Array(buf);
        // Extract strings from binary XML
        const strs = extractBinaryXmlStrings(bytes);
        // Try to find package, version, sdks from string table
        for (const s of strs) {
            if (s.match(/^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*){2,}$/)) {
                if (!APP.manifest.package || APP.manifest.package === '—') APP.manifest.package = s;
            }
            if (s.match(/^android\.permission\./)) APP.manifest.permissions.push(s);
            if (s.match(/^\d+\.\d+/)) { if (APP.manifest.versionName === '—') APP.manifest.versionName = s; }
        }
    } catch (e) { console.warn('Manifest parse warning:', e); }
}

function extractBinaryXmlStrings(bytes) {
    const strings = [];
    if (bytes.length < 8) return strings;
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    // Try to find UTF-8 and UTF-16 strings
    let i = 0;
    while (i < bytes.length - 4) {
        // Look for printable ASCII runs
        let start = i;
        while (i < bytes.length && bytes[i] >= 32 && bytes[i] < 127) i++;
        if (i - start >= 4) {
            strings.push(String.fromCharCode(...bytes.slice(start, i)));
        }
        i++;
    }
    return [...new Set(strings)];
}

// ─── File Tree ───
function buildFileTree() {
    const tree = {};
    for (const path of Object.keys(APP.files)) {
        if (APP.files[path].dir) continue;
        const parts = path.split('/');
        let node = tree;
        for (let i = 0; i < parts.length - 1; i++) {
            if (!node[parts[i]]) node[parts[i]] = {};
            node = node[parts[i]];
        }
        node[parts[parts.length - 1]] = path;
    }
    APP.fileTree = tree;
    renderFileTree();
}

function renderFileTree(filter = '') {
    const container = $('fileTree');
    container.innerHTML = '';
    const filterLower = filter.toLowerCase();
    let fileCount = 0;

    function renderNode(node, depth, parentPath) {
        const entries = Object.entries(node).sort(([a, va], [b, vb]) => {
            const aDir = typeof va === 'object', bDir = typeof vb === 'object';
            if (aDir !== bDir) return aDir ? -1 : 1;
            return a.localeCompare(b);
        });

        for (const [name, value] of entries) {
            const fullPath = parentPath ? parentPath + '/' + name : name;
            const isDir = typeof value === 'object';

            if (filter && !isDir) {
                if (!fullPath.toLowerCase().includes(filterLower) && !name.toLowerCase().includes(filterLower)) continue;
            }

            const item = document.createElement('div');
            item.className = 'tree-item' + (isDir ? ' is-dir' : '');
            if (!isDir && fullPath === APP.currentFile) item.classList.add('active');

            let indent = '';
            for (let i = 0; i < depth; i++) indent += '<span class="tree-indent"></span>';

            if (isDir) {
                item.innerHTML = `${indent}<span class="tree-toggle" data-path="${fullPath}">▼</span><span class="tree-icon">📁</span><span class="tree-name">${name}</span>`;
                item.addEventListener('click', (e) => {
                    const toggle = item.querySelector('.tree-toggle');
                    const next = item.nextElementSibling;
                    toggle.classList.toggle('collapsed');
                    // Toggle children visibility
                    let sibling = item.nextElementSibling;
                    const myDepth = depth;
                    while (sibling) {
                        const sibIndents = sibling.querySelectorAll('.tree-indent').length;
                        if (sibIndents <= myDepth && !sibling.querySelector(`.tree-toggle[data-path="${fullPath}"]`)) break;
                        if (sibIndents > myDepth) {
                            sibling.classList.toggle('hidden', toggle.classList.contains('collapsed'));
                        }
                        sibling = sibling.nextElementSibling;
                    }
                });
            } else {
                const fileInfo = APP.files[value];
                const size = fileInfo ? formatSize(fileInfo.size) : '';
                item.innerHTML = `${indent}<span class="tree-indent"></span><span class="tree-icon">${getFileIcon(name)}</span><span class="tree-name">${name}</span><span class="tree-size">${size}</span>`;
                item.addEventListener('click', () => selectFile(value));
                fileCount++;
            }
            container.appendChild(item);

            if (isDir) {
                renderNode(value, depth + 1, fullPath);
            }
        }
    }

    renderNode(APP.fileTree, 0, '');
    $('fileCount').textContent = fileCount + ' files';
}

// ─── File Selection ───
async function selectFile(path) {
    APP.currentFile = path;
    showLoading('Loading file...', path);

    try {
        const entry = APP.zip.files[path];
        if (!entry) { hideLoading(); toast('File not found', 'error'); return; }

        APP.currentData = await entry.async('arraybuffer');
        hideLoading();

        // Update tree active state
        $$('.tree-item.active').forEach(el => el.classList.remove('active'));
        $$('.tree-item').forEach(el => {
            const nameEl = el.querySelector('.tree-name');
            if (nameEl && el.dataset.path === path) el.classList.add('active');
        });

        // Auto-detect best tab
        if (isImageFile(path)) switchTab('image');
        else if (path.endsWith('.xml') || isTextFile(path)) switchTab('text');
        else if (path.endsWith('.smali')) switchTab('smali');
        else switchTab('hex');

        renderCurrentView();
        renderFileTree($('treeSearch').value);
        toast(`Opened: ${path.split('/').pop()}`, 'info');
    } catch (err) {
        hideLoading();
        toast('Error reading file: ' + err.message, 'error');
    }
}

// ─── Tab Switching ───
function switchTab(tab) {
    APP.currentTab = tab;
    $$('.tab').forEach(t => t.classList.toggle('active', t.dataset.tab === tab));
    ['viewHex', 'viewStrings', 'viewText', 'viewSmali', 'viewImage', 'viewInfo'].forEach(id => {
        $(id).classList.toggle('hidden', id !== 'view' + tab.charAt(0).toUpperCase() + tab.slice(1));
    });
    renderCurrentView();
}

function renderCurrentView() {
    if (!APP.currentData) return;
    const bytes = new Uint8Array(APP.currentData);
    switch (APP.currentTab) {
        case 'hex': renderHex(bytes); break;
        case 'strings': renderStrings(bytes); break;
        case 'text': renderText(bytes); break;
        case 'smali': renderSmali(bytes); break;
        case 'image': renderImage(); break;
        case 'info': renderFileInfo(bytes); break;
    }
}

// ─── Hex Viewer ───
function renderHex(bytes, startOffset = 0) {
    const container = $('hexContent');
    $('hexFileSize').textContent = formatSize(bytes.length);
    const maxBytes = Math.min(bytes.length, 16 * 500); // Show max 500 rows
    let html = '';

    for (let i = startOffset; i < Math.min(startOffset + maxBytes, bytes.length); i += 16) {
        const offset = i.toString(16).toUpperCase().padStart(8, '0');
        let hexPart = '', asciiPart = '';

        for (let j = 0; j < 16; j++) {
            if (i + j < bytes.length) {
                const b = bytes[i + j];
                const hex = b.toString(16).toUpperCase().padStart(2, '0');
                if (b === 0) hexPart += `<span class="null-byte">${hex}</span> `;
                else if (b > 127) hexPart += `<span class="high-byte">${hex}</span> `;
                else hexPart += `<span class="printable-byte">${hex}</span> `;

                asciiPart += (b >= 32 && b < 127) ? String.fromCharCode(b) : '<span class="non-printable">.</span>';
            } else {
                hexPart += '   ';
                asciiPart += ' ';
            }
            if (j === 7) hexPart += ' ';
        }

        html += `<div class="hex-row"><span class="hex-offset">${offset}</span><span class="hex-bytes">${hexPart}</span><span class="hex-ascii">${asciiPart}</span></div>`;
    }

    if (bytes.length > maxBytes + startOffset) {
        html += `<div style="padding:12px;color:var(--text-muted);font-size:0.78rem">... ${formatSize(bytes.length - maxBytes - startOffset)} more (use Ctrl+G to navigate)</div>`;
    }
    container.innerHTML = html;
}

// ─── String Extractor ───
function extractStrings(bytes, minLen = 4) {
    const strings = [];
    let current = '';
    let startOffset = 0;

    for (let i = 0; i < bytes.length; i++) {
        const ch = bytes[i];
        if (ch >= 32 && ch < 127) {
            if (current.length === 0) startOffset = i;
            current += String.fromCharCode(ch);
        } else {
            if (current.length >= minLen) {
                strings.push({ offset: startOffset, value: current });
            }
            current = '';
        }
    }
    if (current.length >= minLen) strings.push({ offset: startOffset, value: current });
    return strings;
}

function renderStrings(bytes) {
    const minLen = parseInt($('stringsMinLen').value) || 4;
    const search = $('stringsSearch').value.toLowerCase();
    const strings = extractStrings(bytes, minLen);
    let filtered = strings;
    if (search) filtered = strings.filter(s => s.value.toLowerCase().includes(search));

    $('stringsCount').textContent = `${filtered.length}/${strings.length} strings`;
    const container = $('stringsContent');
    const flagPatterns = getActiveFlags();
    const maxShow = 500;

    let html = '';
    for (let i = 0; i < Math.min(filtered.length, maxShow); i++) {
        const s = filtered[i];
        const isFlag = flagPatterns.some(p => s.value.match(p));
        let display = escapeHtml(s.value);
        if (search) {
            const re = new RegExp(`(${escapeRegex(search)})`, 'gi');
            display = display.replace(re, '<span class="highlight">$1</span>');
        }
        html += `<div class="string-item${isFlag ? ' is-flag' : ''}" data-value="${escapeHtml(s.value)}" data-offset="${s.offset}" oncontextmenu="showStringContext(event, this)">
            <span class="string-offset">0x${s.offset.toString(16).toUpperCase().padStart(6, '0')}</span>
            <span class="string-value">${display}</span></div>`;
    }
    if (filtered.length > maxShow) {
        html += `<div style="padding:12px;color:var(--text-muted)">... ${filtered.length - maxShow} more strings</div>`;
    }
    container.innerHTML = html || '<div class="empty-state"><div class="empty-state-icon">📝</div><div class="empty-state-text">No strings found</div></div>';
}

// ─── Text/XML Viewer ───
function renderText(bytes) {
    const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    const container = $('textContent');

    if (APP.currentFile && APP.currentFile.endsWith('.xml')) {
        container.innerHTML = highlightXml(text);
    } else {
        container.textContent = text;
    }
}

function highlightXml(text) {
    // Try to pretty-print if it's valid-looking XML
    let formatted = text;
    try {
        // Basic XML syntax highlighting
        formatted = escapeHtml(text)
            .replace(/(&lt;\/?)([\w:\-]+)/g, '$1<span class="xml-tag">$2</span>')
            .replace(/([\w:\-]+)(=)(&quot;|&#39;)(.*?)(\3)/g, '<span class="xml-attr-name">$1</span>$2<span class="xml-attr-value">$3$4$5</span>')
            .replace(/(&lt;!--)(.*?)(--&gt;)/gs, '<span class="xml-comment">$1$2$3</span>');
    } catch (e) {
        formatted = escapeHtml(text);
    }
    return formatted;
}

// ─── Smali Viewer ───
function renderSmali(bytes) {
    const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    const lines = text.split('\n');
    const container = $('smaliContent');
    let html = '';

    for (let i = 0; i < lines.length; i++) {
        let line = escapeHtml(lines[i]);
        // Syntax highlighting
        line = line
            .replace(/^(\s*)(\.(?:class|super|source|method|end method|field|end field|implements|annotation|end annotation|subannotation|end subannotation|locals|registers|param|prologue|line|enum|restart local|end local|catch|catchall))\b/g, '$1<span class="smali-directive">$2</span>')
            .replace(/\b(public|private|protected|static|final|abstract|synthetic|bridge|native|volatile|transient|synchronized|strict|interface|enum|constructor)\b/g, '<span class="smali-keyword">$1</span>')
            .replace(/(L[\w\/\$]+;)/g, '<span class="smali-type">$1</span>')
            .replace(/(&quot;[^&]*?&quot;)/g, '<span class="smali-string">$1</span>')
            .replace(/"([^"]*)"/g, '<span class="smali-string">"$1"</span>')
            .replace(/\b(v\d+|p\d+)\b/g, '<span class="smali-register">$1</span>')
            .replace(/(#.*)$/g, '<span class="smali-comment">$1</span>')
            .replace(/\b(0x[0-9a-fA-F]+|\b\d+)\b/g, '<span class="smali-number">$1</span>')
            .replace(/^(\s*)(:\w+)/g, '$1<span class="smali-label">$2</span>');

        html += `<div class="smali-line"><span class="smali-linenum">${i + 1}</span><span class="smali-code">${line}</span></div>`;
    }
    container.innerHTML = html;
}

// ─── Image Viewer ───
function renderImage() {
    const container = $('imageContent');
    if (!APP.currentFile || !isImageFile(APP.currentFile)) {
        container.innerHTML = '<div class="empty-state"><div class="empty-state-icon">🖼️</div><div class="empty-state-text">Select an image file</div></div>';
        return;
    }
    const blob = new Blob([APP.currentData]);
    const url = URL.createObjectURL(blob);
    container.innerHTML = `<img src="${url}" alt="${APP.currentFile}" onload="this.style.opacity=1" style="opacity:0;transition:opacity 0.3s">`;
}

// ─── File Info ───
function renderFileInfo(bytes) {
    const container = $('fileInfoContent');
    const info = APP.files[APP.currentFile];
    if (!info) { container.innerHTML = '<div class="empty-state"><div class="empty-state-icon">📋</div><div class="empty-state-text">No file selected</div></div>'; return; }

    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    let magic = '';
    if (bytes.length >= 4) magic = Array.from(bytes.slice(0, 4)).map(b => b.toString(16).padStart(2, '0')).join(' ');

    let fileType = 'Unknown';
    if (bytes[0] === 0x64 && bytes[1] === 0x65 && bytes[2] === 0x78) fileType = 'Dalvik Executable (DEX)';
    else if (bytes[0] === 0x50 && bytes[1] === 0x4B) fileType = 'ZIP Archive';
    else if (bytes[0] === 0x89 && bytes[1] === 0x50) fileType = 'PNG Image';
    else if (bytes[0] === 0xFF && bytes[1] === 0xD8) fileType = 'JPEG Image';
    else if (bytes[0] === 0x7F && bytes[1] === 0x45) fileType = 'ELF Binary (Native Library)';
    else if (bytes[0] === 0x03 && bytes[1] === 0x00) fileType = 'Android Binary XML';
    else if (bytes[0] === 0x02 && bytes[1] === 0x00) fileType = 'Android Resource Table';
    else if (isTextFile(APP.currentFile)) fileType = 'Text File';

    // DEX info
    let dexInfo = '';
    if (bytes[0] === 0x64 && bytes[1] === 0x65 && bytes[2] === 0x78 && bytes.length > 112) {
        const dexVersion = String.fromCharCode(bytes[4], bytes[5], bytes[6]);
        const stringCount = view.getUint32(56, true);
        const typeCount = view.getUint32(64, true);
        const methodCount = view.getUint32(88, true);
        const classCount = view.getUint32(96, true);
        dexInfo = `
        <div style="margin-top:16px">
            <div class="details-section-title"><span class="section-icon">🧩</span> DEX Details</div>
            <div class="apk-info-grid">
                <span class="apk-info-label">DEX Version</span><span class="apk-info-value">${dexVersion}</span>
                <span class="apk-info-label">Strings</span><span class="apk-info-value">${stringCount.toLocaleString()}</span>
                <span class="apk-info-label">Types</span><span class="apk-info-value">${typeCount.toLocaleString()}</span>
                <span class="apk-info-label">Methods</span><span class="apk-info-value">${methodCount.toLocaleString()}</span>
                <span class="apk-info-label">Classes</span><span class="apk-info-value">${classCount.toLocaleString()}</span>
            </div>
        </div>`;
    }

    // ELF info
    let elfInfo = '';
    if (bytes[0] === 0x7F && bytes[1] === 0x45 && bytes[2] === 0x4C && bytes[3] === 0x46) {
        const is64 = bytes[4] === 2;
        const endian = bytes[5] === 1 ? 'Little Endian' : 'Big Endian';
        const machineTypes = { 3: 'x86', 40: 'ARM', 62: 'x86_64', 183: 'AArch64' };
        const machine = is64 ? view.getUint16(18, true) : view.getUint16(18, true);
        elfInfo = `
        <div style="margin-top:16px">
            <div class="details-section-title"><span class="section-icon">⚙️</span> ELF Details</div>
            <div class="apk-info-grid">
                <span class="apk-info-label">Class</span><span class="apk-info-value">${is64 ? '64-bit' : '32-bit'}</span>
                <span class="apk-info-label">Endian</span><span class="apk-info-value">${endian}</span>
                <span class="apk-info-label">Machine</span><span class="apk-info-value">${machineTypes[machine] || 'Unknown (' + machine + ')'}</span>
            </div>
        </div>`;
    }

    // Entropy calculation
    const entropy = calcEntropy(bytes);
    const entropyPct = (entropy / 8 * 100).toFixed(1);

    container.innerHTML = `
        <div class="details-section-title"><span class="section-icon">📋</span> File Details</div>
        <div class="apk-info-grid">
            <span class="apk-info-label">Path</span><span class="apk-info-value">${escapeHtml(APP.currentFile)}</span>
            <span class="apk-info-label">Size</span><span class="apk-info-value">${formatSize(bytes.length)} (${bytes.length.toLocaleString()} bytes)</span>
            <span class="apk-info-label">Type</span><span class="apk-info-value">${fileType}</span>
            <span class="apk-info-label">Magic</span><span class="apk-info-value mono">${magic}</span>
            <span class="apk-info-label">Entropy</span><span class="apk-info-value">${entropy.toFixed(3)} / 8.0 (${entropyPct}%)</span>
            <span class="apk-info-label">High Entropy</span><span class="apk-info-value" style="color:${entropy > 7 ? 'var(--accent-red)' : 'var(--accent-green)'}">${entropy > 7 ? '⚠️ Likely encrypted/compressed' : '✅ Normal'}</span>
        </div>
        ${dexInfo}${elfInfo}`;
}

function calcEntropy(bytes) {
    if (bytes.length === 0) return 0;
    const freq = new Array(256).fill(0);
    for (let i = 0; i < bytes.length; i++) freq[bytes[i]]++;
    let entropy = 0;
    for (let i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            const p = freq[i] / bytes.length;
            entropy -= p * Math.log2(p);
        }
    }
    return entropy;
}

// ─── UI Update ───
function updateUI() {
    const files = Object.values(APP.files);
    const fileList = files.filter(f => !f.dir);
    const totalSize = fileList.reduce((sum, f) => sum + (f.size || 0), 0);
    const dexCount = fileList.filter(f => f.name.endsWith('.dex')).length;
    const soCount = fileList.filter(f => f.name.endsWith('.so')).length;

    $('statFiles').textContent = fileList.length;
    $('statSize').textContent = formatSize(totalSize);
    $('statDex').textContent = dexCount;
    $('statNative').textContent = soCount;

    // APK Info
    if (APP.manifest) {
        $('infoPackage').textContent = APP.manifest.package;
        $('infoVersion').textContent = APP.manifest.versionName;
        $('infoMinSdk').textContent = APP.manifest.minSdk;
        $('infoTargetSdk').textContent = APP.manifest.targetSdk;

        // Permissions
        const permEl = $('permissionsList');
        if (APP.manifest.permissions.length > 0) {
            const dangerous = ['CAMERA', 'READ_CONTACTS', 'ACCESS_FINE_LOCATION', 'RECORD_AUDIO', 'READ_PHONE_STATE',
                'SEND_SMS', 'READ_SMS', 'READ_EXTERNAL_STORAGE', 'WRITE_EXTERNAL_STORAGE', 'CALL_PHONE', 'READ_CALL_LOG'];
            permEl.innerHTML = APP.manifest.permissions.map(p => {
                const short = p.replace('android.permission.', '');
                const isDangerous = dangerous.some(d => short.includes(d));
                return `<div class="permission-item"><span class="permission-dot ${isDangerous ? 'dangerous' : 'normal'}"></span>${short}</div>`;
            }).join('');
        } else {
            permEl.innerHTML = '<div class="text-muted" style="font-size:0.75rem">No permissions found in manifest</div>';
        }
    }
}

// ─── CTF Scanner ───
function getActiveFlags() {
    const builtIn = ['CTF', 'FLAG', 'flag', 'HTB', 'THM', 'picoCTF', 'DUCTF', 'LKS', 'pico', 'ctf'];
    const custom = $('flagFormat').value.split(',').map(s => s.trim()).filter(Boolean);
    const all = [...builtIn, ...custom];
    return all.map(prefix => new RegExp(`${escapeRegex(prefix)}\\{[^}]+\\}`, 'g'));
}

async function autoScan() {
    showLoading('🚩 Scanning all files for flags...');
    const results = { flags: [], base64: [], urls: [], secrets: [], interesting: [] };
    const flagPatterns = getActiveFlags();
    const entries = Object.keys(APP.files).filter(p => !APP.files[p].dir);
    let count = 0;

    for (const path of entries) {
        try {
            const entry = APP.zip.files[path];
            if (!entry || APP.files[path].dir) continue;
            const buf = await entry.async('arraybuffer');
            const bytes = new Uint8Array(buf);
            const strs = extractStrings(bytes, 4);

            for (const s of strs) {
                // Flag patterns
                for (const pattern of flagPatterns) {
                    const matches = s.value.match(pattern);
                    if (matches) matches.forEach(m => results.flags.push({ file: path, value: m, type: 'flag' }));
                }
                // Base64
                if (s.value.match(/^[A-Za-z0-9+\/]{12,}={0,2}$/) && s.value.length > 12) {
                    try {
                        const decoded = atob(s.value);
                        if (decoded.length > 4 && /[\x20-\x7e]{4,}/.test(decoded)) {
                            results.base64.push({ file: path, value: s.value, decoded, type: 'base64' });
                        }
                    } catch (e) { }
                }
                // URLs
                const urlMatch = s.value.match(/https?:\/\/[^\s"'<>]+/g);
                if (urlMatch) urlMatch.forEach(u => results.urls.push({ file: path, value: u, type: 'url' }));
                // Secrets
                if (/(?:password|secret|key|token|api_key|apikey|auth|credential|private)/i.test(s.value)) {
                    results.secrets.push({ file: path, value: s.value, type: 'secret' });
                }
                // Interesting
                if (/(flag|ctf|hint|debug|test|admin|root|shell|exec|eval|system)/i.test(s.value) && !results.flags.some(f => f.value === s.value)) {
                    results.interesting.push({ file: path, value: s.value, type: 'interesting' });
                }
            }
        } catch (e) { }

        count++;
        if (count % 20 === 0) {
            setProgress((count / entries.length) * 100);
            showLoading('🚩 Scanning...', `${count}/${entries.length} files`);
            await new Promise(r => setTimeout(r, 0));
        }
    }

    hideLoading();
    showScanResults(results);
}

function showScanResults(results) {
    const total = results.flags.length + results.base64.length + results.urls.length + results.secrets.length + results.interesting.length;
    $('ctfResultsTitle').textContent = `🚩 Scan Results — ${total} findings`;

    let html = '';
    const sections = [
        { title: '🚩 Flags', items: results.flags, color: 'var(--accent-orange)' },
        { title: '🔓 Base64 Encoded', items: results.base64, color: 'var(--accent-purple)' },
        { title: '🌐 URLs', items: results.urls, color: 'var(--accent-blue)' },
        { title: '🔑 Secrets/Keys', items: results.secrets, color: 'var(--accent-red)' },
        { title: '💡 Interesting Strings', items: results.interesting.slice(0, 50), color: 'var(--accent-green)' },
    ];

    for (const section of sections) {
        if (section.items.length === 0) continue;
        html += `<h4 style="color:${section.color};margin:16px 0 8px;font-size:0.9rem">${section.title} (${section.items.length})</h4>`;
        for (const item of section.items.slice(0, 100)) {
            const decoded = item.decoded ? `<div style="color:var(--accent-green);font-size:0.72rem;margin-top:3px">→ ${escapeHtml(item.decoded)}</div>` : '';
            html += `<div class="ctf-result-item" onclick="selectFile('${escapeHtml(item.file)}')">
                <div class="ctf-result-file">📄 ${escapeHtml(item.file)}</div>
                <div class="ctf-result-value">${escapeHtml(item.value)}</div>${decoded}</div>`;
        }
    }

    if (total === 0) {
        html = '<div class="empty-state"><div class="empty-state-icon">🔍</div><div class="empty-state-text">No findings</div><div class="empty-state-sub">Try adding custom flag prefixes</div></div>';
    }

    $('ctfResultsBody').innerHTML = html;
    $('ctfResultsModal').classList.remove('hidden');

    // Also update sidebar results
    const sidebarResults = $('ctfResults');
    if (results.flags.length > 0) {
        sidebarResults.innerHTML = results.flags.map(f =>
            `<div class="ctf-result-item" onclick="selectFile('${escapeHtml(f.file)}')">
                <div class="ctf-result-file">📄 ${f.file.split('/').pop()}</div>
                <div class="ctf-result-value">${escapeHtml(f.value)}</div></div>`
        ).join('');
    }

    toast(`Scan complete: ${total} findings`, total > 0 ? 'success' : 'info');
}

// ─── Decoder ───
function decode(type, input) {
    try {
        switch (type) {
            case 'base64': return atob(input);
            case 'hex': return input.replace(/\s/g, '').match(/.{2}/g)?.map(h => String.fromCharCode(parseInt(h, 16))).join('') || '';
            case 'url': return decodeURIComponent(input);
            case 'rot13': return input.replace(/[a-zA-Z]/g, c => String.fromCharCode(c.charCodeAt(0) + (c.toLowerCase() < 'n' ? 13 : -13)));
            case 'binary': return input.trim().split(/\s+/).map(b => String.fromCharCode(parseInt(b, 2))).join('');
            case 'reverse': return input.split('').reverse().join('');
            case 'ascii': return input.trim().split(/[\s,]+/).map(n => String.fromCharCode(parseInt(n))).join('');
            default: return input;
        }
    } catch (e) { return '⚠️ Error: ' + e.message; }
}

// ─── Helpers ───
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function escapeRegex(str) { return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

function formatSize(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function extractBinaryXmlStrings(bytes) {
    // Extract strings from Android binary XML (AXML) format
    const strings = [];
    const strs = extractStrings(bytes, 3);
    for (const s of strs) {
        if (/^[a-zA-Z][\w.$\/]+$/.test(s.value) && s.value.length > 3) {
            strings.push(s.value);
        }
    }
    // Also try UTF-16LE extraction (common in AXML)
    for (let i = 0; i < bytes.length - 1; i += 2) {
        let str = '';
        while (i < bytes.length - 1 && bytes[i] >= 32 && bytes[i] < 127 && bytes[i + 1] === 0) {
            str += String.fromCharCode(bytes[i]);
            i += 2;
        }
        if (str.length >= 3) strings.push(str);
    }
    return [...new Set(strings)];
}

function showStringContext(event, el) {
    event.preventDefault();
    const menu = $('contextMenu');
    menu.style.left = event.clientX + 'px';
    menu.style.top = event.clientY + 'px';
    menu.classList.remove('hidden');
    menu.dataset.value = el.dataset.value || '';
    menu.dataset.file = APP.currentFile || '';
}

// ─── Event Listeners ───
document.addEventListener('DOMContentLoaded', () => {
    // File open
    $('btnOpen').addEventListener('click', () => $('fileInput').click());
    $('fileInput').addEventListener('change', e => { if (e.target.files[0]) loadAPK(e.target.files[0]); });

    // Drop zone
    const dz = $('dropZone');
    if (dz) {
        dz.addEventListener('click', () => $('fileInput').click());
        ['dragover', 'dragenter'].forEach(ev => dz.addEventListener(ev, e => { e.preventDefault(); dz.classList.add('dragover'); }));
        ['dragleave', 'drop'].forEach(ev => dz.addEventListener(ev, e => { e.preventDefault(); dz.classList.remove('dragover'); }));
        dz.addEventListener('drop', e => { if (e.dataTransfer.files[0]) loadAPK(e.dataTransfer.files[0]); });
    }

    // Also handle drop on entire body
    document.body.addEventListener('dragover', e => e.preventDefault());
    document.body.addEventListener('drop', e => { e.preventDefault(); if (e.dataTransfer.files[0]) loadAPK(e.dataTransfer.files[0]); });

    // Tabs
    $$('.tab').forEach(tab => tab.addEventListener('click', () => switchTab(tab.dataset.tab)));

    // Tree search
    $('treeSearch').addEventListener('input', e => renderFileTree(e.target.value));

    // Strings search
    $('stringsSearch')?.addEventListener('input', () => { if (APP.currentData) renderStrings(new Uint8Array(APP.currentData)); });
    $('stringsMinLen')?.addEventListener('change', () => { if (APP.currentData) renderStrings(new Uint8Array(APP.currentData)); });

    // Copy strings
    $('btnCopyStrings')?.addEventListener('click', () => {
        if (!APP.currentData) return;
        const strs = extractStrings(new Uint8Array(APP.currentData), parseInt($('stringsMinLen').value) || 4);
        navigator.clipboard.writeText(strs.map(s => s.value).join('\n'));
        toast('Strings copied!', 'success');
    });

    // Hex goto
    $('hexGotoBtn')?.addEventListener('click', () => {
        const offset = parseInt($('hexGoto').value, 16) || parseInt($('hexGoto').value) || 0;
        if (APP.currentData) renderHex(new Uint8Array(APP.currentData), offset);
    });

    // CTF Buttons
    $('btnAutoScan')?.addEventListener('click', autoScan);
    $('btnScanStrings')?.addEventListener('click', async () => {
        showLoading('📝 Extracting all strings...');
        const results = [];
        const entries = Object.keys(APP.files).filter(p => !APP.files[p].dir);
        for (const path of entries) {
            try {
                const buf = await APP.zip.files[path].async('arraybuffer');
                const strs = extractStrings(new Uint8Array(buf), 6);
                strs.forEach(s => results.push({ file: path, ...s }));
            } catch (e) { }
        }
        hideLoading();
        $('ctfResultsTitle').textContent = `📝 All Strings — ${results.length} found`;
        $('ctfResultsBody').innerHTML = results.slice(0, 500).map(r =>
            `<div class="ctf-result-item" onclick="selectFile('${escapeHtml(r.file)}')">
                <div class="ctf-result-file">📄 ${r.file.split('/').pop()}</div>
                <div class="ctf-result-value">${escapeHtml(r.value)}</div></div>`
        ).join('') || '<div class="empty-state"><div class="empty-state-icon">📝</div><div class="empty-state-text">No strings found</div></div>';
        $('ctfResultsModal').classList.remove('hidden');
    });

    $('btnScanBase64')?.addEventListener('click', async () => {
        showLoading('🔓 Scanning for Base64...');
        const results = [];
        for (const path of Object.keys(APP.files).filter(p => !APP.files[p].dir)) {
            try {
                const buf = await APP.zip.files[path].async('arraybuffer');
                const strs = extractStrings(new Uint8Array(buf), 8);
                for (const s of strs) {
                    if (s.value.match(/^[A-Za-z0-9+\/]{12,}={0,2}$/)) {
                        try { const d = atob(s.value); if (/[\x20-\x7e]{4,}/.test(d)) results.push({ file: path, value: s.value, decoded: d }); } catch (e) { }
                    }
                }
            } catch (e) { }
        }
        hideLoading();
        $('ctfResultsTitle').textContent = `🔓 Base64 Strings — ${results.length} found`;
        $('ctfResultsBody').innerHTML = results.slice(0, 200).map(r =>
            `<div class="ctf-result-item"><div class="ctf-result-file">📄 ${r.file.split('/').pop()}</div>
            <div class="ctf-result-value">${escapeHtml(r.value)}</div>
            <div style="color:var(--accent-green);font-size:0.72rem;margin-top:3px">→ ${escapeHtml(r.decoded)}</div></div>`
        ).join('') || '<div class="empty-state"><div class="empty-state-icon">🔓</div><div class="empty-state-text">No Base64 strings found</div></div>';
        $('ctfResultsModal').classList.remove('hidden');
    });

    $('btnScanUrls')?.addEventListener('click', async () => {
        showLoading('🌐 Extracting URLs...');
        const results = [];
        for (const path of Object.keys(APP.files).filter(p => !APP.files[p].dir)) {
            try {
                const buf = await APP.zip.files[path].async('arraybuffer');
                const strs = extractStrings(new Uint8Array(buf), 8);
                for (const s of strs) {
                    const urls = s.value.match(/https?:\/\/[^\s"'<>]+/g);
                    if (urls) urls.forEach(u => results.push({ file: path, value: u }));
                }
            } catch (e) { }
        }
        hideLoading();
        const unique = [...new Map(results.map(r => [r.value, r])).values()];
        $('ctfResultsTitle').textContent = `🌐 URLs — ${unique.length} unique found`;
        $('ctfResultsBody').innerHTML = unique.map(r =>
            `<div class="ctf-result-item"><div class="ctf-result-file">📄 ${r.file.split('/').pop()}</div>
            <div class="ctf-result-value" style="color:var(--accent-blue)">${escapeHtml(r.value)}</div></div>`
        ).join('') || '<div class="empty-state"><div class="empty-state-icon">🌐</div><div class="empty-state-text">No URLs found</div></div>';
        $('ctfResultsModal').classList.remove('hidden');
    });

    $('btnScanSecrets')?.addEventListener('click', async () => {
        showLoading('🔑 Searching for secrets...');
        const results = [];
        const patterns = /(?:password|secret|key|token|api_key|apikey|auth|credential|private|passwd|pwd|admin|root|debug|firebase|aws|azure)/i;
        for (const path of Object.keys(APP.files).filter(p => !APP.files[p].dir)) {
            try {
                const buf = await APP.zip.files[path].async('arraybuffer');
                const strs = extractStrings(new Uint8Array(buf), 6);
                for (const s of strs) { if (patterns.test(s.value)) results.push({ file: path, value: s.value }); }
            } catch (e) { }
        }
        hideLoading();
        $('ctfResultsTitle').textContent = `🔑 Secrets — ${results.length} found`;
        $('ctfResultsBody').innerHTML = results.slice(0, 200).map(r =>
            `<div class="ctf-result-item"><div class="ctf-result-file">📄 ${r.file.split('/').pop()}</div>
            <div class="ctf-result-value" style="color:var(--accent-red)">${escapeHtml(r.value)}</div></div>`
        ).join('') || '<div class="empty-state"><div class="empty-state-icon">🔑</div><div class="empty-state-text">No secrets found</div></div>';
        $('ctfResultsModal').classList.remove('hidden');
    });

    // Copy results
    $('btnCopyResults')?.addEventListener('click', () => {
        const text = $('ctfResultsBody').innerText;
        navigator.clipboard.writeText(text);
        toast('Results copied!', 'success');
    });

    // Decoder
    $$('.decoder-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const type = btn.dataset.decode;
            const input = $('decoderInput').value;
            $('decoderOutput').textContent = decode(type, input);
            $$('.decoder-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
        });
    });

    // Shortcuts & ADB modals
    $('btnShortcuts')?.addEventListener('click', () => $('shortcutsModal').classList.remove('hidden'));
    $('btnAdb')?.addEventListener('click', () => $('adbModal').classList.remove('hidden'));

    // Close modals on overlay click
    $$('.modal-overlay').forEach(overlay => {
        overlay.addEventListener('click', e => { if (e.target === overlay) overlay.classList.add('hidden'); });
    });

    // Context menu
    document.addEventListener('click', () => $('contextMenu').classList.add('hidden'));
    $$('.context-item').forEach(item => {
        item.addEventListener('click', () => {
            const action = item.dataset.action;
            const value = $('contextMenu').dataset.value;
            const file = $('contextMenu').dataset.file;
            switch (action) {
                case 'copy': navigator.clipboard.writeText(value); toast('Copied!', 'success'); break;
                case 'bookmark':
                    APP.bookmarks.push({ value, file });
                    renderBookmarks();
                    toast('Bookmarked!', 'success');
                    break;
                case 'decode':
                    $('decoderInput').value = value;
                    toast('Pasted to decoder', 'info');
                    break;
                case 'copyHex':
                    const hex = Array.from(new TextEncoder().encode(value)).map(b => b.toString(16).padStart(2, '0')).join(' ');
                    navigator.clipboard.writeText(hex);
                    toast('Hex copied!', 'success');
                    break;
                case 'copyBase64':
                    navigator.clipboard.writeText(btoa(value));
                    toast('Base64 copied!', 'success');
                    break;
            }
        });
    });

    // Keyboard shortcuts
    document.addEventListener('keydown', e => {
        if (e.ctrlKey && e.key === 'o') { e.preventDefault(); $('fileInput').click(); }
        if (e.ctrlKey && e.key === 'f') { e.preventDefault(); $('stringsSearch')?.focus(); switchTab('strings'); }
        if (e.ctrlKey && e.key === 'g') { e.preventDefault(); $('hexGoto')?.focus(); switchTab('hex'); }
        if (e.ctrlKey && e.key === 'p') { e.preventDefault(); $('treeSearch')?.focus(); }
        if (e.altKey && e.key === 'a') { e.preventDefault(); autoScan(); }
        if (e.altKey && e.key === 'h') { e.preventDefault(); switchTab('hex'); }
        if (e.altKey && e.key === 's') { e.preventDefault(); switchTab('strings'); }
        if (e.altKey && e.key === 'x') { e.preventDefault(); switchTab('text'); }
        if (e.altKey && e.key === 'm') { e.preventDefault(); switchTab('smali'); }
        if (e.altKey && e.key === 'i') { e.preventDefault(); switchTab('image'); }
        if (e.key === '?' && !e.ctrlKey && !e.altKey && document.activeElement.tagName !== 'INPUT' && document.activeElement.tagName !== 'TEXTAREA') {
            $('shortcutsModal').classList.remove('hidden');
        }
        if (e.key === 'Escape') {
            $$('.modal-overlay').forEach(m => m.classList.add('hidden'));
            $('contextMenu').classList.add('hidden');
        }
    });
});

function renderBookmarks() {
    const el = $('bookmarksList');
    if (APP.bookmarks.length === 0) {
        el.innerHTML = '<div class="no-bookmarks">Right-click strings to bookmark</div>';
        return;
    }
    el.innerHTML = APP.bookmarks.map((b, i) =>
        `<div class="bookmark-item">
            <span class="bookmark-remove" onclick="APP.bookmarks.splice(${i},1);renderBookmarks()">✕</span>
            <div><div class="bookmark-text">${escapeHtml(b.value)}</div>
            <div class="bookmark-file">${escapeHtml(b.file || 'unknown')}</div></div></div>`
    ).join('');
}

// ═══════════════════════════════════════════════════════
// 🔥🔥🔥 OVERPOWERED CTF MODE 🔥🔥🔥
// ═══════════════════════════════════════════════════════

// ─── Global Search: search ALL files at once ───
async function globalSearchAll(query) {
    if (!query || !APP.zip) { toast('Enter a search query first', 'error'); return; }
    showLoading(`🔍 Searching ALL files for "${query}"...`);
    const results = [];
    const queryLower = query.toLowerCase();
    const entries = Object.keys(APP.files).filter(p => !APP.files[p].dir);
    let count = 0;

    for (const path of entries) {
        try {
            const buf = await APP.zip.files[path].async('arraybuffer');
            const bytes = new Uint8Array(buf);
            const strs = extractStrings(bytes, 3);
            for (const s of strs) {
                if (s.value.toLowerCase().includes(queryLower)) {
                    results.push({ file: path, value: s.value, offset: s.offset });
                }
            }
        } catch (e) { }
        count++;
        if (count % 30 === 0) {
            setProgress((count / entries.length) * 100);
            showLoading(`🔍 Searching...`, `${count}/${entries.length} files`);
            await new Promise(r => setTimeout(r, 0));
        }
    }

    hideLoading();
    $('ctfResultsTitle').textContent = `🔍 Global Search: "${query}" — ${results.length} matches`;
    let html = '';
    const grouped = {};
    results.forEach(r => { if (!grouped[r.file]) grouped[r.file] = []; grouped[r.file].push(r); });
    for (const [file, items] of Object.entries(grouped)) {
        html += `<h4 style="color:var(--accent-cyan);margin:14px 0 6px;font-size:0.82rem;cursor:pointer" onclick="selectFile('${escapeHtml(file)}')">📄 ${escapeHtml(file)} (${items.length} matches)</h4>`;
        for (const item of items.slice(0, 50)) {
            const highlighted = escapeHtml(item.value).replace(new RegExp(`(${escapeRegex(query)})`, 'gi'), '<span class="highlight">$1</span>');
            html += `<div class="ctf-result-item" onclick="selectFile('${escapeHtml(item.file)}')">
                <span class="string-offset" style="margin-right:8px">0x${item.offset.toString(16).padStart(6, '0')}</span>
                <div class="ctf-result-value">${highlighted}</div></div>`;
        }
        if (items.length > 50) html += `<div style="padding:6px;color:var(--text-muted);font-size:0.72rem">... ${items.length - 50} more in this file</div>`;
    }
    if (results.length === 0) html = '<div class="empty-state"><div class="empty-state-icon">🔍</div><div class="empty-state-text">No matches found</div></div>';
    $('ctfResultsBody').innerHTML = html;
    $('ctfResultsModal').classList.remove('hidden');
    toast(`Found ${results.length} matches in ${Object.keys(grouped).length} files`, results.length > 0 ? 'success' : 'info');
}

// ─── FIND FLAG NOW: The Ultimate OP Button ───
async function findFlagNow() {
    if (!APP.zip) { toast('Load an APK first!', 'error'); return; }
    showLoading('🔥 OVERPOWERED SCAN ACTIVATED...');
    const results = { flags: [], base64: [], base64decoded_flags: [], xor_flags: [], caesar_flags: [], urls: [], secrets: [], interesting: [], hidden: [], hex_patterns: [] };
    const flagPatterns = getActiveFlags();
    const entries = Object.keys(APP.files).filter(p => !APP.files[p].dir);
    let count = 0;

    for (const path of entries) {
        try {
            const entry = APP.zip.files[path];
            if (!entry || APP.files[path].dir) continue;
            const buf = await entry.async('arraybuffer');
            const bytes = new Uint8Array(buf);
            const strs = extractStrings(bytes, 4);

            for (const s of strs) {
                // 1. Direct flag patterns
                for (const pattern of flagPatterns) {
                    const matches = s.value.match(pattern);
                    if (matches) matches.forEach(m => results.flags.push({ file: path, value: m, method: 'Direct match' }));
                }
                // 2. Base64 decode then check for flags
                if (s.value.match(/^[A-Za-z0-9+\/]{8,}={0,2}$/) && s.value.length > 8) {
                    try {
                        const decoded = atob(s.value);
                        if (decoded.length > 3 && /[\x20-\x7e]{3,}/.test(decoded)) {
                            results.base64.push({ file: path, value: s.value, decoded, method: 'Base64' });
                            for (const pattern of flagPatterns) {
                                const m2 = decoded.match(pattern);
                                if (m2) m2.forEach(m => results.base64decoded_flags.push({ file: path, value: m, original: s.value, method: 'Base64 → Flag' }));
                            }
                        }
                    } catch (e) { }
                }
                // 3. URLs
                const urlMatch = s.value.match(/https?:\/\/[^\s"'<>]+/g);
                if (urlMatch) urlMatch.forEach(u => results.urls.push({ file: path, value: u, method: 'URL' }));
                // 4. Secrets
                if (/(?:password|secret|key|token|api_key|apikey|auth|credential|private|passwd|pwd|admin|firebase|aws|azure|flag_|secret_)/i.test(s.value)) {
                    results.secrets.push({ file: path, value: s.value, method: 'Secret pattern' });
                }
                // 5. Interesting
                if (/(flag|ctf|hint|debug|test|admin|root|shell|exec|eval|system|decrypt|encrypt|cipher|hidden|obfusc)/i.test(s.value) && !results.flags.some(f => f.value === s.value)) {
                    results.interesting.push({ file: path, value: s.value, method: 'Keyword' });
                }
            }

            // 6. XOR single-byte brute force (check first 4096 bytes for performance)
            const xorLen = Math.min(bytes.length, 4096);
            for (let key = 1; key < 256; key++) {
                const xored = new Uint8Array(xorLen);
                for (let i = 0; i < xorLen; i++) xored[i] = bytes[i] ^ key;
                const xorStrs = extractStrings(xored, 4);
                for (const xs of xorStrs) {
                    for (const pattern of flagPatterns) {
                        const m = xs.value.match(pattern);
                        if (m) m.forEach(match => results.xor_flags.push({ file: path, value: match, method: `XOR key=0x${key.toString(16).padStart(2, '0')}` }));
                    }
                }
            }

            // 7. Caesar/ROT brute force on extracted strings
            for (const s of strs.slice(0, 200)) {
                for (let shift = 1; shift <= 25; shift++) {
                    const rotated = s.value.replace(/[a-zA-Z]/g, c => {
                        const base = c <= 'Z' ? 65 : 97;
                        return String.fromCharCode(((c.charCodeAt(0) - base + shift) % 26) + base);
                    });
                    for (const pattern of flagPatterns) {
                        const m = rotated.match(pattern);
                        if (m) m.forEach(match => results.caesar_flags.push({ file: path, value: match, original: s.value, method: `ROT${shift}` }));
                    }
                }
            }

            // 8. Reversed strings check
            for (const s of strs.slice(0, 200)) {
                const reversed = s.value.split('').reverse().join('');
                for (const pattern of flagPatterns) {
                    const m = reversed.match(pattern);
                    if (m) m.forEach(match => results.hidden.push({ file: path, value: match, original: s.value, method: 'Reversed string' }));
                }
            }

            // 9. Hex-encoded flag check
            for (const s of strs) {
                if (/^[0-9a-fA-F]{16,}$/.test(s.value) && s.value.length % 2 === 0) {
                    try {
                        const hexDecoded = s.value.match(/.{2}/g).map(h => String.fromCharCode(parseInt(h, 16))).join('');
                        if (/[\x20-\x7e]{4,}/.test(hexDecoded)) {
                            for (const pattern of flagPatterns) {
                                const m = hexDecoded.match(pattern);
                                if (m) m.forEach(match => results.hex_patterns.push({ file: path, value: match, original: s.value, method: 'Hex decode' }));
                            }
                        }
                    } catch (e) { }
                }
            }

        } catch (e) { }

        count++;
        if (count % 5 === 0) {
            setProgress((count / entries.length) * 100);
            showLoading('🔥 DEEP SCANNING...', `${count}/${entries.length} files • flags:${results.flags.length} xor:${results.xor_flags.length} caesar:${results.caesar_flags.length}`);
            await new Promise(r => setTimeout(r, 0));
        }
    }

    hideLoading();

    // Show results in modal
    const allFlags = [...results.flags, ...results.base64decoded_flags, ...results.xor_flags, ...results.caesar_flags, ...results.hidden, ...results.hex_patterns];
    const totalFindings = allFlags.length + results.base64.length + results.urls.length + results.secrets.length + results.interesting.length;
    $('ctfResultsTitle').textContent = `🔥 OVERPOWERED SCAN: ${allFlags.length} flags, ${totalFindings} total findings`;

    let html = '';
    const sections = [
        { title: '🚩🔥 FLAGS FOUND', items: results.flags, color: '#ef4444' },
        { title: '🔓→🚩 Base64 Decoded Flags', items: results.base64decoded_flags, color: '#f59e0b' },
        { title: '🔄→🚩 XOR Brute Force Flags', items: results.xor_flags, color: '#ec4899' },
        { title: '🔠→🚩 Caesar/ROT Flags', items: results.caesar_flags, color: '#84cc16' },
        { title: '🔀→🚩 Hidden (Reversed/Hex)', items: [...results.hidden, ...results.hex_patterns], color: '#a855f7' },
        { title: '🔓 Base64 Encoded Strings', items: results.base64.slice(0, 50), color: 'var(--accent-purple)' },
        { title: '🌐 URLs', items: results.urls.slice(0, 50), color: 'var(--accent-blue)' },
        { title: '🔑 Secrets/Keys', items: results.secrets.slice(0, 50), color: 'var(--accent-red)' },
        { title: '💡 Interesting', items: results.interesting.slice(0, 30), color: 'var(--accent-green)' },
    ];

    for (const section of sections) {
        if (section.items.length === 0) continue;
        html += `<h4 style="color:${section.color};margin:16px 0 8px;font-size:0.9rem">${section.title} (${section.items.length})</h4>`;
        for (const item of section.items.slice(0, 100)) {
            const method = item.method ? `<span style="color:var(--accent-cyan);font-size:0.65rem;background:rgba(0,212,255,0.1);padding:2px 6px;border-radius:4px;margin-left:6px">${item.method}</span>` : '';
            const decoded = item.decoded ? `<div style="color:var(--accent-green);font-size:0.72rem;margin-top:3px">→ ${escapeHtml(item.decoded)}</div>` : '';
            const original = item.original ? `<div style="color:var(--text-muted);font-size:0.68rem;margin-top:2px">from: ${escapeHtml(item.original.substring(0, 80))}</div>` : '';
            html += `<div class="ctf-result-item" onclick="selectFile('${escapeHtml(item.file)}')">
                <div class="ctf-result-file">📄 ${escapeHtml(item.file)} ${method}</div>
                <div class="ctf-result-value" style="color:${section.color}">${escapeHtml(item.value)}</div>${decoded}${original}</div>`;
        }
    }

    if (totalFindings === 0) html = '<div class="empty-state"><div class="empty-state-icon">🔍</div><div class="empty-state-text">No findings — try adding custom flag prefixes</div></div>';
    $('ctfResultsBody').innerHTML = html;
    $('ctfResultsModal').classList.remove('hidden');

    // Sidebar summary
    if (allFlags.length > 0) {
        $('ctfResults').innerHTML = `<div style="padding:8px;background:rgba(239,68,68,0.1);border-radius:6px;border:1px solid rgba(239,68,68,0.3);margin-bottom:8px">
            <div style="color:#ef4444;font-weight:700;font-size:0.82rem">🔥 ${allFlags.length} FLAG(S) FOUND!</div>
            ${allFlags.slice(0, 5).map(f => `<div style="font-family:var(--font-mono);font-size:0.72rem;color:var(--text-primary);margin-top:4px;word-break:break-all">${escapeHtml(f.value)} <span style="color:var(--accent-cyan);font-size:0.62rem">[${f.method}]</span></div>`).join('')}
            ${allFlags.length > 5 ? `<div style="color:var(--text-muted);font-size:0.65rem;margin-top:4px">... and ${allFlags.length - 5} more</div>` : ''}
        </div>`;
    }

    toast(`🔥 OP SCAN: ${allFlags.length} flags, ${totalFindings} total findings`, allFlags.length > 0 ? 'success' : 'info');
}

// ─── XOR Brute Force (standalone) ───
async function xorBruteForce() {
    if (!APP.zip) { toast('Load an APK first!', 'error'); return; }
    showLoading('🔄 XOR Brute Force scanning...');
    const results = [];
    const flagPatterns = getActiveFlags();
    const entries = Object.keys(APP.files).filter(p => !APP.files[p].dir);
    let count = 0;

    for (const path of entries) {
        try {
            const buf = await APP.zip.files[path].async('arraybuffer');
            const bytes = new Uint8Array(buf);
            const checkLen = Math.min(bytes.length, 8192);
            for (let key = 1; key < 256; key++) {
                const xored = new Uint8Array(checkLen);
                for (let i = 0; i < checkLen; i++) xored[i] = bytes[i] ^ key;
                const strs = extractStrings(xored, 4);
                for (const s of strs) {
                    for (const pattern of flagPatterns) {
                        const m = s.value.match(pattern);
                        if (m) m.forEach(match => results.push({ file: path, value: match, key: `0x${key.toString(16).padStart(2, '0')} (${key})`, offset: s.offset }));
                    }
                }
            }
        } catch (e) { }
        count++;
        if (count % 10 === 0) {
            setProgress((count / entries.length) * 100);
            showLoading('🔄 XOR scanning...', `${count}/${entries.length} files • found: ${results.length}`);
            await new Promise(r => setTimeout(r, 0));
        }
    }

    hideLoading();
    $('ctfResultsTitle').textContent = `🔄 XOR Brute Force — ${results.length} flags found`;
    let html = results.length > 0 ? results.map(r =>
        `<div class="ctf-result-item" onclick="selectFile('${escapeHtml(r.file)}')">
            <div class="ctf-result-file">📄 ${escapeHtml(r.file)}</div>
            <div class="ctf-result-value" style="color:#ec4899">${escapeHtml(r.value)}</div>
            <div style="color:var(--accent-cyan);font-size:0.72rem;margin-top:3px">XOR Key: ${r.key} • Offset: 0x${r.offset.toString(16)}</div></div>`
    ).join('') : '<div class="empty-state"><div class="empty-state-icon">🔄</div><div class="empty-state-text">No XOR-encrypted flags found</div><div class="empty-state-sub">Tried all 255 single-byte XOR keys</div></div>';
    $('ctfResultsBody').innerHTML = html;
    $('ctfResultsModal').classList.remove('hidden');
    toast(`XOR scan: ${results.length} flags found`, results.length > 0 ? 'success' : 'info');
}

// ─── Caesar/ROT Brute Force (standalone) ───
async function caesarBruteForce() {
    if (!APP.zip) { toast('Load an APK first!', 'error'); return; }
    showLoading('🔠 Caesar/ROT Brute Force scanning...');
    const results = [];
    const flagPatterns = getActiveFlags();
    const entries = Object.keys(APP.files).filter(p => !APP.files[p].dir);
    let count = 0;

    for (const path of entries) {
        try {
            const buf = await APP.zip.files[path].async('arraybuffer');
            const strs = extractStrings(new Uint8Array(buf), 4);
            for (const s of strs.slice(0, 500)) {
                for (let shift = 1; shift <= 25; shift++) {
                    const rotated = s.value.replace(/[a-zA-Z]/g, c => {
                        const base = c <= 'Z' ? 65 : 97;
                        return String.fromCharCode(((c.charCodeAt(0) - base + shift) % 26) + base);
                    });
                    for (const pattern of flagPatterns) {
                        const m = rotated.match(pattern);
                        if (m) m.forEach(match => results.push({ file: path, value: match, rotation: `ROT${shift}`, original: s.value }));
                    }
                }
            }
        } catch (e) { }
        count++;
        if (count % 20 === 0) {
            setProgress((count / entries.length) * 100);
            showLoading('🔠 Caesar scanning...', `${count}/${entries.length} files • found: ${results.length}`);
            await new Promise(r => setTimeout(r, 0));
        }
    }

    hideLoading();
    $('ctfResultsTitle').textContent = `🔠 Caesar/ROT Brute Force — ${results.length} flags found`;
    let html = results.length > 0 ? results.map(r =>
        `<div class="ctf-result-item" onclick="selectFile('${escapeHtml(r.file)}')">
            <div class="ctf-result-file">📄 ${escapeHtml(r.file)}</div>
            <div class="ctf-result-value" style="color:#84cc16">${escapeHtml(r.value)}</div>
            <div style="color:var(--accent-cyan);font-size:0.72rem;margin-top:3px">${r.rotation} • Original: ${escapeHtml(r.original.substring(0, 60))}</div></div>`
    ).join('') : '<div class="empty-state"><div class="empty-state-icon">🔠</div><div class="empty-state-text">No Caesar/ROT-encrypted flags found</div><div class="empty-state-sub">Tried all 25 rotations</div></div>';
    $('ctfResultsBody').innerHTML = html;
    $('ctfResultsModal').classList.remove('hidden');
    toast(`Caesar scan: ${results.length} flags found`, results.length > 0 ? 'success' : 'info');
}

// ─── Deep Binary Patterns ───
async function deepBinaryPatterns() {
    if (!APP.zip) { toast('Load an APK first!', 'error'); return; }
    showLoading('🧬 Deep Binary Pattern scanning...');
    const results = [];
    const flagPatterns = getActiveFlags();
    const entries = Object.keys(APP.files).filter(p => !APP.files[p].dir);
    let count = 0;

    for (const path of entries) {
        try {
            const buf = await APP.zip.files[path].async('arraybuffer');
            const bytes = new Uint8Array(buf);

            // 1. Check for reversed flag strings in raw bytes
            const strs = extractStrings(bytes, 4);
            for (const s of strs.slice(0, 300)) {
                const reversed = s.value.split('').reverse().join('');
                for (const pattern of flagPatterns) {
                    const m = reversed.match(pattern);
                    if (m) m.forEach(match => results.push({ file: path, value: match, method: 'Reversed', original: s.value }));
                }
            }

            // 2. Hex-encoded strings → decode → check for flags
            for (const s of strs) {
                if (/^[0-9a-fA-F]{16,}$/.test(s.value) && s.value.length % 2 === 0) {
                    try {
                        const hexDecoded = s.value.match(/.{2}/g).map(h => String.fromCharCode(parseInt(h, 16))).join('');
                        if (/[\x20-\x7e]{4,}/.test(hexDecoded)) {
                            for (const pattern of flagPatterns) {
                                const m = hexDecoded.match(pattern);
                                if (m) m.forEach(match => results.push({ file: path, value: match, method: 'Hex-encoded', original: s.value.substring(0, 60) }));
                            }
                            results.push({ file: path, value: hexDecoded, method: 'Hex decode (readable)' });
                        }
                    } catch (e) { }
                }
            }

            // 3. UTF-16LE extraction (null-byte interleaved ASCII)
            let utf16str = '';
            for (let i = 0; i < bytes.length - 1; i += 2) {
                if (bytes[i] >= 32 && bytes[i] < 127 && bytes[i + 1] === 0) {
                    utf16str += String.fromCharCode(bytes[i]);
                } else {
                    if (utf16str.length >= 6) {
                        for (const pattern of flagPatterns) {
                            const m = utf16str.match(pattern);
                            if (m) m.forEach(match => results.push({ file: path, value: match, method: 'UTF-16LE' }));
                        }
                    }
                    utf16str = '';
                }
            }
            if (utf16str.length >= 6) {
                for (const pattern of flagPatterns) {
                    const m = utf16str.match(pattern);
                    if (m) m.forEach(match => results.push({ file: path, value: match, method: 'UTF-16LE' }));
                }
            }

            // 4. Look for split/concatenated flag pattern like 'f'+'l'+'a'+'g'
            const fullText = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
            const concatPattern = /['"]([A-Za-z]{1,4})['"]\s*[+.]\s*['"]([A-Za-z]{1,4})['"]\s*[+.]\s*['"]([A-Za-z]{1,4})['"]/g;
            let cm;
            while ((cm = concatPattern.exec(fullText)) !== null) {
                const joined = cm[1] + cm[2] + cm[3];
                if (/(flag|ctf|key|hint)/i.test(joined)) {
                    results.push({ file: path, value: cm[0], method: 'String concatenation' });
                }
            }

        } catch (e) { }
        count++;
        if (count % 15 === 0) {
            setProgress((count / entries.length) * 100);
            showLoading('🧬 Deep scanning...', `${count}/${entries.length} files • found: ${results.length}`);
            await new Promise(r => setTimeout(r, 0));
        }
    }

    hideLoading();
    // Deduplicate
    const unique = [...new Map(results.map(r => [r.value + r.file + r.method, r])).values()];
    $('ctfResultsTitle').textContent = `🧬 Deep Binary Patterns — ${unique.length} findings`;
    let html = unique.length > 0 ? unique.slice(0, 200).map(r =>
        `<div class="ctf-result-item" onclick="selectFile('${escapeHtml(r.file)}')">
            <div class="ctf-result-file">📄 ${escapeHtml(r.file)} <span style="color:var(--accent-cyan);font-size:0.65rem;background:rgba(0,212,255,0.1);padding:2px 6px;border-radius:4px">${r.method}</span></div>
            <div class="ctf-result-value" style="color:#3b82f6">${escapeHtml(r.value)}</div>
            ${r.original ? `<div style="color:var(--text-muted);font-size:0.68rem;margin-top:2px">from: ${escapeHtml(r.original)}</div>` : ''}</div>`
    ).join('') : '<div class="empty-state"><div class="empty-state-icon">🧬</div><div class="empty-state-text">No hidden binary patterns found</div></div>';
    $('ctfResultsBody').innerHTML = html;
    $('ctfResultsModal').classList.remove('hidden');
    toast(`Deep scan: ${unique.length} findings`, unique.length > 0 ? 'success' : 'info');
}

// ─── Hidden/Obfuscated String Finder ───
async function findHiddenStrings() {
    if (!APP.zip) { toast('Load an APK first!', 'error'); return; }
    showLoading('👻 Scanning for hidden/obfuscated strings...');
    const results = [];
    const entries = Object.keys(APP.files).filter(p => !APP.files[p].dir);
    let count = 0;

    for (const path of entries) {
        try {
            const buf = await APP.zip.files[path].async('arraybuffer');
            const bytes = new Uint8Array(buf);
            const strs = extractStrings(bytes, 4);

            for (const s of strs) {
                // 1. Nested Base64 (decode Base64 → get another Base64 → decode again)
                if (/^[A-Za-z0-9+\/]{12,}={0,2}$/.test(s.value)) {
                    try {
                        const d1 = atob(s.value);
                        if (/^[A-Za-z0-9+\/]{8,}={0,2}$/.test(d1)) {
                            try {
                                const d2 = atob(d1);
                                if (/[\x20-\x7e]{4,}/.test(d2)) {
                                    results.push({ file: path, value: d2, method: 'Double Base64', chain: `${s.value.substring(0, 20)}... → ${d1.substring(0, 20)}... → ${d2}` });
                                }
                            } catch (e) { }
                        }
                    } catch (e) { }
                }

                // 2. Decimal arrays like "102 108 97 103" or "102,108,97,103"
                if (/^[\d\s,]+$/.test(s.value) && s.value.length > 10) {
                    const nums = s.value.split(/[\s,]+/).map(n => parseInt(n)).filter(n => n >= 32 && n < 127);
                    if (nums.length >= 4) {
                        const decoded = nums.map(n => String.fromCharCode(n)).join('');
                        if (/[\x20-\x7e]{4,}/.test(decoded)) {
                            results.push({ file: path, value: decoded, method: 'Decimal ASCII', original: s.value.substring(0, 50) });
                        }
                    }
                }

                // 3. Octal strings like "\\146\\154\\141\\147"
                const octalMatch = s.value.match(/(?:\\[0-7]{3}){4,}/);
                if (octalMatch) {
                    const decoded = octalMatch[0].replace(/\\([0-7]{3})/g, (_, o) => String.fromCharCode(parseInt(o, 8)));
                    if (/[\x20-\x7e]{4,}/.test(decoded)) {
                        results.push({ file: path, value: decoded, method: 'Octal encoding' });
                    }
                }

                // 4. Unicode escape like \u0066\u006c\u0061\u0067
                const unicodeMatch = s.value.match(/(?:\\u[0-9a-fA-F]{4}){4,}/);
                if (unicodeMatch) {
                    try {
                        const decoded = JSON.parse('"' + unicodeMatch[0] + '"');
                        results.push({ file: path, value: decoded, method: 'Unicode escape' });
                    } catch (e) { }
                }

                // 5. High entropy short strings (possible encrypted flags)
                if (s.value.length >= 20 && s.value.length <= 100) {
                    const entropy = calcStringEntropy(s.value);
                    if (entropy > 4.5) {
                        results.push({ file: path, value: s.value, method: `High entropy (${entropy.toFixed(2)})` });
                    }
                }
            }

        } catch (e) { }
        count++;
        if (count % 20 === 0) {
            setProgress((count / entries.length) * 100);
            showLoading('👻 Scanning hidden strings...', `${count}/${entries.length} files • found: ${results.length}`);
            await new Promise(r => setTimeout(r, 0));
        }
    }

    hideLoading();
    const unique = [...new Map(results.map(r => [r.value + r.method, r])).values()];
    $('ctfResultsTitle').textContent = `👻 Hidden/Obfuscated Strings — ${unique.length} findings`;
    let html = unique.length > 0 ? unique.slice(0, 200).map(r =>
        `<div class="ctf-result-item" onclick="selectFile('${escapeHtml(r.file)}')">
            <div class="ctf-result-file">📄 ${escapeHtml(r.file)} <span style="color:var(--accent-purple);font-size:0.65rem;background:rgba(168,85,247,0.1);padding:2px 6px;border-radius:4px">${r.method}</span></div>
            <div class="ctf-result-value" style="color:#a855f7">${escapeHtml(r.value)}</div>
            ${r.original ? `<div style="color:var(--text-muted);font-size:0.68rem;margin-top:2px">from: ${escapeHtml(r.original)}</div>` : ''}
            ${r.chain ? `<div style="color:var(--accent-green);font-size:0.68rem;margin-top:2px">${escapeHtml(r.chain)}</div>` : ''}</div>`
    ).join('') : '<div class="empty-state"><div class="empty-state-icon">👻</div><div class="empty-state-text">No hidden strings found</div></div>';
    $('ctfResultsBody').innerHTML = html;
    $('ctfResultsModal').classList.remove('hidden');
    toast(`Hidden strings: ${unique.length} findings`, unique.length > 0 ? 'success' : 'info');
}

function calcStringEntropy(str) {
    const freq = {};
    for (const c of str) freq[c] = (freq[c] || 0) + 1;
    let entropy = 0;
    for (const c in freq) {
        const p = freq[c] / str.length;
        entropy -= p * Math.log2(p);
    }
    return entropy;
}

// ═══════════════════════════════════════════════════════
// 🔬 ADVANCED RE ANALYSIS
// ═══════════════════════════════════════════════════════

// ─── 🔐 Credential Finder ───
async function credentialFinder() {
    if (!APP.zip) { toast('Load an APK first!', 'error'); return; }
    showLoading('🔐 Scanning for credentials...');
    const results = { creds: [], emails: [], hardcoded: [], connStrings: [], jwt: [], personal: [] };
    const entries = Object.keys(APP.files).filter(p => !APP.files[p].dir);
    let count = 0;

    const credPatterns = [
        { regex: /(?:password|passwd|pwd)\s*[=:]\s*["']?([^\s"'<>]+)/gi, type: 'Password' },
        { regex: /(?:username|user|login|uname)\s*[=:]\s*["']?([^\s"'<>]+)/gi, type: 'Username' },
        { regex: /(?:api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*["']?([^\s"'<>]+)/gi, type: 'API Key' },
        { regex: /(?:token|auth[_-]?token|access[_-]?token|bearer)\s*[=:]\s*["']?([^\s"'<>]+)/gi, type: 'Token' },
        { regex: /(?:secret|private[_-]?key|signing[_-]?key)\s*[=:]\s*["']?([^\s"'<>]+)/gi, type: 'Secret' },
        { regex: /(?:db[_-]?pass|database[_-]?password|mysql[_-]?pass|mongo[_-]?pass)\s*[=:]\s*["']?([^\s"'<>]+)/gi, type: 'DB Password' },
    ];
    const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
    const jwtRegex = /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+/g;
    const connRegex = /(?:jdbc|mongodb|mysql|postgres|redis|sqlite):\/\/[^\s"'<>]+/gi;
    const hardcodedRegex = /["'](?:admin|root|test|default|guest|password|123456|pass123|letmein)['"]/gi;

    for (const path of entries) {
        try {
            const buf = await APP.zip.files[path].async('arraybuffer');
            const bytes = new Uint8Array(buf);
            const strs = extractStrings(bytes, 4);
            const fullText = strs.map(s => s.value).join('\n');

            // Credential patterns
            for (const cp of credPatterns) {
                cp.regex.lastIndex = 0;
                let m;
                while ((m = cp.regex.exec(fullText)) !== null) {
                    results.creds.push({ file: path, value: m[0], type: cp.type });
                }
            }

            // Emails
            let em;
            const emailStr = fullText;
            const emailRe = new RegExp(emailRegex.source, 'g');
            while ((em = emailRe.exec(emailStr)) !== null) {
                if (!em[0].includes('schemas.android.com') && !em[0].includes('apache.org') && !em[0].includes('w3.org') && !em[0].includes('google.com/schemas') && !em[0].endsWith('.png') && !em[0].endsWith('.xml')) {
                    results.emails.push({ file: path, value: em[0] });
                }
            }

            // JWT tokens
            let jm;
            const jwtRe = new RegExp(jwtRegex.source, 'g');
            while ((jm = jwtRe.exec(fullText)) !== null) {
                let payload = '';
                try {
                    const parts = jm[0].split('.');
                    payload = atob(parts[1].replace(/-/g, '+').replace(/_/g, '/'));
                } catch (e) { }
                results.jwt.push({ file: path, value: jm[0].substring(0, 80) + '...', decoded: payload });
            }

            // Connection strings
            let cm;
            const connRe = new RegExp(connRegex.source, 'gi');
            while ((cm = connRe.exec(fullText)) !== null) {
                results.connStrings.push({ file: path, value: cm[0] });
            }

            // Hardcoded common passwords
            let hm;
            const hardRe = new RegExp(hardcodedRegex.source, 'gi');
            while ((hm = hardRe.exec(fullText)) !== null) {
                results.hardcoded.push({ file: path, value: hm[0] });
            }

            // Personal info patterns (for credential-based CTFs)
            for (const s of strs) {
                if (/\b\d{2}[\/\-]\d{2}[\/\-]\d{4}\b/.test(s.value)) results.personal.push({ file: path, value: s.value, type: 'Date' });
                if (/\$\d+\.\d{2}/.test(s.value)) results.personal.push({ file: path, value: s.value, type: 'Money' });
                if (/\b(?:alex|johnson|tricky|blue)\b/i.test(s.value)) results.personal.push({ file: path, value: s.value, type: 'Personal info match' });
            }

        } catch (e) { }
        count++;
        if (count % 20 === 0) {
            setProgress((count / entries.length) * 100);
            showLoading('🔐 Scanning...', `${count}/${entries.length} files`);
            await new Promise(r => setTimeout(r, 0));
        }
    }

    hideLoading();
    const total = results.creds.length + results.emails.length + results.hardcoded.length + results.connStrings.length + results.jwt.length + results.personal.length;
    $('ctfResultsTitle').textContent = `🔐 Credential Finder — ${total} findings`;

    let html = '';
    const sections = [
        { title: '🔐 Credentials (user/pass patterns)', items: results.creds, color: '#ef4444' },
        { title: '📧 Email Addresses', items: [...new Map(results.emails.map(e => [e.value, e])).values()], color: '#3b82f6' },
        { title: '🔑 JWT Tokens', items: results.jwt, color: '#f59e0b' },
        { title: '🔗 Connection Strings', items: results.connStrings, color: '#10b981' },
        { title: '⚠️ Hardcoded Common Passwords', items: results.hardcoded, color: '#ec4899' },
        { title: '👤 Personal Info Matches', items: results.personal, color: '#a855f7' },
    ];

    for (const section of sections) {
        if (section.items.length === 0) continue;
        html += `<h4 style="color:${section.color};margin:16px 0 8px;font-size:0.9rem">${section.title} (${section.items.length})</h4>`;
        for (const item of section.items.slice(0, 100)) {
            const typeTag = item.type ? `<span style="color:var(--accent-cyan);font-size:0.62rem;background:rgba(0,212,255,0.1);padding:2px 6px;border-radius:4px;margin-left:6px">${item.type}</span>` : '';
            const decoded = item.decoded ? `<div style="color:var(--accent-green);font-size:0.72rem;margin-top:3px;word-break:break-all">→ ${escapeHtml(item.decoded)}</div>` : '';
            html += `<div class="ctf-result-item" onclick="selectFile('${escapeHtml(item.file)}')">
                <div class="ctf-result-file">📄 ${escapeHtml(item.file)} ${typeTag}</div>
                <div class="ctf-result-value" style="color:${section.color}">${escapeHtml(item.value)}</div>${decoded}</div>`;
        }
    }

    if (total === 0) html = '<div class="empty-state"><div class="empty-state-icon">🔐</div><div class="empty-state-text">No credentials found</div></div>';
    $('ctfResultsBody').innerHTML = html;
    $('ctfResultsModal').classList.remove('hidden');
    toast(`Credentials: ${total} findings`, total > 0 ? 'success' : 'info');
}

// ─── 📱 Activity Analyzer ───
async function activityAnalyzer() {
    if (!APP.zip) { toast('Load an APK first!', 'error'); return; }
    showLoading('📱 Analyzing Activities & Components...');

    const results = { activities: [], services: [], receivers: [], providers: [], exported: [], intents: [], suspicious: [] };

    // Parse all strings from manifest
    try {
        const manifestEntry = APP.zip.files['AndroidManifest.xml'];
        if (manifestEntry) {
            const buf = await manifestEntry.async('arraybuffer');
            const bytes = new Uint8Array(buf);
            const strs = extractBinaryXmlStrings(bytes);

            for (const s of strs) {
                // Activities
                if (/Activity$/i.test(s) || /\.activity\./i.test(s)) results.activities.push(s);
                // Services
                if (/Service$/i.test(s) || /\.service\./i.test(s)) results.services.push(s);
                // Receivers
                if (/Receiver$/i.test(s) || /\.receiver\./i.test(s)) results.receivers.push(s);
                // Providers
                if (/Provider$/i.test(s) || /\.provider\./i.test(s)) results.providers.push(s);
                // Intent actions/categories
                if (/^android\.intent\./i.test(s) || /^android\.action\./i.test(s)) results.intents.push(s);
                // Suspicious names
                if (/(flag|secret|hidden|debug|test|admin|backdoor|hack|cheat|bypass|exploit|root|decrypt|crack|vulnerability)/i.test(s) && s.length > 5) {
                    results.suspicious.push(s);
                }
                // Look for exported="true" pattern
                if (/exported/i.test(s) || /true/i.test(s)) {
                    // We just note this — binary XML makes it hard to match attributes
                }
            }
        }
    } catch (e) { }

    // Also scan DEX files for class names
    const entries = Object.keys(APP.files).filter(p => p.endsWith('.dex'));
    for (const path of entries) {
        try {
            const buf = await APP.zip.files[path].async('arraybuffer');
            const bytes = new Uint8Array(buf);
            const strs = extractStrings(bytes, 6);

            for (const s of strs) {
                if (/Activity;?$/.test(s.value) && /^L/.test(s.value)) results.activities.push(s.value);
                if (/Service;?$/.test(s.value) && /^L/.test(s.value)) results.services.push(s.value);
                if (/(flag|secret|hidden|debug|test|admin|backdoor|decrypt|verify|check|validate|login|auth|credential)/i.test(s.value) && /^L/.test(s.value)) {
                    results.suspicious.push(s.value);
                }
            }
        } catch (e) { }
    }

    // Also check for smali files if decompiled
    const smaliFiles = Object.keys(APP.files).filter(p => p.endsWith('.smali'));
    for (const path of smaliFiles) {
        const name = path.split('/').pop().replace('.smali', '');
        if (/(activity|flag|secret|login|auth|main|debug|admin)/i.test(name)) {
            results.suspicious.push(`📄 ${path}`);
        }
    }

    hideLoading();

    // Deduplicate
    const dedup = arr => [...new Set(arr)];
    results.activities = dedup(results.activities);
    results.services = dedup(results.services);
    results.receivers = dedup(results.receivers);
    results.providers = dedup(results.providers);
    results.intents = dedup(results.intents);
    results.suspicious = dedup(results.suspicious);

    const total = results.activities.length + results.services.length + results.receivers.length + results.providers.length + results.suspicious.length;
    $('ctfResultsTitle').textContent = `📱 Activity & Component Analysis — ${total} components`;

    let html = '';
    const sections = [
        { title: '⚠️ Suspicious/Interesting', items: results.suspicious, color: '#ef4444', icon: '🚨' },
        { title: '📱 Activities', items: results.activities, color: '#3b82f6', icon: '📱' },
        { title: '⚙️ Services', items: results.services, color: '#10b981', icon: '⚙️' },
        { title: '📡 Receivers', items: results.receivers, color: '#f59e0b', icon: '📡' },
        { title: '💾 Providers', items: results.providers, color: '#a855f7', icon: '💾' },
        { title: '🔗 Intent Actions', items: results.intents, color: 'var(--text-secondary)', icon: '🔗' },
    ];

    for (const section of sections) {
        if (section.items.length === 0) continue;
        html += `<h4 style="color:${section.color};margin:16px 0 8px;font-size:0.9rem">${section.title} (${section.items.length})</h4>`;
        for (const item of section.items) {
            const isSuspicious = /(flag|secret|hidden|debug|admin|backdoor|decrypt|hack)/i.test(item);
            html += `<div class="ctf-result-item" style="${isSuspicious ? 'border-left:3px solid #ef4444' : ''}">
                <div class="ctf-result-value" style="color:${isSuspicious ? '#ef4444' : section.color};font-family:var(--font-mono);font-size:0.78rem">${section.icon} ${escapeHtml(item)}</div></div>`;
        }
    }

    if (total === 0) html = '<div class="empty-state"><div class="empty-state-icon">📱</div><div class="empty-state-text">No components found in manifest</div></div>';
    $('ctfResultsBody').innerHTML = html;
    $('ctfResultsModal').classList.remove('hidden');
    toast(`Components: ${total} found, ${results.suspicious.length} suspicious`, results.suspicious.length > 0 ? 'success' : 'info');
}

// ─── 💾 Database/Config Viewer ───
async function databaseConfigViewer() {
    if (!APP.zip) { toast('Load an APK first!', 'error'); return; }
    showLoading('💾 Scanning for databases & config files...');

    const dbExtensions = ['.db', '.sqlite', '.sqlite3', '.realm'];
    const configExtensions = ['.json', '.yml', '.yaml', '.properties', '.cfg', '.ini', '.conf', '.toml'];
    const prefPatterns = ['shared_prefs', 'SharedPreferences', 'preferences'];
    const results = { databases: [], configs: [], prefs: [], interesting: [] };
    const entries = Object.keys(APP.files).filter(p => !APP.files[p].dir);
    let count = 0;

    for (const path of entries) {
        const lower = path.toLowerCase();
        const name = path.split('/').pop().toLowerCase();

        // Database files
        if (dbExtensions.some(ext => lower.endsWith(ext))) {
            try {
                const buf = await APP.zip.files[path].async('arraybuffer');
                const bytes = new Uint8Array(buf);
                const strs = extractStrings(bytes, 4);
                const tables = strs.filter(s => /^CREATE\s+TABLE/i.test(s.value) || /^INSERT\s+INTO/i.test(s.value));
                const allStrs = strs.filter(s => s.value.length > 3);
                results.databases.push({ file: path, size: APP.files[path]?.size || bytes.length, tables, strings: allStrs.slice(0, 100) });
            } catch (e) {
                results.databases.push({ file: path, size: APP.files[path]?.size || 0, tables: [], strings: [] });
            }
        }

        // Config files
        if (configExtensions.some(ext => lower.endsWith(ext))) {
            try {
                const buf = await APP.zip.files[path].async('arraybuffer');
                const text = new TextDecoder('utf-8', { fatal: false }).decode(new Uint8Array(buf));
                if (text.length > 0 && text.length < 50000) {
                    const isInteresting = /(password|secret|key|token|flag|admin|auth|credential|api|firebase|aws|endpoint|server|host|database|mongo|redis|mysql)/i.test(text);
                    results.configs.push({ file: path, content: text.substring(0, 2000), interesting: isInteresting });
                }
            } catch (e) { }
        }

        // SharedPreferences XML
        if (lower.endsWith('.xml') && (prefPatterns.some(p => lower.includes(p.toLowerCase())) || lower.includes('pref'))) {
            try {
                const buf = await APP.zip.files[path].async('arraybuffer');
                const text = new TextDecoder('utf-8', { fatal: false }).decode(new Uint8Array(buf));
                results.prefs.push({ file: path, content: text.substring(0, 2000) });
            } catch (e) { }
        }

        // Interesting files (unusual extensions or names)
        if (/(secret|flag|hidden|debug|password|credential|token|backup|dump|leak)/i.test(name) && !lower.endsWith('.class') && !lower.endsWith('.dex')) {
            try {
                const buf = await APP.zip.files[path].async('arraybuffer');
                const bytes = new Uint8Array(buf);
                const strs = extractStrings(bytes, 4);
                results.interesting.push({ file: path, size: APP.files[path]?.size || bytes.length, strings: strs.slice(0, 50) });
            } catch (e) {
                results.interesting.push({ file: path, size: 0, strings: [] });
            }
        }

        // Also check assets/ for any text/config-like files
        if (path.startsWith('assets/') && !lower.endsWith('.png') && !lower.endsWith('.jpg') && !lower.endsWith('.mp3') && !lower.endsWith('.ogg') && !lower.endsWith('.wav') && !lower.endsWith('.ttf') && !lower.endsWith('.otf')) {
            if (!dbExtensions.some(ext => lower.endsWith(ext)) && !configExtensions.some(ext => lower.endsWith(ext))) {
                try {
                    const buf = await APP.zip.files[path].async('arraybuffer');
                    const bytes = new Uint8Array(buf);
                    if (bytes.length < 100000) {
                        const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
                        if (/[\x20-\x7e]{10,}/.test(text) && /(password|flag|secret|key|token|admin|login|auth|cred)/i.test(text)) {
                            results.configs.push({ file: path, content: text.substring(0, 2000), interesting: true });
                        }
                    }
                } catch (e) { }
            }
        }

        count++;
        if (count % 30 === 0) {
            setProgress((count / entries.length) * 100);
            showLoading('💾 Scanning...', `${count}/${entries.length} files`);
            await new Promise(r => setTimeout(r, 0));
        }
    }

    hideLoading();
    const total = results.databases.length + results.configs.length + results.prefs.length + results.interesting.length;
    $('ctfResultsTitle').textContent = `💾 Database & Config Files — ${total} found`;

    let html = '';

    // Interesting files first
    if (results.interesting.length > 0) {
        html += `<h4 style="color:#ef4444;margin:16px 0 8px;font-size:0.9rem">🚨 Interesting Files (${results.interesting.length})</h4>`;
        for (const item of results.interesting) {
            html += `<div class="ctf-result-item" onclick="selectFile('${escapeHtml(item.file)}')">
                <div class="ctf-result-file" style="color:#ef4444">🚨 ${escapeHtml(item.file)} (${formatSize(item.size)})</div>`;
            if (item.strings.length > 0) {
                html += `<div style="color:var(--text-secondary);font-size:0.72rem;margin-top:4px;font-family:var(--font-mono)">${item.strings.slice(0, 10).map(s => escapeHtml(s.value)).join('<br>')}</div>`;
            }
            html += '</div>';
        }
    }

    // Databases
    if (results.databases.length > 0) {
        html += `<h4 style="color:#f59e0b;margin:16px 0 8px;font-size:0.9rem">💾 Database Files (${results.databases.length})</h4>`;
        for (const db of results.databases) {
            html += `<div class="ctf-result-item" onclick="selectFile('${escapeHtml(db.file)}')">
                <div class="ctf-result-file" style="color:#f59e0b">💾 ${escapeHtml(db.file)} (${formatSize(db.size)})</div>`;
            if (db.tables.length > 0) {
                html += `<div style="color:var(--accent-green);font-size:0.72rem;margin-top:4px"><strong>SQL Tables/Inserts:</strong><br>${db.tables.slice(0, 10).map(t => `<code style="color:var(--accent-cyan)">${escapeHtml(t.value.substring(0, 120))}</code>`).join('<br>')}</div>`;
            }
            if (db.strings.length > 0) {
                html += `<div style="color:var(--text-secondary);font-size:0.72rem;margin-top:4px;font-family:var(--font-mono)"><strong>Readable Strings:</strong><br>${db.strings.slice(0, 20).map(s => escapeHtml(s.value)).join('<br>')}</div>`;
            }
            html += '</div>';
        }
    }

    // Configs
    const interestingConfigs = results.configs.filter(c => c.interesting);
    const normalConfigs = results.configs.filter(c => !c.interesting);
    if (interestingConfigs.length > 0) {
        html += `<h4 style="color:#ef4444;margin:16px 0 8px;font-size:0.9rem">⚠️ Interesting Config Files (${interestingConfigs.length})</h4>`;
        for (const cfg of interestingConfigs) {
            html += `<div class="ctf-result-item" onclick="selectFile('${escapeHtml(cfg.file)}')">
                <div class="ctf-result-file" style="color:#ef4444">⚠️ ${escapeHtml(cfg.file)}</div>
                <pre style="color:var(--text-secondary);font-size:0.68rem;margin-top:4px;max-height:150px;overflow:auto;white-space:pre-wrap;word-break:break-all">${escapeHtml(cfg.content.substring(0, 500))}</pre></div>`;
        }
    }
    if (normalConfigs.length > 0) {
        html += `<h4 style="color:#10b981;margin:16px 0 8px;font-size:0.9rem">📋 Config Files (${normalConfigs.length})</h4>`;
        for (const cfg of normalConfigs.slice(0, 20)) {
            html += `<div class="ctf-result-item" onclick="selectFile('${escapeHtml(cfg.file)}')">
                <div class="ctf-result-file">📋 ${escapeHtml(cfg.file)}</div></div>`;
        }
    }

    // SharedPreferences
    if (results.prefs.length > 0) {
        html += `<h4 style="color:#a855f7;margin:16px 0 8px;font-size:0.9rem">📝 SharedPreferences (${results.prefs.length})</h4>`;
        for (const pref of results.prefs) {
            html += `<div class="ctf-result-item" onclick="selectFile('${escapeHtml(pref.file)}')">
                <div class="ctf-result-file" style="color:#a855f7">📝 ${escapeHtml(pref.file)}</div>
                <pre style="color:var(--text-secondary);font-size:0.68rem;margin-top:4px;max-height:120px;overflow:auto;white-space:pre-wrap">${escapeHtml(pref.content.substring(0, 400))}</pre></div>`;
        }
    }

    if (total === 0) html = '<div class="empty-state"><div class="empty-state-icon">💾</div><div class="empty-state-text">No databases or config files found</div></div>';
    $('ctfResultsBody').innerHTML = html;
    $('ctfResultsModal').classList.remove('hidden');
    toast(`DB/Config: ${total} found`, total > 0 ? 'success' : 'info');
}

// ─── 🔗 Smali Method Tracer ───
async function smaliMethodTracer() {
    if (!APP.zip) { toast('Load an APK first!', 'error'); return; }
    showLoading('🔗 Tracing security-relevant methods...');

    const results = { auth: [], crypto: [], flag: [], network: [], reflection: [], native: [], interesting: [] };
    const entries = Object.keys(APP.files).filter(p => !APP.files[p].dir);
    let count = 0;

    // Method categories to search for
    const methodPatterns = {
        auth: /(?:login|authenticate|verify|validate|checkPassword|checkPin|checkCredential|isValid|isAuthenticated|onLogin|doLogin|signIn|authorize)/i,
        crypto: /(?:encrypt|decrypt|cipher|aes|des|rsa|md5|sha1|sha256|hash|digest|hmac|pbkdf|bcrypt|scrypt|SecretKey|IvParameterSpec|KeyGenerator|Cipher\.getInstance)/i,
        flag: /(?:getFlag|showFlag|printFlag|displayFlag|flag|setFlag|checkFlag|revealFlag|submitFlag|secret|getSecret)/i,
        network: /(?:HttpURLConnection|OkHttp|Retrofit|HTTPClient|sendRequest|postData|getData|fetchUrl|connectToServer|api\/|endpoint)/i,
        reflection: /(?:Method\.invoke|Class\.forName|getDeclaredMethod|getDeclaredField|setAccessible|getMethod|newInstance|loadClass)/i,
        native: /(?:System\.loadLibrary|System\.load|native |JNI_OnLoad|nativeMethod|loadNativeLibrary)/i,
    };

    for (const path of entries) {
        try {
            const buf = await APP.zip.files[path].async('arraybuffer');
            const bytes = new Uint8Array(buf);
            const strs = extractStrings(bytes, 6);
            const isSmali = path.endsWith('.smali');
            const isDex = path.endsWith('.dex');

            if (!isSmali && !isDex) {
                count++;
                continue;
            }

            if (isSmali) {
                // Parse smali file for method declarations
                const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
                const lines = text.split('\n');
                let currentClass = path;
                let currentMethod = null;
                let methodBody = [];

                for (const line of lines) {
                    const classMatch = line.match(/^\.class\s+.*\s+(L[\w\/\$]+;)/);
                    if (classMatch) currentClass = classMatch[1];

                    const methodMatch = line.match(/^\.method\s+(.*)/);
                    if (methodMatch) {
                        currentMethod = methodMatch[1];
                        methodBody = [];
                    }
                    if (currentMethod) methodBody.push(line);

                    if (line.trim() === '.end method' && currentMethod) {
                        const fullMethod = `${currentClass} → ${currentMethod}`;
                        const bodyText = methodBody.join('\n');

                        for (const [cat, pattern] of Object.entries(methodPatterns)) {
                            if (pattern.test(currentMethod) || pattern.test(bodyText)) {
                                results[cat].push({
                                    file: path,
                                    class: currentClass,
                                    method: currentMethod,
                                    bodyPreview: bodyText.substring(0, 300),
                                    category: cat
                                });
                            }
                        }

                        // Check for interesting method body content
                        if (/(const-string.*flag|const-string.*secret|const-string.*password|const-string.*key)/i.test(bodyText)) {
                            results.interesting.push({
                                file: path,
                                class: currentClass,
                                method: currentMethod,
                                bodyPreview: bodyText.substring(0, 300),
                                category: 'hardcoded string'
                            });
                        }

                        currentMethod = null;
                        methodBody = [];
                    }
                }
            }

            if (isDex) {
                // Extract class/method names from DEX strings
                for (const s of strs) {
                    for (const [cat, pattern] of Object.entries(methodPatterns)) {
                        if (pattern.test(s.value) && s.value.length < 200) {
                            results[cat].push({
                                file: path,
                                class: 'DEX',
                                method: s.value,
                                bodyPreview: '',
                                category: cat
                            });
                        }
                    }
                }
            }

        } catch (e) { }
        count++;
        if (count % 15 === 0) {
            setProgress((count / entries.length) * 100);
            showLoading('🔗 Tracing methods...', `${count}/${entries.length} files`);
            await new Promise(r => setTimeout(r, 0));
        }
    }

    hideLoading();
    const total = Object.values(results).reduce((sum, arr) => sum + arr.length, 0);
    $('ctfResultsTitle').textContent = `🔗 Smali Method Tracer — ${total} methods found`;

    let html = '';
    const sections = [
        { title: '🚩 Flag/Secret Methods', items: results.flag, color: '#ef4444' },
        { title: '🔐 Auth/Login Methods', items: results.auth, color: '#f59e0b' },
        { title: '🔒 Crypto Methods', items: results.crypto, color: '#a855f7' },
        { title: '⭐ Interesting (Hardcoded Strings)', items: results.interesting, color: '#ec4899' },
        { title: '🌐 Network Methods', items: results.network, color: '#3b82f6' },
        { title: '🪞 Reflection', items: results.reflection, color: '#10b981' },
        { title: '⚙️ Native/JNI', items: results.native, color: '#84cc16' },
    ];

    for (const section of sections) {
        if (section.items.length === 0) continue;
        // Deduplicate
        const unique = [...new Map(section.items.map(i => [i.class + i.method, i])).values()];
        html += `<h4 style="color:${section.color};margin:16px 0 8px;font-size:0.9rem">${section.title} (${unique.length})</h4>`;
        for (const item of unique.slice(0, 60)) {
            html += `<div class="ctf-result-item" onclick="selectFile('${escapeHtml(item.file)}')">
                <div class="ctf-result-file">📄 ${escapeHtml(item.file)}</div>
                <div style="color:var(--accent-cyan);font-size:0.72rem;font-family:var(--font-mono)">${escapeHtml(item.class)}</div>
                <div class="ctf-result-value" style="color:${section.color};font-family:var(--font-mono);font-size:0.76rem">${escapeHtml(item.method)}</div>
                ${item.bodyPreview ? `<details style="margin-top:4px"><summary style="color:var(--text-muted);font-size:0.68rem;cursor:pointer">Show method body</summary><pre style="color:var(--text-secondary);font-size:0.65rem;margin-top:4px;max-height:120px;overflow:auto;white-space:pre-wrap">${escapeHtml(item.bodyPreview)}</pre></details>` : ''}</div>`;
        }
    }

    if (total === 0) html = '<div class="empty-state"><div class="empty-state-icon">🔗</div><div class="empty-state-text">No security-relevant methods found</div><div class="empty-state-sub">Try loading an APK with smali or DEX files</div></div>';
    $('ctfResultsBody').innerHTML = html;
    $('ctfResultsModal').classList.remove('hidden');
    toast(`Methods: ${total} found`, total > 0 ? 'success' : 'info');
}

// ─── Wire Up OP Buttons ───
document.addEventListener('DOMContentLoaded', () => {
    // Global Search
    $('btnGlobalSearch')?.addEventListener('click', () => globalSearchAll($('globalSearch').value));
    $('globalSearch')?.addEventListener('keydown', e => { if (e.key === 'Enter') globalSearchAll($('globalSearch').value); });
    // THE BIG BUTTON
    $('btnFindFlagNow')?.addEventListener('click', findFlagNow);
    // Individual OP scanners
    $('btnXorBrute')?.addEventListener('click', xorBruteForce);
    $('btnCaesarBrute')?.addEventListener('click', caesarBruteForce);
    $('btnDeepBinary')?.addEventListener('click', deepBinaryPatterns);
    $('btnHiddenStrings')?.addEventListener('click', findHiddenStrings);
    // Advanced RE Analysis
    $('btnCredentialFinder')?.addEventListener('click', credentialFinder);
    $('btnActivityAnalyzer')?.addEventListener('click', activityAnalyzer);
    $('btnDatabaseViewer')?.addEventListener('click', databaseConfigViewer);
    $('btnSmaliTracer')?.addEventListener('click', smaliMethodTracer);
});
