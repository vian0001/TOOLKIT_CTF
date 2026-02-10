/**
 * SharkLens — App Logic
 * UI rendering, filtering, charts, hex viewer, CSV export
 */

(function () {
    'use strict';

    // State
    let allPackets = [];
    let filteredPackets = [];
    let selectedPacketIndex = -1;
    let activeProtocolFilter = null;
    let parseResult = null;

    // DOM refs
    const $ = (sel) => document.querySelector(sel);
    const $$ = (sel) => document.querySelectorAll(sel);

    const dropZone = $('#dropZone');
    const fileInput = $('#fileInput');
    const btnOpen = $('#btnOpen');
    const btnExport = $('#btnExport');
    const loadingState = $('#loadingState');
    const loadingText = $('#loadingText');
    const fileError = $('#fileError');
    const dashboard = $('#dashboard');
    const fileInfo = $('#fileInfo');
    const fileName = $('#fileName');
    const fileMeta = $('#fileMeta');
    const searchInput = $('#searchInput');
    const protocolChips = $('#protocolChips');
    const filterCount = $('#filterCount');
    const btnClearFilter = $('#btnClearFilter');
    const packetTable = $('#packetTable');
    const detailPanel = $('#detailPanel');
    const detailHeaders = $('#detailHeaders');
    const hexViewer = $('#hexViewer');
    const btnCloseDetail = $('#btnCloseDetail');

    // ============================================
    // FILE HANDLING
    // ============================================
    btnOpen.addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) handleFile(e.target.files[0]);
    });

    // Drag & Drop
    dropZone.addEventListener('click', () => fileInput.click());
    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('drag-over');
    });
    dropZone.addEventListener('dragleave', () => {
        dropZone.classList.remove('drag-over');
    });
    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.classList.remove('drag-over');
        if (e.dataTransfer.files.length > 0) handleFile(e.dataTransfer.files[0]);
    });

    // Prevent default drag behavior on body
    document.body.addEventListener('dragover', (e) => e.preventDefault());
    document.body.addEventListener('drop', (e) => e.preventDefault());

    function handleFile(file) {
        dropZone.style.display = 'none';
        loadingState.style.display = 'flex';
        dashboard.style.display = 'none';
        if (fileError) fileError.style.display = 'none';
        loadingText.textContent = `Reading ${file.name}...`;

        const reader = new FileReader();
        reader.onload = function (e) {
            loadingText.textContent = 'Parsing packets...';
            // Use setTimeout to allow UI to update
            setTimeout(() => {
                try {
                    const parser = new PcapParser();
                    const startTime = performance.now();
                    parseResult = parser.parse(e.target.result);
                    const elapsed = (performance.now() - startTime).toFixed(0);

                    allPackets = parseResult.packets;
                    filteredPackets = allPackets;

                    loadingState.style.display = 'none';
                    dashboard.style.display = 'block';
                    fileInfo.style.display = 'flex';
                    btnExport.style.display = 'inline-flex';

                    fileName.textContent = file.name;
                    fileMeta.textContent = `${parseResult.totalPackets.toLocaleString()} packets • Parsed in ${elapsed}ms`;

                    renderDashboard();
                } catch (err) {
                    loadingState.style.display = 'none';
                    dropZone.style.display = 'flex';
                    if (fileError) {
                        fileError.innerHTML = `<strong>Error parsing file:</strong> ${err.message}<br><span style="font-size:11px;opacity:0.8;font-family:monospace">${err.stack ? err.stack.split('\n')[0] : ''}</span>`;
                        fileError.style.display = 'block';
                    } else {
                        alert(`Error parsing file: ${err.message}`);
                    }
                    console.error(err);
                }
            }, 50);
        };
        reader.onerror = () => {
            loadingState.style.display = 'none';
            dropZone.style.display = 'flex';
            alert('Error reading file');
        };
        reader.readAsArrayBuffer(file);
    }

    // ============================================
    // DASHBOARD RENDERING
    // ============================================
    function renderDashboard() {
        updateStats();
        renderProtocolChips();
        renderProtocolChart();
        renderConversationChart();
        renderAlerts();
        renderPacketTable();
    }

    function updateStats() {
        // Total packets
        $('#statTotalPackets').textContent = filteredPackets.length.toLocaleString();

        // File size
        if (parseResult) {
            $('#statFileSize').textContent = formatBytes(parseResult.fileSize);
        }

        // Duration
        if (filteredPackets.length > 1) {
            const duration = filteredPackets[filteredPackets.length - 1].relativeTime;
            $('#statDuration').textContent = formatDuration(duration);
        } else {
            $('#statDuration').textContent = '0s';
        }

        // Unique protocols
        const protocols = new Set(filteredPackets.map(p => p.protocol));
        $('#statProtocols').textContent = protocols.size;

        // Unique IPs
        const ips = new Set();
        filteredPackets.forEach(p => {
            if (p.ipSrc) ips.add(p.ipSrc);
            if (p.ipDst) ips.add(p.ipDst);
        });
        $('#statUniqueIPs').textContent = ips.size;
    }

    // ============================================
    // PROTOCOL CHIPS
    // ============================================
    function renderProtocolChips() {
        const protoCounts = {};
        allPackets.forEach(p => {
            const proto = getProtoGroup(p.protocol);
            protoCounts[proto] = (protoCounts[proto] || 0) + 1;
        });

        // Sort by count desc
        const sorted = Object.entries(protoCounts).sort((a, b) => b[1] - a[1]);

        protocolChips.innerHTML = sorted.map(([proto, count]) => {
            const chipClass = `chip-${proto.toLowerCase().replace(/[^a-z]/g, '')}`;
            const isKnown = ['tcp', 'udp', 'http', 'https', 'dns', 'icmp', 'arp', 'tls'].includes(proto.toLowerCase());
            return `<button class="chip ${isKnown ? 'chip-' + proto.toLowerCase() : 'chip-other'}" data-proto="${proto}">
                ${proto} <span class="chip-count">${count}</span>
            </button>`;
        }).join('');

        // Chip click handlers
        protocolChips.querySelectorAll('.chip').forEach(chip => {
            chip.addEventListener('click', () => {
                const proto = chip.dataset.proto;
                if (activeProtocolFilter === proto) {
                    activeProtocolFilter = null;
                    chip.classList.remove('active');
                } else {
                    protocolChips.querySelectorAll('.chip').forEach(c => c.classList.remove('active'));
                    activeProtocolFilter = proto;
                    chip.classList.add('active');
                }
                applyFilters();
            });
        });
    }

    function getProtoGroup(protocol) {
        const p = protocol.toUpperCase();
        if (p === 'TCP') return 'TCP';
        if (p === 'UDP') return 'UDP';
        if (p === 'HTTP') return 'HTTP';
        if (p === 'TLS' || p === 'HTTPS') return 'TLS';
        if (p === 'DNS' || p === 'MDNS') return 'DNS';
        if (p === 'ICMP') return 'ICMP';
        if (p === 'ARP') return 'ARP';
        if (p === 'DHCP') return 'DHCP';
        if (p === 'SSDP') return 'SSDP';
        return p;
    }

    // ============================================
    // FILTERING
    // ============================================
    searchInput.addEventListener('input', debounce(applyFilters, 200));
    btnClearFilter.addEventListener('click', () => {
        searchInput.value = '';
        activeProtocolFilter = null;
        protocolChips.querySelectorAll('.chip').forEach(c => c.classList.remove('active'));
        applyFilters();
    });

    function applyFilters() {
        const query = searchInput.value.trim().toLowerCase();
        filteredPackets = allPackets.filter(p => {
            // Protocol filter
            if (activeProtocolFilter) {
                if (getProtoGroup(p.protocol) !== activeProtocolFilter) return false;
            }

            // Text filter
            if (query) {
                // Support simple filter expressions
                if (query.includes('==')) {
                    return matchFilterExpression(p, query);
                }
                // General text search
                const searchStr = `${p.num} ${p.ipSrc} ${p.ipDst} ${p.protocol} ${p.srcPort} ${p.dstPort} ${p.info} ${p.ethSrc} ${p.ethDst}`.toLowerCase();
                return searchStr.includes(query);
            }

            return true;
        });

        filterCount.textContent = filteredPackets.length === allPackets.length
            ? ''
            : `${filteredPackets.length.toLocaleString()} / ${allPackets.length.toLocaleString()}`;

        updateStats();
        renderPacketTable();
    }

    function matchFilterExpression(p, query) {
        // Support: ip.addr==x, ip.src==x, ip.dst==x, protocol==x, port==x
        const parts = query.split('||').map(s => s.trim());

        return parts.some(part => {
            const [key, val] = part.split('==').map(s => s.trim());
            if (!key || !val) return false;

            switch (key) {
                case 'ip.addr': return p.ipSrc === val || p.ipDst === val;
                case 'ip.src': return p.ipSrc === val;
                case 'ip.dst': return p.ipDst === val;
                case 'protocol': return p.protocol.toLowerCase() === val;
                case 'port': return p.srcPort === parseInt(val) || p.dstPort === parseInt(val);
                case 'tcp.port': return p.protocol === 'TCP' && (p.srcPort === parseInt(val) || p.dstPort === parseInt(val));
                case 'udp.port': return p.protocol === 'UDP' && (p.srcPort === parseInt(val) || p.dstPort === parseInt(val));
                default: return false;
            }
        });
    }

    // ============================================
    // PROTOCOL CHART
    // ============================================
    function renderProtocolChart() {
        const protoCounts = {};
        allPackets.forEach(p => {
            const proto = getProtoGroup(p.protocol);
            protoCounts[proto] = (protoCounts[proto] || 0) + 1;
        });

        const sorted = Object.entries(protoCounts).sort((a, b) => b[1] - a[1]).slice(0, 8);
        const maxCount = sorted[0]?.[1] || 1;

        const protoColors = {
            'TCP': 'var(--proto-tcp)',
            'UDP': 'var(--proto-udp)',
            'HTTP': 'var(--proto-http)',
            'TLS': 'var(--proto-https)',
            'DNS': 'var(--proto-dns)',
            'ICMP': 'var(--proto-icmp)',
            'ARP': 'var(--proto-arp)',
            'DHCP': '#06b6d4',
            'SSDP': '#f472b6'
        };

        const chartEl = $('#protocolChart');
        chartEl.innerHTML = sorted.map(([proto, count]) => {
            const pct = (count / maxCount * 100).toFixed(1);
            const color = protoColors[proto] || 'var(--proto-other)';
            const totalPct = (count / allPackets.length * 100).toFixed(1);
            return `<div class="proto-bar-row">
                <span class="proto-bar-label" style="color:${color}">${proto}</span>
                <div class="proto-bar-track">
                    <div class="proto-bar-fill" style="width:${pct}%;background:${color};opacity:0.7"></div>
                </div>
                <span class="proto-bar-value">${totalPct}%</span>
            </div>`;
        }).join('');
    }

    // ============================================
    // CONVERSATION CHART
    // ============================================
    function renderConversationChart() {
        const conversations = {};
        allPackets.forEach(p => {
            if (!p.ipSrc || !p.ipDst) return;
            const key = [p.ipSrc, p.ipDst].sort().join(' ↔ ');
            conversations[key] = (conversations[key] || 0) + 1;
        });

        const sorted = Object.entries(conversations).sort((a, b) => b[1] - a[1]).slice(0, 6);
        const chartEl = $('#conversationChart');

        if (sorted.length === 0) {
            chartEl.innerHTML = '<div style="color:var(--text-muted);font-size:12px;padding:20px;text-align:center;">No IP conversations detected</div>';
            return;
        }

        chartEl.innerHTML = sorted.map(([pair, count]) => {
            return `<div class="conv-item">
                <span class="conv-arrow">⇄</span>
                <span class="conv-ips">${pair}</span>
                <span class="conv-count">${count.toLocaleString()} pkts</span>
            </div>`;
        }).join('');
    }

    // ============================================
    // ALERTS & FINDINGS
    // ============================================
    function renderAlerts() {
        const alerts = [];

        // Find DNS queries
        const dnsQueries = allPackets.filter(p => p.protocol === 'DNS' && p.appData);
        const uniqueDomains = new Set(dnsQueries.map(p => p.appData));
        if (uniqueDomains.size > 0) {
            alerts.push({ type: 'info', icon: '🌐', text: `${uniqueDomains.size} unique DNS domains queried` });
        }

        // Find large packets
        const largePackets = allPackets.filter(p => p.length > 1400);
        if (largePackets.length > 0) {
            alerts.push({ type: 'warn', icon: '📦', text: `${largePackets.length} large packets (>1400 bytes)` });
        }

        // TCP RST flags
        const rstPackets = allPackets.filter(p => p.tcpFlags?.RST);
        if (rstPackets.length > 0) {
            alerts.push({ type: 'danger', icon: '🚫', text: `${rstPackets.length} TCP RST (connection reset) packets` });
        }

        // SYN without ACK (potential scan)
        const synOnly = allPackets.filter(p => p.tcpFlags?.SYN && !p.tcpFlags?.ACK);
        if (synOnly.length > 10) {
            alerts.push({ type: 'danger', icon: '🔍', text: `${synOnly.length} SYN packets without ACK — possible scan` });
        }

        // ICMP traffic
        const icmpPackets = allPackets.filter(p => p.protocol === 'ICMP');
        if (icmpPackets.length > 0) {
            alerts.push({ type: 'info', icon: '📡', text: `${icmpPackets.length} ICMP packets (ping/traceroute)` });
        }

        // ARP traffic
        const arpPackets = allPackets.filter(p => p.protocol === 'ARP');
        if (arpPackets.length > 20) {
            alerts.push({ type: 'warn', icon: '⚠️', text: `${arpPackets.length} ARP packets — possible ARP storm/scan` });
        }

        // Unusual ports
        const unusualPorts = allPackets.filter(p => {
            const ports = [p.srcPort, p.dstPort];
            return ports.some(port => port > 0 && port < 1024 && ![22, 53, 80, 443, 21, 25, 110, 143, 993, 995, 67, 68, 123, 161].includes(port));
        });
        if (unusualPorts.length > 0) {
            alerts.push({ type: 'warn', icon: '🔒', text: `${unusualPorts.length} packets on uncommon well-known ports` });
        }

        // HTTP plaintext
        const httpPlain = allPackets.filter(p => p.protocol === 'HTTP');
        if (httpPlain.length > 0) {
            alerts.push({ type: 'warn', icon: '🔓', text: `${httpPlain.length} unencrypted HTTP packets` });
        }

        const alertsEl = $('#alertsList');
        const alertBadge = $('#alertCount');

        if (alerts.length === 0) {
            alertsEl.innerHTML = '<div style="color:var(--text-muted);font-size:12px;padding:20px;text-align:center;">No notable findings</div>';
            alertBadge.textContent = '0';
        } else {
            alertBadge.textContent = alerts.length;
            alertsEl.innerHTML = alerts.map(a => {
                return `<div class="alert-item alert-${a.type}">
                    <span class="alert-item-icon">${a.icon}</span>
                    <span class="alert-item-text">${a.text}</span>
                </div>`;
            }).join('');
        }
    }

    // ============================================
    // PACKET TABLE (Virtualized for performance)
    // ============================================
    const ROW_HEIGHT = 32;
    let scrollTop = 0;

    function renderPacketTable() {
        // For large datasets, use simple virtual scrolling
        const total = filteredPackets.length;
        const containerHeight = packetTable.clientHeight || 400;
        const totalHeight = total * ROW_HEIGHT;

        // Set inner height
        packetTable.style.position = 'relative';

        // Render visible rows
        const renderRows = () => {
            const start = Math.floor(packetTable.scrollTop / ROW_HEIGHT);
            const visibleCount = Math.ceil(containerHeight / ROW_HEIGHT) + 5;
            const end = Math.min(start + visibleCount, total);

            let html = `<div style="height:${totalHeight}px;position:relative;">`;

            for (let i = start; i < end; i++) {
                const pkt = filteredPackets[i];
                const protoClass = getProtoClass(pkt.protocol);
                const selectedClass = i === selectedPacketIndex ? 'selected' : '';
                const yPos = i * ROW_HEIGHT;

                html += `<div class="packet-row ${protoClass} ${selectedClass}" data-index="${i}" style="position:absolute;top:${yPos}px;left:0;right:0;height:${ROW_HEIGHT}px;">
                    <div class="td td-no">${pkt.num}</div>
                    <div class="td td-time">${pkt.relativeTime.toFixed(4)}</div>
                    <div class="td td-src">${pkt.ipSrc || pkt.ethSrc}</div>
                    <div class="td td-dst">${pkt.ipDst || pkt.ethDst}</div>
                    <div class="td td-proto">${pkt.protocol}</div>
                    <div class="td td-len">${pkt.length}</div>
                    <div class="td td-info" title="${escapeHtml(pkt.info)}">${escapeHtml(pkt.info)}</div>
                </div>`;
            }

            html += '</div>';
            packetTable.innerHTML = html;
        };

        renderRows();

        // Scroll handler
        packetTable.onscroll = debounce(renderRows, 16);

        // Click handler for rows
        packetTable.onclick = (e) => {
            const row = e.target.closest('.packet-row');
            if (!row) return;
            const idx = parseInt(row.dataset.index);
            selectPacket(idx);
        };
    }

    function getProtoClass(protocol) {
        const p = protocol.toLowerCase();
        if (p === 'tcp') return 'proto-tcp';
        if (p === 'udp') return 'proto-udp';
        if (p === 'http') return 'proto-http';
        if (p === 'tls' || p === 'https') return 'proto-https';
        if (p === 'dns' || p === 'mdns') return 'proto-dns';
        if (p === 'icmp') return 'proto-icmp';
        if (p === 'arp') return 'proto-arp';
        return '';
    }

    // ============================================
    // PACKET DETAIL
    // ============================================
    function selectPacket(index) {
        selectedPacketIndex = index;
        const pkt = filteredPackets[index];
        if (!pkt) return;

        detailPanel.style.display = 'flex';

        // Highlight selected row
        packetTable.querySelectorAll('.packet-row').forEach(r => r.classList.remove('selected'));
        const selectedRow = packetTable.querySelector(`[data-index="${index}"]`);
        if (selectedRow) selectedRow.classList.add('selected');

        // Build detail headers
        let detailHTML = '';

        // Frame info
        detailHTML += buildDetailGroup('Frame', [
            ['Packet Number', pkt.num],
            ['Time', pkt.relativeTime.toFixed(6) + 's'],
            ['Captured Length', pkt.length + ' bytes'],
            ['Original Length', pkt.origLen + ' bytes'],
        ]);

        // Ethernet
        if (pkt.ethSrc) {
            detailHTML += buildDetailGroup('Ethernet II', [
                ['Source MAC', pkt.ethSrc],
                ['Destination MAC', pkt.ethDst],
                ['Type', '0x' + pkt.ethType.toString(16).padStart(4, '0')],
            ]);
        }

        // IP
        if (pkt.ipVersion) {
            detailHTML += buildDetailGroup(`Internet Protocol v${pkt.ipVersion}`, [
                ['Source', pkt.ipSrc],
                ['Destination', pkt.ipDst],
                ['Protocol', pkt.ipProto + ' (' + pkt.protocol + ')'],
                ['TTL / Hop Limit', pkt.ipTTL],
            ]);
        }

        // Transport
        if (pkt.srcPort) {
            const transportItems = [
                ['Source Port', pkt.srcPort],
                ['Destination Port', pkt.dstPort],
            ];

            if (pkt.tcpFlags) {
                const flagStr = Object.entries(pkt.tcpFlags)
                    .filter(([_, v]) => v)
                    .map(([k]) => k)
                    .join(', ');
                transportItems.push(['TCP Flags', flagStr || 'None']);
            }

            detailHTML += buildDetailGroup(pkt.protocol === 'UDP' ? 'User Datagram Protocol' : 'Transmission Control Protocol', transportItems);
        }

        // Application
        if (pkt.appData) {
            detailHTML += buildDetailGroup('Application Data', [
                ['Protocol', pkt.appProtocol],
                ['Data', pkt.appData],
            ]);
        }

        detailHeaders.innerHTML = detailHTML;

        // Hex dump
        const hexLines = PcapParser.hexDump(pkt.rawData, 512);
        hexViewer.innerHTML = hexLines.map(line => {
            return `<div class="hex-line"><span class="hex-offset">${line.offset}</span><span class="hex-bytes">${line.hex}</span><span class="hex-ascii">${escapeHtml(line.ascii)}</span></div>`;
        }).join('');
    }

    function buildDetailGroup(title, items) {
        let html = `<div class="detail-tree-group">
            <div class="detail-tree-group-title">${title}</div>
            <div class="detail-tree">`;
        items.forEach(([key, value]) => {
            html += `<div class="detail-tree-item">
                <span class="detail-tree-key">${key}:</span>
                <span class="detail-tree-value">${escapeHtml(String(value))}</span>
            </div>`;
        });
        html += '</div></div>';
        return html;
    }

    btnCloseDetail.addEventListener('click', () => {
        detailPanel.style.display = 'none';
        selectedPacketIndex = -1;
        packetTable.querySelectorAll('.packet-row').forEach(r => r.classList.remove('selected'));
    });

    // ============================================
    // EXPORT CSV
    // ============================================
    btnExport.addEventListener('click', () => {
        const header = ['No', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'SrcPort', 'DstPort', 'Info'];
        const rows = filteredPackets.map(p => [
            p.num,
            p.relativeTime.toFixed(6),
            p.ipSrc || p.ethSrc,
            p.ipDst || p.ethDst,
            p.protocol,
            p.length,
            p.srcPort,
            p.dstPort,
            `"${p.info.replace(/"/g, '""')}"`
        ].join(','));

        const csv = [header.join(','), ...rows].join('\n');
        const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `sharklens_export_${Date.now()}.csv`;
        a.click();
        URL.revokeObjectURL(url);
    });

    // ============================================
    // UTILITIES
    // ============================================
    function formatBytes(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
    }

    function formatDuration(seconds) {
        if (seconds < 1) return (seconds * 1000).toFixed(0) + 'ms';
        if (seconds < 60) return seconds.toFixed(2) + 's';
        const mins = Math.floor(seconds / 60);
        const secs = (seconds % 60).toFixed(0);
        if (mins < 60) return `${mins}m ${secs}s`;
        const hrs = Math.floor(mins / 60);
        return `${hrs}h ${mins % 60}m`;
    }

    function escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    function debounce(fn, delay) {
        let timer;
        return function (...args) {
            clearTimeout(timer);
            timer = setTimeout(() => fn.apply(this, args), delay);
        };
    }

    // ============================================
    // CTF TOOLKIT
    // ============================================
    const ctfModal = $('#ctfModal');
    const ctfModalTitle = $('#ctfModalTitle');
    const ctfModalBody = $('#ctfModalBody');
    const ctfCopyAll = $('#ctfCopyAll');
    const ctfCopyValues = $('#ctfCopyValues');
    const ctfCopyDecoded = $('#ctfCopyDecoded');
    let lastCTFResults = [];

    // 🔽 CTF TOOLKIT TOGGLE
    const ctfToggle = $('#ctfToggle');
    const ctfCollapsible = $('#ctfCollapsible');



    // ⚡ AUTO-DECODE ENGINE
    function autoDecode(str) {
        const decodings = [];

        // 1. Base64 detection
        const b64Match = str.match(/^(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$/);
        if (b64Match) {
            try {
                const decoded = atob(str);
                const printable = decoded.split('').filter(c => {
                    const code = c.charCodeAt(0);
                    return (code >= 32 && code <= 126) || code === 10 || code === 13 || code === 9;
                }).length;
                if (printable / decoded.length > 0.5) {
                    decodings.push({ type: 'Base64', value: decoded });
                } else {
                    decodings.push({ type: 'Base64 (binary)', value: `[${decoded.length} bytes binary data]` });
                }
            } catch (e) { }
        }

        // 2. Hex string detection (e.g. 48656c6c6f)
        const hexMatch = str.match(/^(?:[0-9a-fA-F]{2}){4,}$/);
        if (hexMatch && str.length >= 8) {
            try {
                let decoded = '';
                for (let i = 0; i < str.length; i += 2) {
                    decoded += String.fromCharCode(parseInt(str.substr(i, 2), 16));
                }
                const printable = decoded.split('').filter(c => {
                    const code = c.charCodeAt(0);
                    return (code >= 32 && code <= 126) || code === 10 || code === 13;
                }).length;
                if (printable / decoded.length > 0.6) {
                    decodings.push({ type: 'Hex', value: decoded });
                }
            } catch (e) { }
        }

        // 3. URL encoding detection
        if (str.includes('%') && /%[0-9A-Fa-f]{2}/.test(str)) {
            try {
                const decoded = decodeURIComponent(str);
                if (decoded !== str) {
                    decodings.push({ type: 'URL', value: decoded });
                }
            } catch (e) { }
        }

        // 4. ROT13 detection (only if string looks like it could be flag-related)
        if (/^[A-Za-z0-9{}_!@#\-]+$/.test(str) && str.length >= 6) {
            const rot13 = str.replace(/[a-zA-Z]/g, c => {
                const base = c <= 'Z' ? 65 : 97;
                return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
            });
            // Only show if ROT13 looks interesting (contains flag-like patterns)
            const customPrefixes = getCustomPrefixList();
            const rot13Prefixes = ['CTF', 'FLAG', 'flag', 'Flag', 'HTB', 'THM', 'pico', 'LKS', ...customPrefixes];
            const rot13Regex = new RegExp('(?:' + rot13Prefixes.map(p => p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|') + ')\\{', 'i');
            if (rot13Regex.test(rot13)) {
                decodings.push({ type: 'ROT13', value: rot13 });
            }
        }

        return decodings;
    }

    // 🏴 GET CUSTOM FLAG PREFIXES from input
    function getCustomPrefixList() {
        const input = $('#ctfCustomFlag');
        if (!input || !input.value.trim()) return [];
        return input.value.split(',').map(s => s.trim()).filter(s => s.length > 0);
    }

    function getCustomFlagPatterns() {
        const prefixes = getCustomPrefixList();
        if (prefixes.length === 0) return [];
        // Build regex for each custom prefix: PREFIX{...}
        return prefixes.map(prefix => {
            const escaped = prefix.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
            return new RegExp(escaped + '\\{[^}]+\\}', 'g');
        });
    }

    function showCTFModal(title, results, type) {
        lastCTFResults = results;
        ctfModalTitle.textContent = title;
        ctfModal.style.display = 'flex';

        if (results.length === 0) {
            ctfModalBody.innerHTML = `<div class="ctf-no-results">
                <div class="ctf-no-results-icon">🔍</div>
                <div>Tidak ditemukan hasil untuk "${title}"</div>
            </div>`;
            return;
        }

        let html = `<div class="ctf-result-count">Ditemukan ${results.length} hasil</div>`;
        results.forEach(r => {
            let decodedHtml = '';
            if (r.decoded) {
                decodedHtml = `<div class="ctf-result-decoded"><div class="ctf-result-decoded-label">Decoded:</div>${escapeHtml(r.decoded)}</div>`;
            }
            // Show all auto-decodings
            if (r.decodings && r.decodings.length > 0) {
                r.decodings.forEach(d => {
                    decodedHtml += `<div class="ctf-result-decoded"><div class="ctf-result-decoded-label">${d.type} Decoded:</div>${escapeHtml(d.value)}</div>`;
                });
            }

            html += `<div class="ctf-result-item ${type ? 'result-' + type : ''}" onclick="navigator.clipboard.writeText(this.querySelector('.ctf-result-value')?.textContent || '')">
                <div class="ctf-result-meta">Packet #${r.packetNum} | ${r.source} → ${r.dest} | ${r.protocol}</div>
                <div class="ctf-result-value">${escapeHtml(r.value)}</div>
                ${decodedHtml}
            </div>`;
        });
        ctfModalBody.innerHTML = html;
    }

    // 📋 Copy All (with metadata)
    ctfCopyAll.addEventListener('click', () => {
        const text = lastCTFResults.map(r => {
            let line = `[Pkt#${r.packetNum}] ${r.source}→${r.dest} (${r.protocol}): ${r.value}`;
            if (r.decoded) line += ` => Decoded: ${r.decoded}`;
            if (r.decodings) r.decodings.forEach(d => { line += ` => ${d.type}: ${d.value}`; });
            return line;
        }).join('\n');
        copyAndFlash(ctfCopyAll, text, '📋 Copy All');
    });

    // 📄 Copy Values Only (just the raw strings, one per line)
    ctfCopyValues.addEventListener('click', () => {
        const text = lastCTFResults.map(r => r.value).join('\n');
        copyAndFlash(ctfCopyValues, text, '📄 Copy Values');
    });

    // 🔓 Copy Decoded Only
    ctfCopyDecoded.addEventListener('click', () => {
        const lines = [];
        lastCTFResults.forEach(r => {
            if (r.decoded) lines.push(r.decoded);
            if (r.decodings) r.decodings.forEach(d => lines.push(d.value));
        });
        if (lines.length === 0) {
            copyAndFlash(ctfCopyDecoded, '', '🔓 Copy Decoded');
            return;
        }
        copyAndFlash(ctfCopyDecoded, lines.join('\n'), '🔓 Copy Decoded');
    });

    function copyAndFlash(btn, text, originalText) {
        navigator.clipboard.writeText(text).then(() => {
            btn.textContent = '✅ Copied!';
            setTimeout(() => btn.textContent = originalText, 1500);
        });
    }

    // Extract ASCII string from raw packet data
    function extractStringsFromPacket(pkt, minLen = 6) {
        const data = pkt.rawData;
        const strings = [];
        let current = '';
        for (let i = 0; i < data.length; i++) {
            const c = data[i];
            if (c >= 32 && c <= 126) {
                current += String.fromCharCode(c);
            } else {
                if (current.length >= minLen) {
                    strings.push(current);
                }
                current = '';
            }
        }
        if (current.length >= minLen) strings.push(current);
        return strings;
    }

    // 🚩 FIND FLAGS
    $('#ctfFindFlag').addEventListener('click', () => {
        if (allPackets.length === 0) return;
        const results = [];
        // Common CTF flag patterns + custom ones
        const flagPatterns = [
            /(?:CTF|FLAG|flag|Flag|ctf|FLAG|HTB|htb|THM|thm|picoCTF|pico|DUCTF|ductf|LKS|lks)\{[^}]+\}/g,
            /flag\s*[:=]\s*[^\s,;]+/gi,
            /flag\s*is\s*[:=]?\s*[^\s,;]+/gi,
            /the\s+flag\s+is\s+[^\s,;]+/gi,
            /key\s*[:=]\s*[A-Za-z0-9+/=_-]{8,}/gi,
            /secret\s*[:=]\s*[^\s,;]+/gi,
            ...getCustomFlagPatterns(),
        ];

        const seen = new Set();
        allPackets.forEach(pkt => {
            const strings = extractStringsFromPacket(pkt, 4);
            strings.forEach(str => {
                flagPatterns.forEach(pattern => {
                    pattern.lastIndex = 0;
                    let match;
                    while ((match = pattern.exec(str)) !== null) {
                        const val = match[0];
                        if (!seen.has(val)) {
                            seen.add(val);
                            const result = {
                                packetNum: pkt.num,
                                source: pkt.ipSrc || pkt.ethSrc,
                                dest: pkt.ipDst || pkt.ethDst,
                                protocol: pkt.protocol,
                                value: val,
                                decodings: autoDecode(val)
                            };
                            results.push(result);
                        }
                    }
                });
            });
        });
        showCTFModal('🚩 Flag Scanner Results', results, 'flag');
    });

    // 📝 EXTRACT STRINGS (with auto-decode!)
    $('#ctfExtractStrings').addEventListener('click', () => {
        if (allPackets.length === 0) return;
        const results = [];
        const seen = new Set();

        allPackets.forEach(pkt => {
            const strings = extractStringsFromPacket(pkt, 8);
            strings.forEach(str => {
                if (str.length > 200) str = str.substring(0, 200) + '...';
                const key = str.substring(0, 100);
                if (!seen.has(key)) {
                    seen.add(key);
                    results.push({
                        packetNum: pkt.num,
                        source: pkt.ipSrc || pkt.ethSrc,
                        dest: pkt.ipDst || pkt.ethDst,
                        protocol: pkt.protocol,
                        value: str,
                        decodings: autoDecode(str)
                    });
                }
            });
        });

        // Sort: strings with decodings first, then by length
        results.sort((a, b) => {
            const aHas = (a.decodings && a.decodings.length > 0) ? 1 : 0;
            const bHas = (b.decodings && b.decodings.length > 0) ? 1 : 0;
            if (bHas !== aHas) return bHas - aHas;
            return b.value.length - a.value.length;
        });
        showCTFModal(`📝 Extracted Strings (${results.length})`, results.slice(0, 500), 'string');
    });

    // 🔓 BASE64 DECODE
    $('#ctfBase64').addEventListener('click', () => {
        if (allPackets.length === 0) return;
        const results = [];
        const b64Pattern = /(?:[A-Za-z0-9+/]{4}){3,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})/g;
        const seen = new Set();

        allPackets.forEach(pkt => {
            const strings = extractStringsFromPacket(pkt, 8);
            strings.forEach(str => {
                b64Pattern.lastIndex = 0;
                let match;
                while ((match = b64Pattern.exec(str)) !== null) {
                    const b64 = match[0];
                    if (b64.length < 12 || seen.has(b64)) continue;
                    seen.add(b64);

                    let decoded = '';
                    try {
                        decoded = atob(b64);
                        // Check if decoded content is readable
                        const printable = decoded.split('').filter(c => {
                            const code = c.charCodeAt(0);
                            return (code >= 32 && code <= 126) || code === 10 || code === 13 || code === 9;
                        }).length;
                        if (printable / decoded.length < 0.6) {
                            decoded = `[Binary data, ${decoded.length} bytes]`;
                        }
                    } catch (e) {
                        decoded = '[Invalid Base64]';
                    }

                    results.push({
                        packetNum: pkt.num,
                        source: pkt.ipSrc || pkt.ethSrc,
                        dest: pkt.ipDst || pkt.ethDst,
                        protocol: pkt.protocol,
                        value: b64,
                        decoded: decoded
                    });
                }
            });
        });
        showCTFModal('🔓 Base64 Detected & Decoded', results, 'b64');
    });

    // 🔑 FIND CREDENTIALS
    $('#ctfCredentials').addEventListener('click', () => {
        if (allPackets.length === 0) return;
        const results = [];
        const credPatterns = [
            /(?:password|passwd|pwd|pass)\s*[:=]\s*[^\s&,;]{1,100}/gi,
            /(?:username|user|usr|login|uname)\s*[:=]\s*[^\s&,;]{1,100}/gi,
            /(?:token|api[_-]?key|apikey|auth|bearer|session|cookie|jwt)\s*[:=]\s*[^\s&,;]{1,200}/gi,
            /(?:secret|private[_-]?key)\s*[:=]\s*[^\s&,;]{1,200}/gi,
            /Authorization:\s*.+/gi,
            /Set-Cookie:\s*.+/gi,
            /Cookie:\s*.+/gi,
            /(?:AWS|AKIA)[A-Za-z0-9+/=]{10,}/g,
            /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
        ];
        const seen = new Set();

        allPackets.forEach(pkt => {
            const strings = extractStringsFromPacket(pkt, 6);
            strings.forEach(str => {
                credPatterns.forEach(pattern => {
                    pattern.lastIndex = 0;
                    let match;
                    while ((match = pattern.exec(str)) !== null) {
                        const val = match[0].substring(0, 300);
                        if (!seen.has(val)) {
                            seen.add(val);
                            results.push({
                                packetNum: pkt.num,
                                source: pkt.ipSrc || pkt.ethSrc,
                                dest: pkt.ipDst || pkt.ethDst,
                                protocol: pkt.protocol,
                                value: val
                            });
                        }
                    }
                });
            });
        });
        showCTFModal('🔑 Credentials & Secrets Found', results, 'cred');
    });

    // 🌐 EXTRACT URLs
    $('#ctfURLs').addEventListener('click', () => {
        if (allPackets.length === 0) return;
        const results = [];
        const urlPattern = /https?:\/\/[^\s"'<>]{5,}/gi;
        const seen = new Set();

        allPackets.forEach(pkt => {
            const strings = extractStringsFromPacket(pkt, 10);
            strings.forEach(str => {
                urlPattern.lastIndex = 0;
                let match;
                while ((match = urlPattern.exec(str)) !== null) {
                    const url = match[0].replace(/[)\]}>]+$/, '');
                    if (!seen.has(url)) {
                        seen.add(url);
                        results.push({
                            packetNum: pkt.num,
                            source: pkt.ipSrc || pkt.ethSrc,
                            dest: pkt.ipDst || pkt.ethDst,
                            protocol: pkt.protocol,
                            value: url
                        });
                    }
                }
            });

            // Also add DNS domains
            if (pkt.appData && pkt.protocol === 'DNS') {
                const domain = pkt.appData;
                if (!seen.has(domain)) {
                    seen.add(domain);
                    results.push({
                        packetNum: pkt.num,
                        source: pkt.ipSrc || pkt.ethSrc,
                        dest: pkt.ipDst || pkt.ethDst,
                        protocol: 'DNS',
                        value: `[DNS Query] ${domain}`
                    });
                }
            }
        });
        showCTFModal('🌐 URLs & Domains Extracted', results, 'url');
    });

    // 📁 DETECT FILES (Magic Bytes)
    $('#ctfFiles').addEventListener('click', () => {
        if (allPackets.length === 0) return;
        const results = [];
        const signatures = [
            { magic: [0x89, 0x50, 0x4E, 0x47], name: 'PNG Image', ext: '.png' },
            { magic: [0xFF, 0xD8, 0xFF], name: 'JPEG Image', ext: '.jpg' },
            { magic: [0x47, 0x49, 0x46, 0x38], name: 'GIF Image', ext: '.gif' },
            { magic: [0x25, 0x50, 0x44, 0x46], name: 'PDF Document', ext: '.pdf' },
            { magic: [0x50, 0x4B, 0x03, 0x04], name: 'ZIP/DOCX/XLSX Archive', ext: '.zip' },
            { magic: [0x50, 0x4B, 0x05, 0x06], name: 'ZIP Archive (empty)', ext: '.zip' },
            { magic: [0x1F, 0x8B], name: 'GZIP Archive', ext: '.gz' },
            { magic: [0x42, 0x5A, 0x68], name: 'BZIP2 Archive', ext: '.bz2' },
            { magic: [0x37, 0x7A, 0xBC, 0xAF], name: '7-Zip Archive', ext: '.7z' },
            { magic: [0x52, 0x61, 0x72, 0x21], name: 'RAR Archive', ext: '.rar' },
            { magic: [0x4D, 0x5A], name: 'Windows EXE/DLL', ext: '.exe' },
            { magic: [0x7F, 0x45, 0x4C, 0x46], name: 'ELF Binary (Linux)', ext: '.elf' },
            { magic: [0xCA, 0xFE, 0xBA, 0xBE], name: 'Java Class / Mach-O', ext: '.class' },
            { magic: [0x49, 0x44, 0x33], name: 'MP3 Audio', ext: '.mp3' },
            { magic: [0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70], name: 'MP4 Video', ext: '.mp4' },
            { magic: [0x66, 0x74, 0x79, 0x70], name: 'MP4/MOV (ftyp)', ext: '.mp4', offset: 4 },
            { magic: [0xD0, 0xCF, 0x11, 0xE0], name: 'MS Office (DOC/XLS/PPT)', ext: '.doc' },
            { magic: [0x53, 0x51, 0x4C, 0x69, 0x74, 0x65], name: 'SQLite Database', ext: '.db' },
        ];

        allPackets.forEach(pkt => {
            const data = pkt.rawData;
            // Start scanning from after typical headers (Ethernet 14 + IP 20 + TCP 20 = 54)
            const startOffsets = [0, 14, 34, 54, 42, 66];

            signatures.forEach(sig => {
                for (const baseOffset of startOffsets) {
                    const scanOffset = baseOffset + (sig.offset || 0);
                    if (scanOffset + sig.magic.length > data.length) continue;

                    let match = true;
                    for (let i = 0; i < sig.magic.length; i++) {
                        if (data[scanOffset + i] !== sig.magic[i]) {
                            match = false;
                            break;
                        }
                    }

                    if (match) {
                        results.push({
                            packetNum: pkt.num,
                            source: pkt.ipSrc || pkt.ethSrc,
                            dest: pkt.ipDst || pkt.ethDst,
                            protocol: pkt.protocol,
                            value: `${sig.name} (${sig.ext}) detected at offset ${scanOffset} | Packet size: ${data.length} bytes`
                        });
                        break; // One match per signature per packet
                    }
                }
            });
        });
        showCTFModal('📁 File Signatures Detected', results, 'file');
    });

    // ⚡ AUTO SOLVE — Run ALL scanners in one click
    $('#ctfAutoSolve').addEventListener('click', () => {
        if (allPackets.length === 0) return;

        const allResults = [];
        const seen = new Set();

        // Common patterns + custom ones
        const flagPatterns = [
            /(?:CTF|FLAG|flag|Flag|ctf|HTB|htb|THM|thm|picoCTF|pico|DUCTF|ductf|LKS|lks)\{[^}]+\}/g,
            /flag\s*[:=]\s*[^\s,;]+/gi,
            /flag\s*is\s*[:=]?\s*[^\s,;]+/gi,
            /the\s+flag\s+is\s+[^\s,;]+/gi,
            ...getCustomFlagPatterns(),
        ];
        const b64Pattern = /(?:[A-Za-z0-9+/]{4}){3,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})/g;
        const credPatterns = [
            /(?:password|passwd|pwd|pass)\s*[:=]\s*[^\s&,;]{1,100}/gi,
            /(?:username|user|usr|login)\s*[:=]\s*[^\s&,;]{1,100}/gi,
            /(?:token|api[_-]?key|apikey|auth|bearer|session|jwt)\s*[:=]\s*[^\s&,;]{1,200}/gi,
            /Authorization:\s*.+/gi,
            /Set-Cookie:\s*.+/gi,
            /Cookie:\s*.+/gi,
        ];
        const urlPattern = /https?:\/\/[^\s"'<>]{5,}/gi;
        const fileSigs = [
            { magic: [0x89, 0x50, 0x4E, 0x47], name: 'PNG' },
            { magic: [0xFF, 0xD8, 0xFF], name: 'JPEG' },
            { magic: [0x25, 0x50, 0x44, 0x46], name: 'PDF' },
            { magic: [0x50, 0x4B, 0x03, 0x04], name: 'ZIP' },
            { magic: [0x1F, 0x8B], name: 'GZIP' },
            { magic: [0x52, 0x61, 0x72, 0x21], name: 'RAR' },
            { magic: [0x4D, 0x5A], name: 'EXE' },
            { magic: [0x7F, 0x45, 0x4C, 0x46], name: 'ELF' },
            { magic: [0x53, 0x51, 0x4C, 0x69, 0x74, 0x65], name: 'SQLite' },
        ];

        allPackets.forEach(pkt => {
            const strings = extractStringsFromPacket(pkt, 4);
            const pktInfo = {
                packetNum: pkt.num,
                source: pkt.ipSrc || pkt.ethSrc || '?',
                dest: pkt.ipDst || pkt.ethDst || '?',
                protocol: pkt.protocol
            };

            // 1. Flag scan
            strings.forEach(str => {
                flagPatterns.forEach(p => {
                    p.lastIndex = 0;
                    let m;
                    while ((m = p.exec(str)) !== null) {
                        const v = m[0];
                        const key = '🚩' + v;
                        if (!seen.has(key)) {
                            seen.add(key);
                            allResults.push({ ...pktInfo, value: v, category: '🚩 FLAGS', decodings: autoDecode(v) });
                        }
                    }
                });
            });

            // 2. Credentials
            strings.forEach(str => {
                credPatterns.forEach(p => {
                    p.lastIndex = 0;
                    let m;
                    while ((m = p.exec(str)) !== null) {
                        const v = m[0].substring(0, 200);
                        const key = '🔑' + v;
                        if (!seen.has(key)) {
                            seen.add(key);
                            allResults.push({ ...pktInfo, value: v, category: '🔑 CREDENTIALS' });
                        }
                    }
                });
            });

            // 3. Base64
            strings.forEach(str => {
                b64Pattern.lastIndex = 0;
                let m;
                while ((m = b64Pattern.exec(str)) !== null) {
                    const b64 = m[0];
                    if (b64.length < 12) continue;
                    const key = '🔓' + b64;
                    if (!seen.has(key)) {
                        seen.add(key);
                        allResults.push({ ...pktInfo, value: b64, category: '🔓 BASE64', decodings: autoDecode(b64) });
                    }
                }
            });

            // 4. URLs
            strings.forEach(str => {
                urlPattern.lastIndex = 0;
                let m;
                while ((m = urlPattern.exec(str)) !== null) {
                    const url = m[0].replace(/[)\]}>]+$/, '');
                    const key = '🌐' + url;
                    if (!seen.has(key)) {
                        seen.add(key);
                        allResults.push({ ...pktInfo, value: url, category: '🌐 URLs' });
                    }
                }
            });

            // 5. File signatures
            const data = pkt.rawData;
            const offsets = [0, 14, 34, 54, 42, 66];
            fileSigs.forEach(sig => {
                for (const off of offsets) {
                    if (off + sig.magic.length > data.length) continue;
                    let ok = true;
                    for (let i = 0; i < sig.magic.length; i++) {
                        if (data[off + i] !== sig.magic[i]) { ok = false; break; }
                    }
                    if (ok) {
                        const v = `${sig.name} file at offset ${off} (${data.length} bytes)`;
                        const key = '📁' + pkt.num + sig.name;
                        if (!seen.has(key)) {
                            seen.add(key);
                            allResults.push({ ...pktInfo, value: v, category: '📁 FILES' });
                        }
                        break;
                    }
                }
            });
        });

        // Group by category and render custom modal
        const categories = ['🚩 FLAGS', '🔑 CREDENTIALS', '🔓 BASE64', '🌐 URLs', '📁 FILES'];
        const grouped = {};
        categories.forEach(c => grouped[c] = []);
        allResults.forEach(r => {
            if (grouped[r.category]) grouped[r.category].push(r);
        });

        // Build combined results with category headers
        const combined = [];
        categories.forEach(cat => {
            if (grouped[cat].length > 0) {
                grouped[cat].forEach(r => combined.push(r));
            }
        });

        lastCTFResults = combined;
        ctfModalTitle.textContent = `⚡ Auto Solve — ${combined.length} findings`;
        ctfModal.style.display = 'flex';

        if (combined.length === 0) {
            ctfModalBody.innerHTML = `<div class="ctf-no-results">
                <div class="ctf-no-results-icon">🤷</div>
                <div>Tidak ada yang mencurigakan ditemukan di ${allPackets.length} paket</div>
            </div>`;
            return;
        }

        let html = `<div class="ctf-result-count">⚡ Ditemukan ${combined.length} total findings dari ${allPackets.length} paket</div>`;
        let currentCat = '';
        combined.forEach(r => {
            if (r.category !== currentCat) {
                currentCat = r.category;
                const count = grouped[currentCat].length;
                html += `<div style="margin:16px 0 8px;padding:8px 12px;background:rgba(99,102,241,0.1);border-radius:8px;font-weight:700;font-size:14px;color:#c7d2fe;">${currentCat} <span style="font-size:11px;opacity:0.7;">(${count})</span></div>`;
            }
            const typeMap = { '🚩 FLAGS': 'flag', '🔑 CREDENTIALS': 'cred', '🔓 BASE64': 'b64', '🌐 URLs': 'url', '📁 FILES': 'file' };
            const itemType = typeMap[r.category] || '';
            let decodedHtml = '';
            if (r.decodings && r.decodings.length > 0) {
                r.decodings.forEach(d => {
                    decodedHtml += `<div class="ctf-result-decoded"><div class="ctf-result-decoded-label">${d.type} Decoded:</div>${escapeHtml(d.value)}</div>`;
                });
            }
            html += `<div class="ctf-result-item result-${itemType}" onclick="navigator.clipboard.writeText(this.querySelector('.ctf-result-value')?.textContent || '')">
                <div class="ctf-result-meta">Packet #${r.packetNum} | ${r.source} → ${r.dest} | ${r.protocol}</div>
                <div class="ctf-result-value">${escapeHtml(r.value)}</div>
                ${decodedHtml}
            </div>`;
        });
        ctfModalBody.innerHTML = html;
    });

    // 🔽 CTF TOOLBAR TOGGLE
    ctfToggle.addEventListener('click', () => {
        ctfToggle.classList.toggle('open');
        ctfCollapsible.classList.toggle('open');
        ctfToggle.querySelector('.ctf-toggle-icon').textContent = ctfCollapsible.classList.contains('open') ? '▲' : '▼';
    });

    // 🏷️ QUICK FILTERS
    document.querySelectorAll('.ctf-qf').forEach(btn => {
        btn.addEventListener('click', () => {
            const filter = btn.dataset.filter;
            const wasActive = btn.classList.contains('active');

            // Clear all quick filter active states
            document.querySelectorAll('.ctf-qf').forEach(b => b.classList.remove('active'));

            if (wasActive) {
                // Deactivate
                searchInput.value = '';
                activeProtocolFilter = null;
                protocolChips.querySelectorAll('.chip').forEach(c => c.classList.remove('active'));
                applyFilters();
                return;
            }

            btn.classList.add('active');

            // Clear protocol chip filter
            activeProtocolFilter = null;
            protocolChips.querySelectorAll('.chip').forEach(c => c.classList.remove('active'));

            switch (filter) {
                case 'http-only':
                    searchInput.value = '';
                    activeProtocolFilter = 'HTTP';
                    break;
                case 'dns-only':
                    searchInput.value = '';
                    activeProtocolFilter = 'DNS';
                    break;
                case 'ftp':
                    searchInput.value = 'port==21';
                    break;
                case 'telnet':
                    searchInput.value = 'port==23';
                    break;
                case 'smtp':
                    searchInput.value = 'port==25';
                    break;
                case 'ssh':
                    searchInput.value = 'port==22';
                    break;
                case 'data-packets':
                    // Filter packets with PSH+ACK (data transfer)
                    searchInput.value = '';
                    filteredPackets = allPackets.filter(p =>
                        p.tcpFlags && p.tcpFlags.PSH && p.tcpFlags.ACK
                    );
                    filterCount.textContent = `${filteredPackets.length.toLocaleString()} / ${allPackets.length.toLocaleString()}`;
                    updateStats();
                    renderPacketTable();
                    return;
            }
            applyFilters();
        });
    });

    // ============================================
    // KEYBOARD SHORTCUTS
    // ============================================
    document.addEventListener('keydown', (e) => {
        // Close CTF modal with Escape
        if (e.key === 'Escape') {
            if (ctfModal.style.display !== 'none' && ctfModal.style.display !== '') {
                ctfModal.style.display = 'none';
                return;
            }
            detailPanel.style.display = 'none';
            selectedPacketIndex = -1;
        }

        // Don't trigger shortcuts when typing in search
        if (e.target.tagName === 'INPUT') return;

        // Ctrl+O to open
        if (e.ctrlKey && e.key === 'o') {
            e.preventDefault();
            fileInput.click();
        }

        // Ctrl+F to focus filter
        if (e.ctrlKey && e.key === 'f') {
            e.preventDefault();
            searchInput.focus();
        }

        // Arrow keys to navigate packets
        if (selectedPacketIndex >= 0) {
            if (e.key === 'ArrowDown' && selectedPacketIndex < filteredPackets.length - 1) {
                e.preventDefault();
                selectPacket(selectedPacketIndex + 1);
            }
            if (e.key === 'ArrowUp' && selectedPacketIndex > 0) {
                e.preventDefault();
                selectPacket(selectedPacketIndex - 1);
            }
        }

        // Ctrl+E to export
        if (e.ctrlKey && e.key === 'e' && allPackets.length > 0) {
            e.preventDefault();
            btnExport.click();
        }

        // CTF Shortcuts (with Alt key)
        if (e.altKey && allPackets.length > 0) {
            switch (e.key) {
                case 'a': case 'A': e.preventDefault(); $('#ctfAutoSolve').click(); break;
                case '1': e.preventDefault(); $('#ctfFindFlag').click(); break;
                case '2': e.preventDefault(); $('#ctfExtractStrings').click(); break;
                case '3': e.preventDefault(); $('#ctfBase64').click(); break;
                case '4': e.preventDefault(); $('#ctfCredentials').click(); break;
                case '5': e.preventDefault(); $('#ctfURLs').click(); break;
                case '6': e.preventDefault(); $('#ctfFiles').click(); break;
            }
        }
    });
})();
