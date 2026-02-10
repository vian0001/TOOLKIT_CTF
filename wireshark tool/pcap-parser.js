/**
 * SharkLens PCAP Parser
 * Binary parser for PCAP and PCAP-NG files
 * Parses: Ethernet → IPv4 → TCP/UDP/ICMP headers + application layer (HTTP, DNS)
 */

class PcapParser {
    constructor() {
        this.packets = [];
        this.fileFormat = null; // 'pcap' or 'pcapng'
        this.linkType = 1; // Ethernet
        this.snapLen = 65535;
        this.byteOrder = 'little'; // 'little' or 'big'
        this.startTime = null;
    }

    /**
     * Parse an ArrayBuffer containing PCAP data
     * @param {ArrayBuffer} buffer 
     * @returns {Object} Parsed result with packets and metadata
     */
    parse(buffer) {
        this.packets = [];
        const view = new DataView(buffer);
        const magic = view.getUint32(0, true);

        if (magic === 0xa1b2c3d4 || magic === 0xd4c3b2a1) {
            // Standard PCAP
            this.fileFormat = 'pcap';
            this.byteOrder = (magic === 0xa1b2c3d4) ? 'little' : 'big';
            this._parsePcap(view, buffer);
        } else if (magic === 0xa1b23c4d || magic === 0x4d3cb2a1) {
            // PCAP with nanosecond timestamps
            this.fileFormat = 'pcap';
            this.byteOrder = (magic === 0xa1b23c4d) ? 'little' : 'big';
            this._parsePcap(view, buffer, true);
        } else {
            // Try PCAP-NG
            const blockType = view.getUint32(0, true);
            if (blockType === 0x0a0d0d0a) {
                this.fileFormat = 'pcapng';
                this._parsePcapNg(view, buffer);
            } else {
                throw new Error('Unsupported file format. Expected PCAP or PCAP-NG.');
            }
        }

        return {
            format: this.fileFormat,
            linkType: this.linkType,
            totalPackets: this.packets.length,
            packets: this.packets,
            fileSize: buffer.byteLength
        };
    }

    _le() { return this.byteOrder === 'little'; }

    _parsePcap(view, buffer, nanoseconds = false) {
        const le = this._le();
        // Global Header: 24 bytes
        // magic(4) + major(2) + minor(2) + thiszone(4) + sigfigs(4) + snaplen(4) + network(4)
        this.snapLen = view.getUint32(16, le);
        this.linkType = view.getUint32(20, le);

        let offset = 24;
        let packetNum = 0;

        while (offset + 16 <= buffer.byteLength) {
            // Packet Header: 16 bytes
            const tsSec = view.getUint32(offset, le);
            const tsUsec = view.getUint32(offset + 4, le);
            const inclLen = view.getUint32(offset + 8, le);
            const origLen = view.getUint32(offset + 12, le);

            if (inclLen > 262144 || offset + 16 + inclLen > buffer.byteLength) break;

            const timestamp = nanoseconds
                ? tsSec + tsUsec / 1e9
                : tsSec + tsUsec / 1e6;

            if (this.startTime === null) this.startTime = timestamp;

            const packetData = new Uint8Array(buffer, offset + 16, inclLen);
            const parsed = this._parsePacket(packetData, packetNum + 1, timestamp);
            parsed.origLen = origLen;
            this.packets.push(parsed);

            offset += 16 + inclLen;
            packetNum++;

            // Safety limit
            if (packetNum >= 100000) break;
        }
    }

    _parsePcapNg(view, buffer) {
        let offset = 0;
        let packetNum = 0;
        let interfaces = [];

        while (offset + 8 <= buffer.byteLength) {
            const blockType = view.getUint32(offset, true);
            const blockLen = view.getUint32(offset + 4, true);

            if (blockLen < 12 || offset + blockLen > buffer.byteLength) break;

            switch (blockType) {
                case 0x0a0d0d0a: // Section Header Block
                    // Check byte order
                    if (offset + 12 <= buffer.byteLength) {
                        const bom = view.getUint32(offset + 8, true);
                        this.byteOrder = (bom === 0x1a2b3c4d) ? 'little' : 'big';
                    }
                    break;

                case 0x00000001: { // Interface Description Block
                    const linkType = view.getUint16(offset + 8, this._le());
                    const snapLen = view.getUint32(offset + 12, this._le());
                    interfaces.push({ linkType, snapLen, tsResol: 6 }); // default microseconds
                    if (interfaces.length === 1) {
                        this.linkType = linkType;
                        this.snapLen = snapLen;
                    }
                    break;
                }

                case 0x00000006: { // Enhanced Packet Block
                    if (offset + 28 <= buffer.byteLength) {
                        const interfaceId = view.getUint32(offset + 8, this._le());
                        const tsHigh = view.getUint32(offset + 12, this._le());
                        const tsLow = view.getUint32(offset + 16, this._le());
                        const capturedLen = view.getUint32(offset + 20, this._le());
                        const origLen = view.getUint32(offset + 24, this._le());

                        if (capturedLen > 262144 || offset + 28 + capturedLen > buffer.byteLength) break;

                        // Calculate timestamp
                        const tsResol = (interfaces[interfaceId] || {}).tsResol || 6;
                        const ts64 = tsHigh * 4294967296 + tsLow;
                        const timestamp = ts64 / Math.pow(10, tsResol);

                        if (this.startTime === null) this.startTime = timestamp;

                        const packetData = new Uint8Array(buffer, offset + 28, capturedLen);
                        const parsed = this._parsePacket(packetData, packetNum + 1, timestamp);
                        parsed.origLen = origLen;
                        this.packets.push(parsed);
                        packetNum++;

                        if (packetNum >= 100000) break;
                    }
                    break;
                }
            }

            // Move to next block (aligned to 4 bytes)
            const alignedLen = Math.ceil(blockLen / 4) * 4;
            offset += alignedLen;
        }
    }

    _parsePacket(data, num, timestamp) {
        const result = {
            num,
            timestamp,
            relativeTime: timestamp - (this.startTime || timestamp),
            length: data.length,
            origLen: data.length,
            rawData: data,
            // Ethernet
            ethSrc: '',
            ethDst: '',
            ethType: 0,
            // IP
            ipVersion: 0,
            ipSrc: '',
            ipDst: '',
            ipProto: 0,
            ipTTL: 0,
            // Transport
            srcPort: 0,
            dstPort: 0,
            protocol: 'Unknown',
            info: '',
            // Flags
            tcpFlags: null,
            // Application layer
            appProtocol: '',
            appData: ''
        };

        if (data.length < 14) {
            result.protocol = 'Unknown';
            result.info = `Short frame (${data.length} bytes)`;
            return result;
        }

        // Parse Ethernet header (14 bytes)
        if (this.linkType === 1) { // Ethernet
            result.ethDst = this._formatMAC(data, 0);
            result.ethSrc = this._formatMAC(data, 6);
            result.ethType = (data[12] << 8) | data[13];
            this._parseEthPayload(data, 14, result);
        } else if (this.linkType === 101) { // Raw IP
            this._parseIPv4(data, 0, result);
        } else if (this.linkType === 113) { // Linux SLL
            if (data.length >= 16) {
                result.ethType = (data[14] << 8) | data[15];
                this._parseEthPayload(data, 16, result);
            }
        } else {
            result.protocol = `LinkType:${this.linkType}`;
            result.info = `${data.length} bytes`;
        }

        return result;
    }

    _parseEthPayload(data, offset, result) {
        switch (result.ethType) {
            case 0x0800: // IPv4
                this._parseIPv4(data, offset, result);
                break;
            case 0x0806: // ARP
                this._parseARP(data, offset, result);
                break;
            case 0x86DD: // IPv6
                this._parseIPv6(data, offset, result);
                break;
            case 0x8100: // VLAN
                if (data.length > offset + 4) {
                    result.ethType = (data[offset + 2] << 8) | data[offset + 3];
                    this._parseEthPayload(data, offset + 4, result);
                }
                break;
            default:
                result.protocol = `Eth:0x${result.ethType.toString(16).padStart(4, '0')}`;
                result.info = `${result.ethSrc} → ${result.ethDst}`;
        }
    }

    _parseIPv4(data, offset, result) {
        if (data.length < offset + 20) {
            result.protocol = 'IPv4';
            result.info = 'Truncated IP header';
            return;
        }

        const versionIHL = data[offset];
        result.ipVersion = (versionIHL >> 4) & 0xF;
        const headerLen = (versionIHL & 0xF) * 4;
        const totalLength = (data[offset + 2] << 8) | data[offset + 3];
        result.ipTTL = data[offset + 8];
        result.ipProto = data[offset + 9];
        result.ipSrc = `${data[offset + 12]}.${data[offset + 13]}.${data[offset + 14]}.${data[offset + 15]}`;
        result.ipDst = `${data[offset + 16]}.${data[offset + 17]}.${data[offset + 18]}.${data[offset + 19]}`;

        const transportOffset = offset + headerLen;

        switch (result.ipProto) {
            case 1: // ICMP
                this._parseICMP(data, transportOffset, result);
                break;
            case 6: // TCP
                this._parseTCP(data, transportOffset, result);
                break;
            case 17: // UDP
                this._parseUDP(data, transportOffset, result);
                break;
            default:
                result.protocol = `IP:${result.ipProto}`;
                result.info = `${result.ipSrc} → ${result.ipDst} | Proto: ${result.ipProto}`;
        }
    }

    _parseIPv6(data, offset, result) {
        if (data.length < offset + 40) {
            result.protocol = 'IPv6';
            result.info = 'Truncated IPv6 header';
            return;
        }

        result.ipVersion = 6;
        const nextHeader = data[offset + 6];
        result.ipTTL = data[offset + 7]; // Hop Limit

        result.ipSrc = this._formatIPv6(data, offset + 8);
        result.ipDst = this._formatIPv6(data, offset + 24);
        result.ipProto = nextHeader;

        const transportOffset = offset + 40;

        switch (nextHeader) {
            case 1: // ICMPv4
            case 58: // ICMPv6
                this._parseICMP(data, transportOffset, result);
                break;
            case 6:
                this._parseTCP(data, transportOffset, result);
                break;
            case 17:
                this._parseUDP(data, transportOffset, result);
                break;
            default:
                result.protocol = `IPv6:${nextHeader}`;
                result.info = `${result.ipSrc} → ${result.ipDst}`;
        }
    }

    _parseTCP(data, offset, result) {
        if (data.length < offset + 20) {
            result.protocol = 'TCP';
            result.info = `${result.ipSrc} → ${result.ipDst} | Truncated`;
            return;
        }

        result.srcPort = (data[offset] << 8) | data[offset + 1];
        result.dstPort = (data[offset + 2] << 8) | data[offset + 3];
        const seqNum = ((data[offset + 4] << 24) | (data[offset + 5] << 16) | (data[offset + 6] << 8) | data[offset + 7]) >>> 0;
        const ackNum = ((data[offset + 8] << 24) | (data[offset + 9] << 16) | (data[offset + 10] << 8) | data[offset + 11]) >>> 0;
        const dataOffset = ((data[offset + 12] >> 4) & 0xF) * 4;
        const flags = data[offset + 13];
        const windowSize = (data[offset + 14] << 8) | data[offset + 15];

        result.tcpFlags = {
            FIN: !!(flags & 0x01),
            SYN: !!(flags & 0x02),
            RST: !!(flags & 0x04),
            PSH: !!(flags & 0x08),
            ACK: !!(flags & 0x10),
            URG: !!(flags & 0x20)
        };

        const flagStr = Object.entries(result.tcpFlags)
            .filter(([_, v]) => v)
            .map(([k]) => k)
            .join(', ');

        result.protocol = 'TCP';

        // Detect application protocol
        const payloadOffset = offset + dataOffset;
        const payloadLen = data.length - payloadOffset;

        if (this._isHTTP(result.srcPort, result.dstPort)) {
            if (payloadLen > 0) {
                this._parseHTTPPayload(data, payloadOffset, payloadLen, result);
            } else {
                result.protocol = 'HTTP';
                result.info = `${result.ipSrc}:${result.srcPort} → ${result.ipDst}:${result.dstPort} [${flagStr}] Seq=${seqNum} Ack=${ackNum} Win=${windowSize}`;
            }
        } else if (this._isTLS(result.srcPort, result.dstPort, data, payloadOffset, payloadLen)) {
            result.protocol = 'TLS';
            result.info = `${result.ipSrc}:${result.srcPort} → ${result.ipDst}:${result.dstPort} [${flagStr}]`;
            if (payloadLen > 0) {
                this._parseTLSRecord(data, payloadOffset, payloadLen, result);
            }
        } else {
            result.info = `${result.ipSrc}:${result.srcPort} → ${result.ipDst}:${result.dstPort} [${flagStr}] Seq=${seqNum} Ack=${ackNum} Win=${windowSize} Len=${payloadLen}`;
        }
    }

    _parseUDP(data, offset, result) {
        if (data.length < offset + 8) {
            result.protocol = 'UDP';
            result.info = `${result.ipSrc} → ${result.ipDst} | Truncated`;
            return;
        }

        result.srcPort = (data[offset] << 8) | data[offset + 1];
        result.dstPort = (data[offset + 2] << 8) | data[offset + 3];
        const udpLen = (data[offset + 4] << 8) | data[offset + 5];

        result.protocol = 'UDP';

        // Check for DNS
        if (result.srcPort === 53 || result.dstPort === 53) {
            this._parseDNS(data, offset + 8, result);
        } else if (result.srcPort === 67 || result.dstPort === 67 || result.srcPort === 68 || result.dstPort === 68) {
            result.protocol = 'DHCP';
            result.info = `${result.ipSrc}:${result.srcPort} → ${result.ipDst}:${result.dstPort} | Len=${udpLen}`;
        } else if (result.srcPort === 5353 || result.dstPort === 5353) {
            this._parseDNS(data, offset + 8, result);
            result.protocol = 'mDNS';
        } else if (result.srcPort === 1900 || result.dstPort === 1900) {
            result.protocol = 'SSDP';
            result.info = `${result.ipSrc}:${result.srcPort} → ${result.ipDst}:${result.dstPort} | Len=${udpLen}`;
        } else {
            result.info = `${result.ipSrc}:${result.srcPort} → ${result.ipDst}:${result.dstPort} | Len=${udpLen}`;
        }
    }

    _parseICMP(data, offset, result) {
        result.protocol = 'ICMP';
        if (data.length < offset + 4) {
            result.info = `${result.ipSrc} → ${result.ipDst}`;
            return;
        }

        const type = data[offset];
        const code = data[offset + 1];
        const typeNames = {
            0: 'Echo Reply',
            3: 'Destination Unreachable',
            5: 'Redirect',
            8: 'Echo Request',
            11: 'Time Exceeded',
            13: 'Timestamp Request',
            14: 'Timestamp Reply'
        };

        const typeName = typeNames[type] || `Type ${type}`;
        result.info = `${result.ipSrc} → ${result.ipDst} | ${typeName} (code=${code})`;

        if ((type === 0 || type === 8) && data.length >= offset + 8) {
            const id = (data[offset + 4] << 8) | data[offset + 5];
            const seq = (data[offset + 6] << 8) | data[offset + 7];
            result.info += ` id=0x${id.toString(16)} seq=${seq}`;
        }
    }

    _parseARP(data, offset, result) {
        result.protocol = 'ARP';
        if (data.length < offset + 28) {
            result.info = 'ARP (truncated)';
            return;
        }

        const opcode = (data[offset + 6] << 8) | data[offset + 7];
        const senderIP = `${data[offset + 14]}.${data[offset + 15]}.${data[offset + 16]}.${data[offset + 17]}`;
        const targetIP = `${data[offset + 24]}.${data[offset + 25]}.${data[offset + 26]}.${data[offset + 27]}`;
        const senderMAC = this._formatMAC(data, offset + 8);

        if (opcode === 1) {
            result.info = `Who has ${targetIP}? Tell ${senderIP}`;
        } else if (opcode === 2) {
            result.info = `${senderIP} is at ${senderMAC}`;
        } else {
            result.info = `Opcode ${opcode}: ${senderIP} → ${targetIP}`;
        }

        result.ipSrc = senderIP;
        result.ipDst = targetIP;
    }

    _parseDNS(data, offset, result) {
        result.protocol = 'DNS';
        if (data.length < offset + 12) {
            result.info = `${result.ipSrc} → ${result.ipDst} | DNS (truncated)`;
            return;
        }

        const id = (data[offset] << 8) | data[offset + 1];
        const flags = (data[offset + 2] << 8) | data[offset + 3];
        const isResponse = !!(flags & 0x8000);
        const qdCount = (data[offset + 4] << 8) | data[offset + 5];
        const anCount = (data[offset + 6] << 8) | data[offset + 7];

        // Parse first query name
        let queryName = '';
        let pos = offset + 12;
        try {
            const nameResult = this._parseDNSName(data, pos, offset);
            queryName = nameResult.name;
            pos = nameResult.offset;
        } catch (e) {
            queryName = '(parse error)';
        }

        // Parse query type
        let queryType = '';
        if (pos + 4 <= data.length) {
            const qtype = (data[pos] << 8) | data[pos + 1];
            const qtypeNames = { 1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 255: 'ANY', 65: 'HTTPS' };
            queryType = qtypeNames[qtype] || `Type${qtype}`;
        }

        if (isResponse) {
            result.info = `${result.ipSrc} → ${result.ipDst} | DNS Response 0x${id.toString(16)} | ${queryType} ${queryName} (${anCount} answers)`;
        } else {
            result.info = `${result.ipSrc} → ${result.ipDst} | DNS Query 0x${id.toString(16)} | ${queryType} ${queryName}`;
        }

        result.appProtocol = 'DNS';
        result.appData = queryName;
    }

    _parseDNSName(data, offset, dnsStart) {
        let name = '';
        let pos = offset;
        let jumps = 0;
        let returnPos = -1;

        while (pos < data.length && jumps < 20) {
            const len = data[pos];
            if (len === 0) {
                pos++;
                break;
            }
            if ((len & 0xC0) === 0xC0) {
                // Pointer
                if (returnPos === -1) returnPos = pos + 2;
                const ptr = ((len & 0x3F) << 8) | data[pos + 1];
                pos = dnsStart + ptr;
                jumps++;
                continue;
            }
            if (name.length > 0) name += '.';
            for (let i = 1; i <= len && pos + i < data.length; i++) {
                name += String.fromCharCode(data[pos + i]);
            }
            pos += len + 1;
        }

        return { name, offset: returnPos !== -1 ? returnPos : pos };
    }

    _isHTTP(srcPort, dstPort) {
        const httpPorts = [80, 8080, 8000, 8888, 3000, 5000];
        return httpPorts.includes(srcPort) || httpPorts.includes(dstPort);
    }

    _isTLS(srcPort, dstPort, data, offset, len) {
        if (srcPort === 443 || dstPort === 443) return true;
        // Check TLS record header
        if (len >= 5 && data[offset] >= 20 && data[offset] <= 23) {
            const version = (data[offset + 1] << 8) | data[offset + 2];
            if (version >= 0x0300 && version <= 0x0304) return true;
        }
        return false;
    }

    _parseHTTPPayload(data, offset, len, result) {
        if (len <= 0) return;

        try {
            // Try to read first line as ASCII
            let firstLine = '';
            for (let i = 0; i < Math.min(len, 200); i++) {
                const c = data[offset + i];
                if (c === 0x0d || c === 0x0a) break;
                if (c >= 32 && c <= 126) firstLine += String.fromCharCode(c);
            }

            const httpMethods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH', 'CONNECT'];
            const isRequest = httpMethods.some(m => firstLine.startsWith(m + ' '));
            const isResponse = firstLine.startsWith('HTTP/');

            if (isRequest || isResponse) {
                result.protocol = 'HTTP';
                result.appProtocol = 'HTTP';
                result.appData = firstLine;
                result.info = `${result.ipSrc}:${result.srcPort} → ${result.ipDst}:${result.dstPort} | ${firstLine}`;
            }
        } catch (e) { /* ignore */ }
    }

    _parseTLSRecord(data, offset, len, result) {
        if (len < 5) return;
        const contentType = data[offset];
        const typeNames = { 20: 'Change Cipher Spec', 21: 'Alert', 22: 'Handshake', 23: 'Application Data' };
        const typeName = typeNames[contentType] || `Type ${contentType}`;

        if (contentType === 22 && len >= 6) {
            const hsType = data[offset + 5];
            const hsNames = { 1: 'Client Hello', 2: 'Server Hello', 11: 'Certificate', 12: 'Server Key Exchange', 14: 'Server Hello Done', 16: 'Client Key Exchange' };
            const hsName = hsNames[hsType] || `HS Type ${hsType}`;
            result.info += ` | ${hsName}`;
        } else {
            result.info += ` | ${typeName}`;
        }
    }

    _formatMAC(data, offset) {
        const parts = [];
        for (let i = 0; i < 6; i++) {
            parts.push(data[offset + i].toString(16).padStart(2, '0'));
        }
        return parts.join(':');
    }

    _formatIPv6(data, offset) {
        const groups = [];
        for (let i = 0; i < 8; i++) {
            groups.push(((data[offset + i * 2] << 8) | data[offset + i * 2 + 1]).toString(16));
        }
        // Simple compression: replace longest run of 0s with ::
        let ipv6 = groups.join(':');
        ipv6 = ipv6.replace(/(^|:)0(:0)+(:|$)/, '::');
        return ipv6;
    }

    /**
     * Get hex dump of packet data
     */
    static hexDump(data, maxBytes = 256) {
        const lines = [];
        const len = Math.min(data.length, maxBytes);

        for (let i = 0; i < len; i += 16) {
            const offset = i.toString(16).padStart(6, '0');
            let hex = '';
            let ascii = '';

            for (let j = 0; j < 16; j++) {
                if (i + j < len) {
                    const b = data[i + j];
                    hex += b.toString(16).padStart(2, '0') + ' ';
                    ascii += (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.';
                } else {
                    hex += '   ';
                    ascii += ' ';
                }
                if (j === 7) hex += ' ';
            }

            lines.push({ offset, hex: hex.trimEnd(), ascii });
        }

        return lines;
    }
}

// Export for use
window.PcapParser = PcapParser;
