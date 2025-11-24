// 相关环境变量(都是可选的)
// PASSWORD | password  访问密码
// SUB_PATH | subpath  订阅路径
// PROXYIP  | proxyip  代理IP
// UUID     | uuid     UUID
// WS_PATH  | ws_path  WebSocket路径，默认为 /?ed=2560

import { connect } from 'cloudflare:sockets';

let subPath = 'link';     // 节点订阅路径,不修改将使用uuid作为订阅路径
let password = '123456';  // 主页密码,建议修改或添加 PASSWORD环境变量
let proxyIP = '';  // proxyIP
let yourUUID = '5zz1x235-1195-41pd-953v-0aafbd917b63'; // UUID,建议修改或添加环境便量
let wsPath = '/?ed=2560';  // WebSocket路径，可以修改为 /、/vless、/path 等 

// CDN 
let cfip = [ // 格式:优选域名:端口#备注名称、优选IP:端口#备注名称、[ipv6优选]:端口#备注名称、优选域名#备注 
    'mfa.gov.ua#白嫖1', 'saas.sin.fan#白嫖2', 'store.ubi.com#白嫖3','cf.130519.xyz#白嫖4','cf.008500.xyz#白嫖5', 
    'cf.090227.xyz#白嫖6', 'cf.877774.xyz#白嫖7','cdns.doon.eu.org#白嫖8','sub.danfeng.eu.org#白嫖9','cf.zhetengsha.eu.org#白嫖10'
];  // 在此感谢各位大佬维护的优选域名

function closeSocketQuietly(socket) { 
    try { 
        if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CLOSING) {
            socket.close(); 
        }
    } catch (error) {} 
}

function formatIdentifier(arr, offset = 0) {
    const hex = [...arr.slice(offset, offset + 16)].map(b => b.toString(16).padStart(2, '0')).join('');
    return `${hex.substring(0,8)}-${hex.substring(8,12)}-${hex.substring(12,16)}-${hex.substring(16,20)}-${hex.substring(20)}`;
}

function base64ToArray(b64Str) {
    if (!b64Str) return { error: null };
    try { 
        const binaryString = atob(b64Str.replace(/-/g, '+').replace(/_/g, '/'));
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return { earlyData: bytes.buffer, error: null }; 
    } catch (error) { 
        return { error }; 
    }
}

function parsePryAddress(serverStr) {
    if (!serverStr) return null;
    serverStr = serverStr.trim();
    // 解析 S5
    if (serverStr.startsWith('socks://') || serverStr.startsWith('socks5://')) {
        const urlStr = serverStr.replace(/^socks:\/\//, 'socks5://');
        try {
            const url = new URL(urlStr);
            return {
                type: 'socks5',
                host: url.hostname,
                port: parseInt(url.port) || 1080,
                username: url.username ? decodeURIComponent(url.username) : '',
                password: url.password ? decodeURIComponent(url.password) : ''
            };
        } catch (e) {
            return null;
        }
    }
    
    // 解析 HTTP
    if (serverStr.startsWith('http://') || serverStr.startsWith('https://')) {
        try {
            const url = new URL(serverStr);
            return {
                type: 'http',
                host: url.hostname,
                port: parseInt(url.port) || (serverStr.startsWith('https://') ? 443 : 80),
                username: url.username ? decodeURIComponent(url.username) : '',
                password: url.password ? decodeURIComponent(url.password) : ''
            };
        } catch (e) {
            return null;
        }
    }
    
    // 处理 IPv6 格式 [host]:port
    if (serverStr.startsWith('[')) {
        const closeBracket = serverStr.indexOf(']');
        if (closeBracket > 0) {
            const host = serverStr.substring(1, closeBracket);
            const rest = serverStr.substring(closeBracket + 1);
            if (rest.startsWith(':')) {
                const port = parseInt(rest.substring(1), 10);
                if (!isNaN(port) && port > 0 && port <= 65535) {
                    return { type: 'direct', host, port };
                }
            }
            return { type: 'direct', host, port: 443 };
        }
    }

    const lastColonIndex = serverStr.lastIndexOf(':');
    
    if (lastColonIndex > 0) {
        const host = serverStr.substring(0, lastColonIndex);
        const portStr = serverStr.substring(lastColonIndex + 1);
        const port = parseInt(portStr, 10);
        
        if (!isNaN(port) && port > 0 && port <= 65535) {
            return { type: 'direct', host, port };
        }
    }
    
    return { type: 'direct', host: serverStr, port: 443 };
}

function isSpeedTestSite(hostname) {
    const speedTestDomains = ['speedtest.net','fast.com','speedtest.cn','speed.cloudflare.com', 'ovo.speedtestcustom.com'];
    if (speedTestDomains.includes(hostname)) {
        return true;
    }

    for (const domain of speedTestDomains) {
        if (hostname.endsWith('.' + domain) || hostname === domain) {
            return true;
        }
    }
    return false;
}


export default {
	/**
	 * @param {import("@cloudflare/workers-types").Request} request
	 * @param {{UUID: string, uuid: string, PROXYIP: string, PASSWORD: string, PASSWD: string, password: string, proxyip: string, proxyIP: string, SUB_PATH: string, subpath: string}} env
	 * @param {import("@cloudflare/workers-types").ExecutionContext} ctx
	 * @returns {Promise<Response>}
	 */
    async fetch(request, env, ctx) {
        try {
            // 初始化变量（确保在每次请求时都有默认值）
            let currentSubPath = subPath;
            let currentPassword = password;
            let currentProxyIP = proxyIP;
            let currentUUID = yourUUID;
            let currentWsPath = wsPath;

            // 优先读取环境变量
            if (env) {
                // 先读取 UUID（因为 subPath 可能需要使用它）
                currentUUID = env.UUID || env.uuid || currentUUID;
                
                // 读取其他环境变量
                currentPassword = env.PASSWORD || env.PASSWD || env.password || currentPassword;
                currentSubPath = env.SUB_PATH || env.subpath || currentSubPath;
                currentWsPath = env.WS_PATH || env.ws_path || currentWsPath;
            }

            // 如果 subPath 是 'link' 或空，使用 UUID 作为路径
			if (currentSubPath === 'link' || currentSubPath === '') {
				currentSubPath = currentUUID;
			}

            // 读取代理 IP 配置
            if (env && (env.PROXYIP || env.proxyip || env.proxyIP)) {
                const servers = (env.PROXYIP || env.proxyip || env.proxyIP).split(',').map(s => s.trim());
                currentProxyIP = servers[0]; 
            }
            
            const url = new URL(request.url);
            const pathname = url.pathname;
            
            let pathProxyIP = null;
            if (pathname.startsWith('/proxyip=')) {
                try {
                    pathProxyIP = decodeURIComponent(pathname.substring(9)).trim();
                } catch (e) {
                    // 忽略错误
                }

                if (pathProxyIP && !request.headers.get('Upgrade')) {
                    currentProxyIP = pathProxyIP;
                    return new Response(`set proxyIP to: ${currentProxyIP}\n\n`, {
                        headers: { 
                            'Content-Type': 'text/plain; charset=utf-8',
                            'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
                        },
                    });
                }
            }

            if (request.headers.get('Upgrade') === 'websocket') {
                let wsPathProxyIP = null;
                if (pathname.startsWith('/proxyip=')) {
                    try {
                        wsPathProxyIP = decodeURIComponent(pathname.substring(9)).trim();
                    } catch (e) {
                        // 忽略错误
                    }
                }
                
                const customProxyIP = wsPathProxyIP || url.searchParams.get('proxyip') || request.headers.get('proxyip');
                try {
                    return await handleVlsRequest(request, customProxyIP, currentUUID, currentProxyIP);
                } catch (error) {
                    return new Response(`WebSocket connection failed: ${error.message}`, { status: 500 });
                }
            } else if (request.method === 'GET') {
                if (url.pathname === '/') {
                    return getHomePage(request, currentPassword, currentUUID, currentSubPath);
                }
                
                if (url.pathname.toLowerCase().includes(`/${currentSubPath.toLowerCase()}`)) {
                    const currentDomain = url.hostname;
                    const vlsHeader = 'v' + 'l' + 'e' + 's' + 's';
                    
                    // 生成 VLESS 节点
                    const vlsLinks = cfip.map(cdnItem => {
                        let host, port = 8443, nodeName = '';
                        if (cdnItem.includes('#')) {
                            const parts = cdnItem.split('#');
                            cdnItem = parts[0];
                            nodeName = parts[1];
                        }

                        if (cdnItem.startsWith('[') && cdnItem.includes(']:')) {
                            const ipv6End = cdnItem.indexOf(']:');
                            host = cdnItem.substring(0, ipv6End + 1); 
                            const portStr = cdnItem.substring(ipv6End + 2); 
                            port = parseInt(portStr) || 8443;
                        } else if (cdnItem.includes(':')) {
                            const parts = cdnItem.split(':');
                            host = parts[0];
                            port = parseInt(parts[1]) || 8443;
                        } else {
                            host = cdnItem;
                        }
                        
                        const vlsNodeName = nodeName ? `${nodeName}` : `Workers`;
                        // URL 编码路径（encodeURIComponent 会自动编码特殊字符）
                        const encodedPath = encodeURIComponent(currentWsPath);
                        return `${vlsHeader}://${currentUUID}@${host}:${port}?encryption=none&security=tls&sni=${currentDomain}&fp=firefox&allowInsecure=1&type=ws&host=${currentDomain}&path=${encodedPath}#${vlsNodeName}`;
                    });
                    
                    const linksText = vlsLinks.join('\n');
                    const base64Content = btoa(unescape(encodeURIComponent(linksText)));
                    return new Response(base64Content, {
                        headers: { 
                            'Content-Type': 'text/plain; charset=utf-8',
                            'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
                        },
                    });
                }
            }
            return new Response('Not Found', { status: 404 });
        } catch (err) {
            return new Response(`Internal Server Error: ${err.message}`, { status: 500 });
        }
    },
};

/**
 * 
 * @param {import("@cloudflare/workers-types").Request} request
 * @param {string|null} customProxyIP
 * @param {string} uuid
 * @param {string} defaultProxyIP
 */
async function handleVlsRequest(request, customProxyIP, uuid, defaultProxyIP) {
    const wssPair = new WebSocketPair();
    const [clientSock, serverSock] = Object.values(wssPair);
    serverSock.accept();
    let remoteConnWrapper = { socket: null };
    let isDnsQuery = false;
    const earlyData = request.headers.get('sec-websocket-protocol') || '';
    const readable = makeReadableStr(serverSock, earlyData);

    // 强化优化：添加智能数据流缓冲和随机化，减少异常的数据传输模式
    let dataBuffer = new Uint8Array(0);
    let lastProcessTime = Date.now();
    // 动态刷新间隔，模拟真实网络波动
    const getBufferFlushInterval = () => {
        const base = 8; // 基础间隔
        const variation = Math.random() * 8; // 0-8ms 变化
        return base + variation;
    };
    let bufferFlushInterval = getBufferFlushInterval();
    
    readable.pipeTo(new WritableStream({
        async write(chunk) {
            try {
                // 强化优化：智能数据处理，添加随机化和自然延迟
                const now = Date.now();
                const timeSinceLastProcess = now - lastProcessTime;
                
                // 动态更新刷新间隔，模拟网络波动
                bufferFlushInterval = getBufferFlushInterval();
                
                // 如果距离上次处理时间太短，合并到缓冲区
                if (timeSinceLastProcess < bufferFlushInterval && dataBuffer.length > 0) {
                    const newBuffer = new Uint8Array(dataBuffer.length + chunk.byteLength);
                    newBuffer.set(dataBuffer);
                    newBuffer.set(chunk, dataBuffer.length);
                    dataBuffer = newBuffer;
                    // 如果缓冲区太大，立即处理（添加小随机延迟）
                    if (dataBuffer.length > 16384) {
                        chunk = dataBuffer;
                        dataBuffer = new Uint8Array(0);
                        // 添加小延迟，模拟网络处理时间
                        await new Promise(resolve => setTimeout(resolve, Math.random() * 3));
                        lastProcessTime = Date.now();
                    } else {
                        // 添加随机等待时间
                        const waitTime = bufferFlushInterval - timeSinceLastProcess + Math.random() * 5;
                        await new Promise(resolve => setTimeout(resolve, Math.max(0, waitTime)));
                        return; // 等待下次刷新
                    }
                } else {
                    // 处理缓冲区数据
                    if (dataBuffer.length > 0) {
                        const combinedChunk = new Uint8Array(dataBuffer.length + chunk.byteLength);
                        combinedChunk.set(dataBuffer);
                        combinedChunk.set(chunk, dataBuffer.length);
                        chunk = combinedChunk;
                        dataBuffer = new Uint8Array(0);
                    }
                    // 添加微小的随机延迟，模拟真实网络处理
                    if (chunk.byteLength > 0) {
                        await new Promise(resolve => setTimeout(resolve, Math.random() * 2));
                    }
                    lastProcessTime = Date.now();
                }
                
                if (isDnsQuery) {
                    await forwardataudp(chunk, serverSock, null);
                    return;
                }
                
                // 如果连接已建立，直接转发数据
                if (remoteConnWrapper.socket) {
                    let writer = null;
                    try {
                        writer = remoteConnWrapper.socket.writable.getWriter();
                        await writer.write(chunk);
                    } catch (writeErr) {
                        // 改进错误处理：检查错误类型，区分可恢复和不可恢复的错误
                        const errorMsg = writeErr.message || String(writeErr);
                        if (errorMsg.includes('closed') || errorMsg.includes('aborted') || errorMsg.includes('canceled') || errorMsg.includes('broken')) {
                            // 连接已关闭或损坏，清理连接
                            if (remoteConnWrapper.socket) {
                                try {
                                    remoteConnWrapper.socket.close();
                                } catch (e) {}
                                remoteConnWrapper.socket = null;
                            }
                            closeSocketQuietly(serverSock);
                        } else {
                            // 其他错误，可能是临时错误，尝试继续
                            // 强化优化：使用指数退避重试，模拟真实网络重试模式
                            const retryAttempts = Math.min(3, Math.floor(Math.random() * 3) + 1);
                            const baseDelay = 50;
                            const backoffDelay = baseDelay * Math.pow(2, retryAttempts - 1) + Math.random() * 50;
                            await new Promise(resolve => setTimeout(resolve, backoffDelay));
                            // 不立即关闭连接，给连接恢复的机会
                        }
                    } finally {
                        // 确保 writer 锁总是被释放
                        if (writer) {
                            try {
                                writer.releaseLock();
                            } catch (e) {
                                // 忽略释放锁时的错误
                            }
                        }
                    }
                    return;
                }
                
                // 解析 VLESS 协议
                const { hasError, message, addressType, port, hostname, rawIndex, version, isUDP } = parseVLsPacketHeader(chunk, uuid);
                if (hasError) {
                    throw new Error(message);
                }

                if (isSpeedTestSite(hostname)) {
                    throw new Error('Speedtest site is blocked');
                }

                if (isUDP) {
                    if (port === 53) {
                        isDnsQuery = true;
                        const respHeader = new Uint8Array([version[0], 0]);
                        const rawData = chunk.slice(rawIndex);
                        await forwardataudp(rawData, serverSock, respHeader);
                        return;
                    } else {
                        throw new Error('UDP is not supported');
                    }
                }
                
                const respHeader = new Uint8Array([version[0], 0]);
                const rawData = chunk.slice(rawIndex);
                await forwardataTCP(hostname, port, rawData, serverSock, respHeader, remoteConnWrapper, customProxyIP, defaultProxyIP);
            } catch (err) {
                // 改进错误处理：区分不同类型的错误
                const errorMsg = err.message || String(err);
                // 只有严重错误才关闭连接，临时错误不关闭
                if (errorMsg.includes('Invalid') || errorMsg.includes('blocked') || errorMsg.includes('not supported')) {
                    // 协议错误或策略错误，需要关闭
                    closeSocketQuietly(serverSock);
                    if (remoteConnWrapper.socket) {
                        try {
                            remoteConnWrapper.socket.close();
                        } catch (e) {}
                        remoteConnWrapper.socket = null;
                    }
                }
                // 其他错误可能是临时性的，不立即关闭连接
            }
        },
    })).catch((err) => {
        // 改进：只在连接打开时关闭
        if (serverSock.readyState === WebSocket.OPEN || serverSock.readyState === WebSocket.CLOSING) {
            closeSocketQuietly(serverSock);
        }
        if (remoteConnWrapper.socket) {
            try {
                remoteConnWrapper.socket.close();
            } catch (e) {}
            remoteConnWrapper.socket = null;
        }
    });

    return new Response(null, { status: 101, webSocket: clientSock });
}


async function connect2Socks5(proxyConfig, targetHost, targetPort, initialData) {
    const { host, port, username, password } = proxyConfig;
    const socket = connect({ hostname: host, port: port });
    const writer = socket.writable.getWriter();
    const reader = socket.readable.getReader();
    
    try {
        const authMethods = username && password ? 
            new Uint8Array([0x05, 0x02, 0x00, 0x02]) :
            new Uint8Array([0x05, 0x01, 0x00]); 
        
        await writer.write(authMethods);
        const methodResponse = await reader.read();
        if (methodResponse.done || methodResponse.value.byteLength < 2) {
            throw new Error('S5 method selection failed');
        }
        
        const selectedMethod = new Uint8Array(methodResponse.value)[1];
        if (selectedMethod === 0x02) {
            if (!username || !password) {
                throw new Error('S5 requires authentication');
            }
            const userBytes = new TextEncoder().encode(username);
            const passBytes = new TextEncoder().encode(password);
            const authPacket = new Uint8Array(3 + userBytes.length + passBytes.length);
            authPacket[0] = 0x01; 
            authPacket[1] = userBytes.length;
            authPacket.set(userBytes, 2);
            authPacket[2 + userBytes.length] = passBytes.length;
            authPacket.set(passBytes, 3 + userBytes.length);
            await writer.write(authPacket);
            const authResponse = await reader.read();
            if (authResponse.done || new Uint8Array(authResponse.value)[1] !== 0x00) {
                throw new Error('S5 authentication failed');
            }
        } else if (selectedMethod !== 0x00) {
            throw new Error(`S5 unsupported auth method: ${selectedMethod}`);
        }
        
        const hostBytes = new TextEncoder().encode(targetHost);
        const connectPacket = new Uint8Array(7 + hostBytes.length);
        connectPacket[0] = 0x05;
        connectPacket[1] = 0x01;
        connectPacket[2] = 0x00; 
        connectPacket[3] = 0x03; 
        connectPacket[4] = hostBytes.length;
        connectPacket.set(hostBytes, 5);
        new DataView(connectPacket.buffer).setUint16(5 + hostBytes.length, targetPort, false);
        await writer.write(connectPacket);
        const connectResponse = await reader.read();
        if (connectResponse.done || new Uint8Array(connectResponse.value)[1] !== 0x00) {
            throw new Error('S5 connection failed');
        }
        
        await writer.write(initialData);
        writer.releaseLock();
        reader.releaseLock();
        return socket;
    } catch (error) {
        writer.releaseLock();
        reader.releaseLock();
        throw error;
    }
}

async function connect2Http(proxyConfig, targetHost, targetPort, initialData) {
    const { host, port, username, password } = proxyConfig;
    const socket = connect({ hostname: host, port: port });
    const writer = socket.writable.getWriter();
    const reader = socket.readable.getReader();
    try {
        let connectRequest = `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\n`;
        connectRequest += `Host: ${targetHost}:${targetPort}\r\n`;
        
        if (username && password) {
            const auth = btoa(`${username}:${password}`);
            connectRequest += `Proxy-Authorization: Basic ${auth}\r\n`;
        }
        
        // 优化：使用更真实的 User-Agent，减少检测
        const userAgents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        ];
        const randomUA = userAgents[Math.floor(Math.random() * userAgents.length)];
        connectRequest += `User-Agent: ${randomUA}\r\n`;
        connectRequest += `Connection: keep-alive\r\n`;
        connectRequest += `Accept: */*\r\n`;
        connectRequest += '\r\n';
        await writer.write(new TextEncoder().encode(connectRequest));
        let responseBuffer = new Uint8Array(0);
        let headerEndIndex = -1;
        let bytesRead = 0;
        const maxHeaderSize = 8192;
        
        while (headerEndIndex === -1 && bytesRead < maxHeaderSize) {
            const { done, value } = await reader.read();
            if (done) {
                throw new Error('Connection closed before receiving HTTP response');
            }
            const newBuffer = new Uint8Array(responseBuffer.length + value.length);
            newBuffer.set(responseBuffer);
            newBuffer.set(value, responseBuffer.length);
            responseBuffer = newBuffer;
            bytesRead = responseBuffer.length;
            
            for (let i = 0; i < responseBuffer.length - 3; i++) {
                if (responseBuffer[i] === 0x0d && responseBuffer[i + 1] === 0x0a &&
                    responseBuffer[i + 2] === 0x0d && responseBuffer[i + 3] === 0x0a) {
                    headerEndIndex = i + 4;
                    break;
                }
            }
        }
        
        if (headerEndIndex === -1) {
            throw new Error('Invalid HTTP response');
        }
        
        const headerText = new TextDecoder().decode(responseBuffer.slice(0, headerEndIndex));
        const statusLine = headerText.split('\r\n')[0];
        const statusMatch = statusLine.match(/HTTP\/\d\.\d\s+(\d+)/);
        
        if (!statusMatch) {
            throw new Error(`Invalid response: ${statusLine}`);
        }
        
        const statusCode = parseInt(statusMatch[1]);
        if (statusCode < 200 || statusCode >= 300) {
            throw new Error(`Connection failed: ${statusLine}`);
        }
        
        // HTTP connection established
        
        await writer.write(initialData);
        writer.releaseLock();
        reader.releaseLock();
        
        return socket;
    } catch (error) {
        try { 
            writer.releaseLock(); 
        } catch (e) {}
        try { 
            reader.releaseLock(); 
        } catch (e) {}
        try { 
            socket.close(); 
        } catch (e) {}
        throw error;
    }
}

async function forwardataTCP(host, portNum, rawData, ws, respHeader, remoteConnWrapper, customProxyIP, defaultProxyIP) {
    // 强化优化：添加更自然的随机延迟，模拟真实网络环境
    // 使用指数分布模拟真实网络延迟
    const baseDelay = 15; // 基础延迟
    const randomFactor = Math.random();
    const exponentialDelay = baseDelay * (1 + Math.log(1 + randomFactor * 9)); // 15-150ms 指数分布延迟
    const jitter = (Math.random() - 0.5) * 20; // ±10ms 抖动
    const totalDelay = Math.max(5, Math.floor(exponentialDelay + jitter));
    await new Promise(resolve => setTimeout(resolve, totalDelay));
    
    async function connectDirect(address, port, data) {
        // 强化优化：添加连接建立前的随机延迟，模拟真实网络
        const connectDelay = Math.random() * 30 + 5; // 5-35ms 随机延迟
        await new Promise(resolve => setTimeout(resolve, connectDelay));
        
        const remoteSock = connect({ hostname: address, port: port });
        const writer = remoteSock.writable.getWriter();
        
        // 强化优化：数据写入前添加小延迟，模拟网络传输时间
        await new Promise(resolve => setTimeout(resolve, Math.random() * 5 + 1));
        await writer.write(data);
        writer.releaseLock();
        return remoteSock;
    }
    
    let proxyConfig = null;
    let shouldUseProxy = false;
    if (customProxyIP) {
        proxyConfig = parsePryAddress(customProxyIP);
        if (proxyConfig && (proxyConfig.type === 'socks5' || proxyConfig.type === 'http' || proxyConfig.type === 'https')) {
            shouldUseProxy = true;
        } else if (!proxyConfig) {
            proxyConfig = parsePryAddress(defaultProxyIP) || { type: 'direct', host: defaultProxyIP, port: 443 };
        }
    } else {
        proxyConfig = parsePryAddress(defaultProxyIP) || { type: 'direct', host: defaultProxyIP, port: 443 };
        if (proxyConfig.type === 'socks5' || proxyConfig.type === 'http' || proxyConfig.type === 'https') {
            shouldUseProxy = true;
        }
    }
    
    async function connecttoPry() {
        let newSocket;
        if (proxyConfig.type === 'socks5') {
            newSocket = await connect2Socks5(proxyConfig, host, portNum, rawData);
        } else if (proxyConfig.type === 'http' || proxyConfig.type === 'https') {
            newSocket = await connect2Http(proxyConfig, host, portNum, rawData);
        } else {
            newSocket = await connectDirect(proxyConfig.host, proxyConfig.port, rawData);
        }
        
        remoteConnWrapper.socket = newSocket;
        // 强化优化：智能连接关闭处理，添加随机延迟，模拟真实网络关闭模式
        newSocket.closed.catch(() => {}).then(() => {
            // 使用随机延迟关闭，避免固定模式被检测
            const closeDelay = 150 + Math.random() * 200; // 150-350ms 随机延迟
            setTimeout(() => {
                if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CLOSING) {
                    closeSocketQuietly(ws);
                }
            }, closeDelay);
        });
        connectStreams(newSocket, ws, respHeader, null);
    }
    
    if (shouldUseProxy) {
        try {
            await connecttoPry();
        } catch (err) {
            throw err;
        }
    } else {
        try {
            const initialSocket = await connectDirect(host, portNum, rawData);
            remoteConnWrapper.socket = initialSocket;
            connectStreams(initialSocket, ws, respHeader, connecttoPry);  // 恢复备用连接功能
        } catch (err) {
            // 直连失败时，尝试使用备用连接（代理或备用地址）
            // 这对于访问 Cloudflare CDN 网站很重要
            if (defaultProxyIP) {
                await connecttoPry();
            } else {
                throw err;
            }
        }
    }
}

function parseVLsPacketHeader(chunk, token) {
    if (chunk.byteLength < 24) return { hasError: true, message: 'Invalid data' };
    const version = new Uint8Array(chunk.slice(0, 1));
    if (formatIdentifier(new Uint8Array(chunk.slice(1, 17))) !== token) return { hasError: true, message: 'Invalid uuid' };
    const optLen = new Uint8Array(chunk.slice(17, 18))[0];
    const cmd = new Uint8Array(chunk.slice(18 + optLen, 19 + optLen))[0];
    let isUDP = false;
    if (cmd === 1) {} else if (cmd === 2) { isUDP = true; } else { return { hasError: true, message: 'Invalid command' }; }
    const portIdx = 19 + optLen;
    const port = new DataView(chunk.slice(portIdx, portIdx + 2)).getUint16(0);
    let addrIdx = portIdx + 2, addrLen = 0, addrValIdx = addrIdx + 1, hostname = '';
    const addressType = new Uint8Array(chunk.slice(addrIdx, addrValIdx))[0];
    switch (addressType) {
        case 1: 
            addrLen = 4; 
            hostname = new Uint8Array(chunk.slice(addrValIdx, addrValIdx + addrLen)).join('.'); 
            break;
        case 2: 
            addrLen = new Uint8Array(chunk.slice(addrValIdx, addrValIdx + 1))[0]; 
            addrValIdx += 1; 
            hostname = new TextDecoder().decode(chunk.slice(addrValIdx, addrValIdx + addrLen)); 
            break;
        case 3: 
            addrLen = 16; 
            const ipv6 = []; 
            const ipv6View = new DataView(chunk.slice(addrValIdx, addrValIdx + addrLen)); 
            for (let i = 0; i < 8; i++) ipv6.push(ipv6View.getUint16(i * 2).toString(16)); 
            hostname = ipv6.join(':'); 
            break;
        default: 
            return { hasError: true, message: `Invalid address type: ${addressType}` };
    }
    if (!hostname) return { hasError: true, message: `Invalid address: ${addressType}` };
    return { hasError: false, addressType, port, hostname, isUDP, rawIndex: addrValIdx + addrLen, version };
}

function makeReadableStr(socket, earlyDataHeader) {
    let cancelled = false;
    return new ReadableStream({
        start(controller) {
            socket.addEventListener('message', (event) => { 
                if (!cancelled) controller.enqueue(event.data); 
            });
            socket.addEventListener('close', () => { 
                if (!cancelled) { 
                    closeSocketQuietly(socket); 
                    controller.close(); 
                } 
            });
            socket.addEventListener('error', (err) => controller.error(err));
            const { earlyData, error } = base64ToArray(earlyDataHeader);
            if (error) controller.error(error); 
            else if (earlyData) controller.enqueue(earlyData);
        },
        cancel() { 
            cancelled = true; 
            closeSocketQuietly(socket); 
        }
    });
}

async function connectStreams(remoteSocket, webSocket, headerData, retryFunc) {
    let header = headerData, hasData = false;
    let lastSendTime = Date.now();
    let buffer = new Uint8Array(0);
    // 强化优化：动态最小发送间隔，模拟真实网络波动
    const getMinSendInterval = () => {
        const base = 3; // 基础间隔
        const variation = Math.random() * 7; // 0-7ms 变化
        return base + variation;
    };
    let minSendInterval = getMinSendInterval();
    
    try {
        await remoteSocket.readable.pipeTo(
            new WritableStream({
                async write(chunk, controller) {
                    try {
                        hasData = true;
                        // 优化：添加数据缓冲和流量整形，减少异常模式
                        const now = Date.now();
                        const timeSinceLastSend = now - lastSendTime;
                        
                        // 改进连接状态检查：在 CLOSING 状态也尝试发送，避免数据丢失
                        if (webSocket.readyState === WebSocket.CLOSED) {
                            // 连接已完全关闭，停止处理
                            return;
                        }
                        // 在 OPEN 或 CLOSING 状态都尝试发送数据
                        if (webSocket.readyState === WebSocket.OPEN || webSocket.readyState === WebSocket.CLOSING) {
                            try {
                                // 强化优化：智能数据流处理，添加随机化和自然延迟
                                minSendInterval = getMinSendInterval(); // 动态更新间隔
                                
                                // 数据包大小随机化：随机分片大包，模拟真实网络
                                const maxChunkSize = 8192 + Math.floor(Math.random() * 4096); // 8-12KB 随机
                                if (chunk.byteLength > maxChunkSize) {
                                    // 大包分片发送，添加随机延迟
                                    const chunks = [];
                                    for (let i = 0; i < chunk.byteLength; i += maxChunkSize) {
                                        chunks.push(chunk.slice(i, Math.min(i + maxChunkSize, chunk.byteLength)));
                                    }
                                    for (let i = 0; i < chunks.length; i++) {
                                        if (i > 0) {
                                            // 分片之间添加随机延迟
                                            await new Promise(resolve => setTimeout(resolve, Math.random() * 5 + 2));
                                        }
                                        if (header && i === 0) {
                                            const response = new Uint8Array(header.length + chunks[i].byteLength);
                                            response.set(header, 0);
                                            response.set(chunks[i], header.length);
                                            webSocket.send(response.buffer);
                                            header = null;
                                        } else {
                                            webSocket.send(chunks[i]);
                                        }
                                        lastSendTime = Date.now();
                                    }
                                    return;
                                }
                                
                                // 正常大小的数据包处理
                                if (timeSinceLastSend < minSendInterval && buffer.length > 0) {
                                    // 合并到缓冲区
                                    const newBuffer = new Uint8Array(buffer.length + chunk.byteLength);
                                    newBuffer.set(buffer);
                                    newBuffer.set(chunk, buffer.length);
                                    buffer = newBuffer;
                                    // 等待最小间隔（添加随机抖动）
                                    const waitTime = minSendInterval - timeSinceLastSend + Math.random() * 3;
                                    await new Promise(resolve => setTimeout(resolve, Math.max(0, waitTime)));
                                    chunk = buffer;
                                    buffer = new Uint8Array(0);
                                } else if (timeSinceLastSend < minSendInterval) {
                                    // 即使没有缓冲区，也添加小延迟
                                    await new Promise(resolve => setTimeout(resolve, minSendInterval - timeSinceLastSend + Math.random() * 2));
                                }
                                
                                if (header) { 
                                    const response = new Uint8Array(header.length + chunk.byteLength);
                                    response.set(header, 0);
                                    response.set(chunk, header.length);
                                    webSocket.send(response.buffer); 
                                    header = null; 
                                } else { 
                                    webSocket.send(chunk); 
                                }
                                lastSendTime = Date.now();
                            } catch (sendErr) {
                                // 发送失败，检查是否是连接已关闭
                                if (webSocket.readyState === WebSocket.CLOSED) {
                                    return;
                                }
                                // 其他发送错误，可能是临时问题，继续尝试
                            }
                        }
                    } catch (writeErr) {
                        // 优化：减少错误日志，避免暴露特征
                        if (webSocket.readyState === WebSocket.CLOSED) {
                            // 连接已关闭，正常处理
                            return;
                        }
                        // 其他错误，不中断数据流，继续处理
                    }
                },
                abort() {
                    // 改进：只在连接打开时关闭
                    if (webSocket.readyState === WebSocket.OPEN || webSocket.readyState === WebSocket.CLOSING) {
                        closeSocketQuietly(webSocket);
                    }
                },
            })
        ).catch((err) => { 
            // 改进错误处理：不立即关闭，检查连接状态
            if (webSocket.readyState === WebSocket.OPEN || webSocket.readyState === WebSocket.CLOSING) {
                closeSocketQuietly(webSocket);
            }
        });
        
        if (!hasData && retryFunc) {
            await retryFunc();
        }
    } catch (err) {
        closeSocketQuietly(webSocket);
        throw err;
    }
}

async function forwardataudp(udpChunk, webSocket, respHeader) {
    try {
        const tcpSocket = connect({ hostname: '8.8.4.4', port: 53 });
        let vlessHeader = respHeader;
        const writer = tcpSocket.writable.getWriter();
        await writer.write(udpChunk);
        writer.releaseLock();
        await tcpSocket.readable.pipeTo(new WritableStream({
            async write(chunk) {
                if (webSocket.readyState === WebSocket.OPEN) {
                    if (vlessHeader) { 
                        const response = new Uint8Array(vlessHeader.length + chunk.byteLength);
                        response.set(vlessHeader, 0);
                        response.set(chunk, vlessHeader.length);
                        webSocket.send(response.buffer);
                        vlessHeader = null; 
                    } else { 
                        webSocket.send(chunk); 
                    }
                }
            },
        }));
    } catch (error) {
        // console.error('UDP forward error:', error);
    }
}

/**
 * @param {import("@cloudflare/workers-types").Request} request
 * @param {string} currentPassword
 * @param {string} currentUUID
 * @param {string} currentSubPath
 * @returns {Response}
 */
function getHomePage(request, currentPassword, currentUUID, currentSubPath) {
	const url = request.headers.get('Host');
	const baseUrl = `https://${url}`;
	const urlObj = new URL(request.url);
	const providedPassword = urlObj.searchParams.get('password');
	if (providedPassword) {
		if (providedPassword === currentPassword) {
			return getMainPageContent(url, baseUrl, currentPassword, currentUUID, currentSubPath);
		} else {
			return getLoginPage(url, baseUrl, true);
		}
	}
	return getLoginPage(url, baseUrl, false);
}

/**
 * 获取登录页面
 * @param {string} url 
 * @param {string} baseUrl 
 * @param {boolean} showError 
 * @returns {Response}
 */
function getLoginPage(url, baseUrl, showError = false) {
	const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Workers Service - 登录</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #7dd3ca 0%, #a17ec4 100%);
            height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #333;
            margin: 0;
            padding: 0;
            overflow: hidden;
        }
        
        .login-container {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 40px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
            max-width: 400px;
            width: 95%;
            text-align: center;
        }
        
        .logo {
            margin-bottom: -20px;
            background: linear-gradient(135deg, #7dd3ca 0%, #a17ec4 100%)
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        
        .title {
            font-size: 1.8rem;
            margin-bottom: 8px;
            color: #2d3748;
        }
        
        .subtitle {
            color: #718096;
            margin-bottom: 30px;
            font-size: 1rem;
        }
        
        .form-group {
            margin-bottom: 20px;
            text-align: left;
        }
        
        .form-label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: #4a5568;
        }
        
        .form-input {
            width: 100%;
            padding: 12px 16px;
            border: 2px solid #e2e8f0;
            border-radius: 8px;
            font-size: 1rem;
            transition: border-color 0.3s ease;
            background: #fff;
        }
        
        .form-input:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }
        
        .btn-login {
            width: 100%;
            padding: 12px 20px;
            background: linear-gradient(135deg, #12cd9e 0%, #a881d0 100%);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        
        .btn-login:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(0, 0, 0, 0.1);
        }
        
        .error-message {
            background: #fed7d7;
            color: #c53030;
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 20px;
            border-left: 4px solid #e53e3e;
        }
        
        .footer {
            margin-top: 20px;
            color: #718096;
            font-size: 0.9rem;
        }
        
        @media (max-width: 480px) {
            .login-container {
                padding: 30px 20px;
                margin: 10px;
            }
            
            .logo {
                font-size: 2.5rem;
            }
            
            .title {
                font-size: 1.5rem;
            }
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo"><img src="https://hhh.xdm66.qzz.io/img/cfpng.png" alt="Logo"></div>
        <h1 class="title">Workers Service</h1>
        <p class="subtitle">请输入密码以访问服务</p>
        
        ${showError ? '<div class="error-message">密码错误,请重试</div>' : ''}
        
        <form onsubmit="handleLogin(event)">
            <div class="form-group">
                <input 
                    type="password" 
                    id="password" 
                    name="password" 
                    class="form-input" 
                    placeholder="请输入密码"
                    required
                    autofocus
                >
            </div>
            <button type="submit" class="btn-login">登录</button>
        </form>
        

    </div>
    
    <script>
        function handleLogin(event) {
            event.preventDefault();
            const password = document.getElementById('password').value;
            const currentUrl = new URL(window.location);
            currentUrl.searchParams.set('password', password);
            window.location.href = currentUrl.toString();
        }
    </script>
</body>
</html>`;

	return new Response(html, {
		status: 200,
		headers: {
			'Content-Type': 'text/html;charset=utf-8',
			'Cache-Control': 'no-cache, no-store, must-revalidate',
		},
	});
}

/**
 * 获取主页内容(密码验证通过后显示)
 * @param {string} url 
 * @param {string} baseUrl 
 * @returns {Response}
 */
function getMainPageContent(url, baseUrl, currentPassword, currentUUID, currentSubPath) {
	const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Workers Service</title>
    <link rel="stylesheet" href="https://hhh.xdm66.qzz.io/img/all.min.css">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #66ead7 0%, #9461c8 100%);
            height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #333;
            margin: 0;
            padding: 0;
            overflow: hidden;
        }
        
        .container {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 20px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
            max-width: 800px;
            width: 95%;
            max-height: 90vh;
            text-align: center;
            overflow-y: auto;
            display: flex;
            flex-direction: column;
            position: relative;
        }
        
        .logout-btn {
            position: fixed;
            top: 20px;
            right: 20px;
            background: #a7a0d8;
            color: #dc2929;
            border: none;
            border-radius: 8px;
            padding: 8px 16px;
            font-size: 0.9rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            gap: 6px;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
            z-index: 1000;
        }
        
        .logout-btn i {
            font-size: 0.9rem;
        }
        
        .logout-btn:hover {
            background: #e0e0e0;
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
        }
        
        .logo {
            margin-bottom: -10px;
            background: linear-gradient(45deg, #667eea, #764ba2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        
        .title {
            font-size: 1.8rem;
            margin-bottom: 8px;
            color: #2d3748;
        }
        
        .subtitle {
            color: #718096;
            margin-bottom: 15px;
            font-size: 1rem;
        }
        
        .info-card {
            background: #f7fafc;
            border-radius: 12px;
            padding: 15px;
            margin: 10px 0;
            border-left: 3px solid #6ed8c9;
            flex: 1;
            overflow-y: auto;
        }
        
        .info-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 6px 0;
            border-bottom: 1px solid #e2e8f0;
            font-size: 0.9rem;
        }
        
        .info-item:last-child {
            border-bottom: none;
        }
        
        .label {
            font-weight: 600;
            color: #4a5568;
        }
        
        .value {
            color:rgb(20, 23, 29);
            font-family: 'Courier New', monospace;
            background: #edf2f7;
            padding: 4px 8px;
            border-radius: 6px;
            font-size: 0.8rem;
        }
        
        .button-group {
            display: flex;
            gap: 10px;
            justify-content: center;
            flex-wrap: wrap;
            margin: 15px 0;
        }
        
        .btn {
            padding: 10px 20px;
            border: none;
            border-radius: 8px;
            font-size: 0.9rem;
            font-weight: 600;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
            transition: all 0.3s ease;
            min-width: 100px;
        }
        
        .btn-primary {
            background: linear-gradient(45deg, #667eea, #764ba2);
            color: white;
        }
        
        .btn-secondary {
            background: linear-gradient(45deg, #68e3d6, #906cc9);
            color: #001379;
        }
        
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(0, 0, 0, 0.1);
        }
        
        .status {
            display: inline-block;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background: #48bb78;
            margin-right: 8px;
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.5; }
            100% { opacity: 1; }
        }
        
        .footer {
            margin-top: 10px;
            color: #718096;
            font-size: 1rem;
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 8px;
        }
        
        .footer-links {
            display: flex;
            align-items: center;
            gap: 15px;
            flex-wrap: wrap;
            justify-content: center;
        }
        
        .footer-link {
            color: #667eea;
            text-decoration: none;
            display: flex;
            align-items: center;
            gap: 6px;
            font-weight: 500;
            transition: all 0.3s ease;
            padding: 4px 8px;
            border-radius: 6px;
        }
        
        .footer-link:hover {
            background: rgba(102, 126, 234, 0.1);
            transform: translateY(-1px);
        }
        
        .github-icon {
            width: 16px;
            height: 16px;
            fill: currentColor;
        }
        
        .toast {
            position: fixed;
            top: 20px;
            right: 20px;
            background:rgb(244, 252, 247);
            border-left: 4px solid #48bb78;
            border-radius: 8px;
            padding: 12px 16px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
            display: flex;
            align-items: center;
            gap: 10px;
            z-index: 1000;
            opacity: 0;
            transform: translateX(100%);
            transition: all 0.3s ease;
            max-width: 300px;
        }
        
        .toast.show {
            opacity: 1;
            transform: translateX(0);
        }
        
        .toast-icon {
            width: 20px;
            height: 20px;
            background: #48bb78;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 12px;
            font-weight: bold;
        }
        
        .toast-message {
            color: #2d3748;
            font-size: 14px;
            font-weight: 500;
        }
        
        @media (max-width: 768px) {
            .container {
                padding: 15px;
                margin: 10px;
                max-height: 95vh;
            }
            
            .logout-btn {
                top: 15px;
                right: 15px;
                padding: 6px 12px;
                font-size: 0.8rem;
            }
            
            .logo {
                font-size: 2rem;
            }
            
            .title {
                font-size: 1.5rem;
            }
            
            .button-group {
                flex-direction: column;
                align-items: center;
                gap: 8px;
            }
            
            .btn {
                width: 100%;
                max-width: 180px;
                padding: 8px 16px;
                font-size: 0.85rem;
            }
            
            .info-item {
                flex-direction: column;
                align-items: flex-start;
                gap: 4px;
            }
            
            .value {
                word-break: break-all;
                font-size: 0.8rem;
            }
            
            .footer-links {
                flex-direction: column;
                gap: 10px;
            }
        }
        
        @media (max-width: 480px) {
            .container {
                padding: 10px;
                margin: 5px;
            }
            
            .info-card {
                padding: 10px;
            }
            
            .toast {
                top: 10px;
                right: 10px;
                left: 10px;
                max-width: none;
                transform: translateY(-100%);
            }
            
            .toast.show {
                transform: translateY(0);
            }
        }
    </style>
</head>
<body>
    <button onclick="logout()" class="logout-btn">
        <i class="fas fa-sign-out-alt"></i>
        <span>退出登录</span>
    </button>
    
    <div class="container">
        <div class="logo"><img src="https://hhh.xdm66.qzz.io/img/cfpng.png" alt="Logo"></div>
        <h1 class="title">Workers Service</h1>
        <p class="subtitle">基于 Cloudflare Workers 的高性能网络服务 (VLESS)</p>
        
        <div class="info-card">
            <div class="info-item">
                <span class="label">服务状态</span>
                <span class="value"><span class="status"></span>运行中</span>
            </div>
            <div class="info-item">
                <span class="label">主机地址</span>
                <span class="value">${url}</span>
            </div>
            <div class="info-item">
                <span class="label">UUID</span>
                <span class="value">${currentUUID || 'N/A'}</span>
            </div>
            <div class="info-item">
                <span class="label">V2rayN订阅地址</span>
                <span class="value">${baseUrl}/${currentSubPath || 'link'}</span>
            </div>
            <div class="info-item">
                <span class="label">Clash订阅地址</span>
                <span class="value">https://sublink.xdm66.qzz.io/clash?config=${baseUrl}/${currentSubPath || 'link'}</span>
            </div>
            <div class="info-item">
                <span class="label">singbox订阅地址</span>
                <span class="value">https://sublink.xdm66.qzz.io/singbox?config=${baseUrl}/${currentSubPath || 'link'}</span>
            </div>
        </div>
        
        <div class="button-group">
            <button onclick="copySingboxSubscription()" class="btn btn-secondary">复制singbox订阅链接</button>
            <button onclick="copyClashSubscription()" class="btn btn-secondary">复制Clash订阅链接</button>
            <button onclick="copySubscription()" class="btn btn-secondary">复制V2rayN订阅链接</button>
        </div>
        
        <div class="footer">
            <div class="footer-links">
                <a href="https://github.com/eooce/Cloudflare-proxy" target="_blank" class="footer-link">
                    <svg class="github-icon" viewBox="0 0 24 24">
                        <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.479-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
                    </svg>
                    <span>根据eooce/Cloudflare-proxy修改而来</span>
                </a>
            </div>
        </div>
    </div>
    
    <script>
        function showToast(message) {
            const existingToast = document.querySelector('.toast');
            if (existingToast) {
                existingToast.remove();
            }
            
            const toast = document.createElement('div');
            toast.className = 'toast';
            
            const icon = document.createElement('div');
            icon.className = 'toast-icon';
            icon.textContent = '✓';
            
            const messageDiv = document.createElement('div');
            messageDiv.className = 'toast-message';
            messageDiv.textContent = message;
            
            toast.appendChild(icon);
            toast.appendChild(messageDiv);
            
            document.body.appendChild(toast);
            
            setTimeout(() => {
                toast.classList.add('show');
            }, 10);
            
            setTimeout(() => {
                toast.classList.remove('show');
                setTimeout(() => {
                    if (toast.parentNode) {
                        toast.parentNode.removeChild(toast);
                    }
                }, 300);
            }, 1500);
        }
        
        function copySubscription() {
            const configUrl = '${baseUrl}/${currentSubPath || 'link'}';
            navigator.clipboard.writeText(configUrl).then(() => {
                showToast('V2rayN订阅链接已复制到剪贴板!');
            }).catch(() => {
                const textArea = document.createElement('textarea');
                textArea.value = configUrl;
                document.body.appendChild(textArea);
                textArea.select();
                document.execCommand('copy');
                document.body.removeChild(textArea);
                showToast('V2rayN订阅链接已复制到剪贴板!');
            });
        }
        
        function copyClashSubscription() {
            const clashUrl = 'https://sublink.xdm66.qzz.io/clash?config=${baseUrl}/${currentSubPath || 'link'}';
            navigator.clipboard.writeText(clashUrl).then(() => {
                showToast('Clash订阅链接已复制到剪贴板!');
            }).catch(() => {
                const textArea = document.createElement('textarea');
                textArea.value = clashUrl;
                document.body.appendChild(textArea);
                textArea.select();
                document.execCommand('copy');
                document.body.removeChild(textArea);
                showToast('Clash订阅链接已复制到剪贴板!');
            });
        }
        
        function copySingboxSubscription() {
            const singboxUrl = 'https://sublink.xdm66.qzz.io/singbox?config=${baseUrl}/${currentSubPath || 'link'}';
            navigator.clipboard.writeText(singboxUrl).then(() => {
                showToast('singbox订阅链接已复制到剪贴板!');
            }).catch(() => {
                const textArea = document.createElement('textarea');
                textArea.value = singboxUrl;
                document.body.appendChild(textArea);
                textArea.select();
                document.execCommand('copy');
                document.body.removeChild(textArea);
                showToast('singbox订阅链接已复制到剪贴板!');
            });
        }
        
        function logout() {
            if (confirm('确定要退出登录吗?')) {
                const currentUrl = new URL(window.location);
                currentUrl.searchParams.delete('password');
                window.location.href = currentUrl.toString();
            }
        }
    </script>
</body>
</html>`;

	return new Response(html, {
		status: 200,
		headers: {
			'Content-Type': 'text/html;charset=utf-8',
			'Cache-Control': 'no-cache, no-store, must-revalidate',
		},
	});
}
