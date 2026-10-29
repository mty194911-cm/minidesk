'use strict';
// MiniDesk web client: WebSocket -> AES-GCM -> WebCodecs H.264 -> canvas; touch/mouse/keyboard -> host.

// ---- protocol (mirror of protocol.py) ----
const VIDEO = 0x01, SCREEN = 0x02, CURSOR = 0x03, LAN = 0x04, PONG = 0x41, BYE = 0x7F;
const MOVE = 0x10, BUTTON = 0x11, WHEEL = 0x12, KEY = 0x20, TEXT = 0x21;
const ACK = 0x30, KEYFRAME = 0x31, CONFIG = 0x32, PING = 0x40, NOTE = 0x50;
const QUALITY_KBPS = [3000, 8000, 20000];  // caps: the host adapts the bitrate below them
// Served by the PC itself on its LAN port (not by the relay): every connection from this page is direct.
const ON_LAN = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(location.hostname);
const FPS = 60;

const $ = id => document.getElementById(id);
const stage = $('stage'), canvas = $('screen'), cursorEl = $('cursor'), ime = $('ime');
const kbdEl = $('kbd'), keysEl = $('keys'), previewEl = $('preview'), panel = $('panel');
const dock = $('dock'), fab = $('fab'), kbtn = $('kbtn');
const statsEl = $('stats'), toastEl = $('toast'), msgEl = $('msg');
const ctx2d = canvas.getContext('2d', { alpha: false, desynchronized: true });
const te = new TextEncoder(), td = new TextDecoder();
const clamp = (v, lo, hi) => Math.min(hi, Math.max(lo, v));
const esc = s => String(s).replace(/[&<>"']/g, c => `&#${c.charCodeAt(0)};`);  // device names come from links
const store = {
  get(k, d) {
    try { const v = localStorage.getItem('md.' + k); return v == null ? d : JSON.parse(v); } catch { return d; }
  },
  set(k, v) { try { localStorage.setItem('md.' + k, JSON.stringify(v)); } catch { /* private mode */ } },
};

// ---- crypto (mirror of secure.py) ----
const cat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let i = 0;
  for (const p of parts) { out.set(p, i); i += p.length; }
  return out;
};
const nonce = n => { const iv = new Uint8Array(12); new DataView(iv.buffer).setBigUint64(4, BigInt(n)); return iv; };
const b64d = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat(-s.length & 3)),
                                  c => c.charCodeAt(0));

class AuthError extends Error {}

async function handshake(recv, send, K) {
  const S = crypto.subtle;
  const kp = await S.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
  const cpub = new Uint8Array(await S.exportKey('raw', kp.publicKey));
  const nc = crypto.getRandomValues(new Uint8Array(16));
  send(cat(cpub, nc));
  const r = await recv();
  if (!r || r.length !== 113) throw new AuthError('host closed');
  const hpub = r.subarray(0, 65), ns = r.subarray(65, 81), tag = r.subarray(81);
  const T = cat(cpub, hpub, nc, ns);
  const mk = await S.importKey('raw', K, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
  if (!await S.verify('HMAC', mk, tag, cat(te.encode('minidesk host'), T))) throw new AuthError('bad host');
  send(new Uint8Array(await S.sign('HMAC', mk, cat(te.encode('minidesk client'), T))));
  const peer = await S.importKey('raw', hpub, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const shared = await S.deriveBits({ name: 'ECDH', public: peer }, kp.privateKey, 256);
  const hk = await S.importKey('raw', shared, 'HKDF', false, ['deriveBits']);
  const okm = new Uint8Array(await S.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: K, info: cat(te.encode('minidesk session'), T) }, hk, 512));
  const aes = k => S.importKey('raw', k, 'AES-GCM', false, ['encrypt', 'decrypt']);
  const rx = await aes(okm.subarray(0, 32)), tx = await aes(okm.subarray(32));
  // Sealed message = [u64 counter][ciphertext+tag]: over QUIC each video frame has its own stream, so messages
  // may arrive out of order. Replays are refused with a window of recently seen counters (as in secure.py).
  let ntx = 0, max = -1;
  const seen = new Set();
  return {
    open: async d => {
      const n = Number(new DataView(d.buffer, d.byteOffset, 8).getBigUint64(0));
      if (n <= max - 4096 || seen.has(n)) throw new AuthError('replay');
      seen.add(n);  // before the await: a concurrent copy must not pass the check too
      let plain;
      try { plain = new Uint8Array(await S.decrypt({ name: 'AES-GCM', iv: nonce(n) }, rx, d.subarray(8))); }
      catch (e) { seen.delete(n); throw e; }
      if (n > max) {
        max = n;
        if (seen.size > 8192) for (const s of seen) if (s <= n - 4096) seen.delete(s);
      }
      return plain;
    },
    seal: async d => {
      const n = ntx++;
      return cat(nonce(n).subarray(4), new Uint8Array(await S.encrypt({ name: 'AES-GCM', iv: nonce(n) }, tx, d)));
    },
  };
}

// ---- connection ----
// Paths, best first: LAN direct (rank 2, WebSocket to the PC itself), relay over UDP (rank 1, WebTransport/QUIC:
// a lost packet delays only its own frame, and the relay's congestion control does not collapse on random loss),
// relay over TCP (rank 0, WebSocket: for browsers or networks without UDP). They are dialled in parallel, and a
// better path that comes up later takes over.
const PATH_NAMES = ['经服务器·TCP', '经服务器·UDP', '局域网直连'];
let devices = {}, target = null, conn = null, generation = 0, retry = 0, retryTimer = 0, wakeLock = null;
let lastEnd = '';  // why the previous connection broke: reported to the PC (host.log) over the next one

function post(pt) {
  const c = conn;
  if (!c) return;
  // Sealing is async; chaining keeps the counters in send order.
  c.chain = c.chain.then(async () => c.send(await c.chan.seal(pt))).catch(() => {});
}
function msg(type, size, fill) {
  const b = new Uint8Array(1 + size);
  b[0] = type;
  if (fill) fill(new DataView(b.buffer));
  return b;
}
const sendConfig = () => post(msg(CONFIG, 5, v => {
  v.setUint32(1, QUALITY_KBPS[quality], true);
  v.setUint8(5, FPS);
}));
const sendButton = (b, down) => {
  flushMove();
  post(msg(BUTTON, 2, v => { v.setUint8(1, b); v.setUint8(2, down ? 1 : 0); }));
};
const click = b => { sendButton(b, true); sendButton(b, false); };
const sendKey = (sc, down) => post(msg(KEY, 3, v => { v.setUint16(1, sc, true); v.setUint8(3, down ? 1 : 0); }));
let lastKeyReq = 0;
function requestKey() {
  const now = performance.now();
  if (now - lastKeyReq > 500) { lastKeyReq = now; post(msg(KEYFRAME, 0)); }
}

function inbox() {  // incoming messages of one connection; recv() resolves null once it is closed
  const queue = [], waiters = [];
  return {
    push: d => waiters.length ? waiters.shift()(d) : queue.push(d),
    recv: () => queue.length ? Promise.resolve(queue.shift()) : new Promise(r => waiters.push(r)),
    end: () => waiters.splice(0).forEach(w => w(null)),
  };
}

function dial(url, K, rank) {  // WebSocket: LAN direct, or the relay's TCP fallback
  return new Promise((resolve, reject) => {
    const sock = new WebSocket(url);
    sock.binaryType = 'arraybuffer';
    const box = inbox();
    const c = { rank, direct: rank === 2, recv: box.recv, chain: Promise.resolve(), onclose: null,
                send: d => { if (sock.readyState === 1) sock.send(d); }, close: () => sock.close() };
    const timer = setTimeout(() => sock.close(), rank === 2 ? 2500 : 10000);
    sock.onmessage = e => box.push(new Uint8Array(e.data));
    sock.onclose = e => {
      c.why ??= `WebSocket 关闭 ${e.code}${e.reason ? ' ' + e.reason : ''}`;
      clearTimeout(timer);
      box.end();
      reject(Object.assign(new Error('closed'), { code: e.code }));
      c.onclose?.(e.code);
    };
    sock.onopen = async () => {
      try {
        c.chan = await handshake(c.recv, c.send, K);
        clearTimeout(timer);
        resolve(c);
      } catch (e) {
        reject(e);
        sock.close();
      }
    };
  });
}

const frame = d => {  // [u32 len][payload]
  const o = new Uint8Array(4 + d.length);
  new DataView(o.buffer).setUint32(0, d.length, true);
  o.set(d, 4);
  return o;
};
async function readFramed(readable, push) {  // [u32 len][payload] messages from one stream
  const r = readable.getReader();
  let buf = new Uint8Array(0);
  try {
    for (;;) {
      const { value, done } = await r.read();
      if (done) return;
      buf = buf.length ? cat(buf, value) : value;
      while (buf.length >= 4) {
        const n = new DataView(buf.buffer, buf.byteOffset, 4).getUint32(0, true);
        if (buf.length < 4 + n) break;
        push(buf.slice(4, 4 + n));
        buf = buf.subarray(4 + n);
      }
    }
  } catch { /* session closed */ }
}
async function readFrames(streams, push) {  // one video frame per unidirectional stream
  const r = streams.getReader();
  try {
    for (;;) {
      const { value, done } = await r.read();
      if (done) return;
      new Response(value).arrayBuffer().then(b => push(new Uint8Array(b)), () => {});
    }
  } catch { /* session closed */ }
}

async function dialUdp(K) {  // WebTransport to the relay; its certificate is pinned by the hash /wt publishes
  const info = await (await fetch('wt', { cache: 'no-store' })).json();
  const wt = new WebTransport(`https://${location.hostname}:${info.port}/wt/c/${target}`, {
    serverCertificateHashes: info.hashes.map(h => ({ algorithm: 'sha-256', value: b64d(h) })),
    congestionControl: 'low-latency',
  });
  const box = inbox();
  let closed = false;
  const c = { rank: 1, direct: false, recv: box.recv, chain: Promise.resolve(), onclose: null, send: () => {},
              close: () => { try { wt.close(); } catch { /* already closed */ } } };
  // Generous: TCP comes up meanwhile anyway (after 2 s), and UDP takes over whenever it is ready. A congested
  // evening link needed more than 6 s for relay pairing plus the handshake round trips.
  const timer = setTimeout(c.close, 15000);
  wt.closed.then(i => { c.why ??= `WebTransport 关闭 ${i?.closeCode ?? '-'} ${i?.reason || ''}`; },
                 e => { c.why ??= `WebTransport 出错 ${e?.message || e}`; })
    .finally(() => { closed = true; clearTimeout(timer); box.end(); c.onclose?.(0); });
  try {
    await wt.ready;
    const ctl = await wt.createBidirectionalStream();
    const writer = ctl.writable.getWriter();
    c.send = d => { if (!closed) writer.write(frame(d)).catch(() => {}); };
    readFramed(ctl.readable, box.push);
    readFrames(wt.incomingUnidirectionalStreams, box.push);
    c.chan = await handshake(c.recv, c.send, K);
  } catch (e) {
    c.close();
    throw e;
  }
  clearTimeout(timer);
  return c;
}

function open() {
  clearTimeout(retryTimer);
  retryTimer = 0;
  const gen = ++generation;
  dropConn();
  const dev = devices[target], K = b64d(dev.key);
  status(`正在连接 ${esc(dev.name)}…`);
  const pending = new Set();
  let err = null, tcpStarted = false;
  const attempt = p => {
    pending.add(p);
    p.then(c => {
      if (gen === generation && (!conn || c.rank > conn.rank)) use(c);
      else c.close();
    }, e => {
      if (e instanceof AuthError || !(err instanceof AuthError) && (e?.code || !err)) err = e;  // most telling
    }).finally(() => {
      pending.delete(p);
      if (gen !== generation || conn || pending.size) return;
      if (err instanceof AuthError) {
        showMsg('配对已失效。在电脑上运行 <code>python host.py --pair</code> 重新扫码。', [['忘记这台电脑', forget]]);
      } else {
        lost(err?.code === 4404 ? '电脑不在线' : '连不上服务器');
      }
    });
  };
  const tcp = () => {
    if (tcpStarted) return;
    tcpStarted = true;
    const ws = location.protocol === 'https:' ? 'wss' : 'ws';
    attempt(dial(`${ws}://${location.host}/ws/c/${target}`, K, ON_LAN ? 2 : 0));
  };
  if (ON_LAN || !window.WebTransport) {
    tcp();
  } else {
    attempt(dialUdp(K).catch(e => { tcp(); throw e; }));  // no UDP in this browser or network: TCP
    setTimeout(() => { if (gen === generation && !conn) tcp(); }, 2000);  // UDP slow to come up: TCP meanwhile
  }
  for (const u of ON_LAN ? [] : dev.lan || []) attempt(dial(u, K, 2));
}

function use(c) {
  const old = conn;
  conn = c;
  old?.close();
  resetDecoder();
  resetReorder();
  retry = 0;
  hideMsg();
  toast(c.rank === 2 && !ON_LAN ? '已切换到局域网直连' : '', 1500);
  renderLan();
  c.since = c.lastRx = performance.now();
  c.onclose = code => {
    if (conn !== c) return;
    conn = null;
    if (code === 4001) ended('电脑端断开了连接');
    else if (code === 4002) ended('已在另一台设备上连接');
    else { lastEnd = endReport(c); lost('连接已断开'); }
  };
  sendConfig();
  if (lastEnd) { post(cat(Uint8Array.of(NOTE), te.encode(lastEnd))); lastEnd = ''; }
  keepAwake();
  (async () => {
    try {
      for (let d; (d = await c.recv());) {
        c.lastRx = performance.now();
        const m = await c.chan.open(d);
        if (conn === c) handle(m);
      }
    } catch (e) {  // undecryptable message
      c.why ??= `${e?.name || '出错'}: ${e?.message || e}`;
      c.close();
    }
  })();
}

// On 4G the UDP session went completely silent every 1-2 minutes and stayed so, while a new one connected within
// a second (carriers stall single UDP flows): after 3 s of silence dial a fresh one alongside, and switch to it if
// the old one is still silent by then.
function rescue(c) {
  if (c.rescuing) return;
  c.rescuing = true;
  const gen = generation;
  dialUdp(b64d(devices[target].key)).then(n => {
    const idle = performance.now() - c.lastRx;
    if (gen !== generation || conn !== c || idle < 3000) return n.close();
    c.why = `${(idle / 1000).toFixed(1)} 秒没收到任何数据，已换新的 UDP 连接`;
    lastEnd = endReport(c);
    use(n);
  }, () => {}).finally(() => { c.rescuing = false; });
}

function endReport(c) {
  const now = performance.now(), net = navigator.connection;
  return `${PATH_NAMES[c.rank]} 用了 ${((now - c.since) / 1000).toFixed(0)} 秒后断开：${c.why || '原因不明'}；` +
    `最后收到数据在 ${((now - c.lastRx) / 1000).toFixed(1)} 秒前` + (net ? `，网络 ${net.type || net.effectiveType}` : '') +
    (document.hidden ? '，页面在后台' : '') + (navigator.onLine === false ? '，手机离线' : '');
}

function tryDirect(urls) {  // on a relay session: switch to the LAN path as soon as one answers
  const gen = generation, K = b64d(devices[target].key);
  const tries = urls.map(u => dial(u, K, 2).then(c => {
    if (gen === generation && conn && conn.rank < 2) use(c);
    else c.close();
  }));
  // Browsers may block a public page from reaching private addresses (Chrome's Local Network Access):
  // then point to the LAN entry, which loads the page from the PC itself.
  Promise.allSettled(tries).then(rs => {
    if (gen === generation && conn && conn.rank < 2 && rs.every(r => r.status === 'rejected') && !lanHinted) {
      lanHinted = true;
      toast('在同一 Wi-Fi？菜单 →「局域网直连」更快', 5000);
    }
  });
}
let lanHinted = false;

// LAN entry: open the page from the PC's LAN address, carrying the pairing in the fragment (never sent anywhere).
function renderLan() {
  const dev = target && devices[target], box = $('lan');
  const urls = !ON_LAN && dev?.lan || [];
  box.hidden = !urls.length || conn?.rank === 2;
  $('lanbtns').replaceChildren(...urls.map(u => {
    const host = new URL(u.replace(/^wss:/, 'https:')).host, b = document.createElement('button');
    b.textContent = host.split(':')[0];
    b.onclick = () => { location.href = `https://${host}/#${target}.${dev.key}.${encodeURIComponent(dev.name)}`; };
    return b;
  }));
}

function dropConn() {
  const c = conn;
  conn = null;
  c?.close();
  resetDecoder();
  releaseAll();
}

function lost(text) {
  resetDecoder();
  const delay = retry ? Math.min(1000 * 2 ** (retry - 1), 15000) : 300;
  retry++;
  status(`${text}，正在重连…`, [['立即重连', open], ['选择电脑', start]]);
  retryTimer = setTimeout(open, delay);
}

function disconnect() {
  ended(`已断开 ${esc(devices[target].name)}`);
}
function ended(html) {  // no automatic reconnect
  generation++;
  clearTimeout(retryTimer);
  retryTimer = 0;
  dropConn();
  everShown = false;
  showMsg(html, [['重新连接', open], ['选择电脑', start]]);
}

function forget() {
  delete devices[target];
  store.set('devices', devices);
  start();
}

function keepAwake() {
  if (!document.hidden) navigator.wakeLock?.request('screen').then(l => { wakeLock = l; }, () => {});
}

function handle(m) {
  const v = new DataView(m.buffer, m.byteOffset, m.byteLength);
  switch (m[0]) {
    case VIDEO: onVideo(m[1] === 1, v.getUint32(2, true), m.subarray(6)); break;
    case SCREEN: setScreen(v.getUint16(1, true), v.getUint16(3, true)); break;
    case CURSOR: onRemoteCursor(v.getInt16(1, true), v.getInt16(3, true)); break;
    case LAN: {
      const urls = JSON.parse(td.decode(m.subarray(1)));
      devices[target].lan = urls;
      store.set('devices', devices);
      renderLan();
      if (conn.rank < 2) tryDirect(urls);
      break;
    }
    case PONG: stats.rtt = performance.now() - v.getFloat64(1, true); break;
    case BYE: {  // the PC ended this session on purpose: do not reconnect by ourselves
      const code = v.getUint16(1, true);
      ended(code === 4001 ? '电脑端断开了连接' : '已在另一台设备上连接');
      break;
    }
  }
}

// ---- video ----
let decoder = null, W = 0, H = 0, everShown = false;
const stats = { frames: 0, bytes: 0, rtt: 0 };

function codecOf(au) {  // "avc1.PPCCLL" from the SPS in an Annex-B access unit
  for (let i = 0; i + 6 < au.length; i++) {
    if (au[i] === 0 && au[i + 1] === 0 && au[i + 2] === 1 && (au[i + 3] & 31) === 7) {
      return 'avc1.' + [au[i + 4], au[i + 5], au[i + 6]].map(b => b.toString(16).padStart(2, '0')).join('');
    }
  }
  return null;
}

function resetDecoder() {
  if (decoder && decoder.state !== 'closed') decoder.close();
  decoder = null;
}

function onFrame(f) {
  ctx2d.drawImage(f, 0, 0);
  f.close();
  stats.frames++;
  if (!everShown) { everShown = true; firstFrameHints(); }
}

// Over UDP every frame has its own stream, so frames can complete out of order: decode strictly in sequence.
// A keyframe that overtakes missing frames restarts from itself; a gap open for 1 s asks for a fresh keyframe.
let nextSeq = 0, gapTimer = 0;
const early = new Map();
function resetReorder() {
  nextSeq = 0;
  early.clear();
  clearTimeout(gapTimer);
  gapTimer = 0;
}
function onVideo(key, seq, au) {
  post(msg(ACK, 4, v => v.setUint32(1, seq, true)));
  stats.bytes += au.length;
  if (nextSeq && seq < nextSeq) return;  // late duplicate
  if (!nextSeq || (key && seq > nextSeq && !early.has(nextSeq))) {
    early.clear();
    nextSeq = seq;
  }
  early.set(seq, [key, au]);
  while (early.has(nextSeq)) {
    const [k, a] = early.get(nextSeq);
    early.delete(nextSeq++);
    decodeFrame(k, a);
  }
  if (!early.size) {
    clearTimeout(gapTimer);
    gapTimer = 0;
  } else if (!gapTimer) {
    gapTimer = setTimeout(() => { resetReorder(); resetDecoder(); requestKey(); }, 1000);
  }
}
function decodeFrame(key, au) {
  if (key && (!decoder || decoder.state !== 'configured')) {
    const codec = codecOf(au);
    if (codec) {
      resetDecoder();
      decoder = new VideoDecoder({ output: onFrame, error: () => { decoder = null; requestKey(); } });
      decoder.configure({ codec, optimizeForLatency: true });
    }
  }
  if (!decoder || decoder.state !== 'configured') return requestKey();
  decoder.decode(new EncodedVideoChunk({ type: key ? 'key' : 'delta', timestamp: performance.now() * 1000, data: au }));
}

function setScreen(w, h) {
  resetDecoder();  // the next keyframe reconfigures
  if (w === W && h === H) return;
  W = canvas.width = w;
  H = canvas.height = h;
  cur.x = clamp(cur.x, 0, W - 1);
  cur.y = clamp(cur.y, 0, H - 1);
  fit();
}

// ---- view: the canvas holds the full-resolution screen; zoom/pan is a GPU transform ----
// The fit area avoids notches/rounded corners; the visible area also excludes the soft keyboard and key bar,
// so the part of the screen being typed into can be panned above them.
const view = { s: 1, x: 0, y: 0 };
let atFit = true;
const probe = document.createElement('div');
probe.style.cssText = 'position:fixed;visibility:hidden;pointer-events:none;padding:env(safe-area-inset-top) ' +
  'env(safe-area-inset-right) env(safe-area-inset-bottom) env(safe-area-inset-left)';
document.body.append(probe);

function safeArea() {
  const s = getComputedStyle(probe);
  const t = parseFloat(s.paddingTop) || 0, r = parseFloat(s.paddingRight) || 0;
  const b = parseFloat(s.paddingBottom) || 0, l = parseFloat(s.paddingLeft) || 0;
  return { x: l, y: t, w: innerWidth - l - r, h: innerHeight - t - b };
}
function visibleArea() {
  const a = safeArea();
  if (kbdEl.classList.contains('show')) {
    const vv = window.visualViewport;
    a.h = (vv ? vv.height + vv.offsetTop : innerHeight) - kbdEl.offsetHeight - a.y;
  }
  return a;
}
const fitScale = () => { const a = safeArea(); return Math.min(a.w / W, a.h / H) || 1; };
const maxScale = () => Math.max(fitScale() * 6, 2);
const toRemote = (cx, cy) => [(cx - view.x) / view.s, (cy - view.y) / view.s];

function fit() {
  view.s = fitScale();
  atFit = true;
  applyView();
}
function applyView() {
  const a = visibleArea(), sw = W * view.s, sh = H * view.s;
  view.x = sw <= a.w ? a.x + (a.w - sw) / 2 : clamp(view.x, a.x + a.w - sw, a.x);
  view.y = sh <= a.h ? a.y + (a.h - sh) / 2 : clamp(view.y, a.y + a.h - sh, a.y);
  canvas.style.transform = `translate(${view.x}px,${view.y}px) scale(${view.s})`;
  drawCursor();
}
function zoomTo(s, cx, cy) {  // keep the screen point under (cx, cy) in place
  const [rx, ry] = toRemote(cx, cy);
  view.s = clamp(s, fitScale(), maxScale());
  view.x = cx - rx * view.s;
  view.y = cy - ry * view.s;
  atFit = false;
  applyView();
}

// ---- cursor: tracked locally (sub-pixel) so it moves with zero latency; the host's position is adopted when idle
const cur = { x: 0, y: 0 };
let showCursor = false, lastLocalMove = 0, moveDirty = false, sentX = -1, sentY = -1;
const wheel = { x: 0, y: 0 };
let fling = null;

function setCursor(x, y) {
  cur.x = clamp(x, 0, W - 1);
  cur.y = clamp(y, 0, H - 1);
  lastLocalMove = performance.now();
  moveDirty = true;
  drawCursor();
}
function onRemoteCursor(x, y) {
  if (performance.now() - lastLocalMove < 500) return;
  cur.x = x;
  cur.y = y;
  drawCursor();
}
const cursorScreen = () => [cur.x * view.s + view.x, cur.y * view.s + view.y];
function drawCursor() {
  const [x, y] = cursorScreen();
  cursorEl.style.display = showCursor && W ? 'block' : 'none';
  cursorEl.style.transform = `translate(${x - 1}px,${y - 1}px)`;
}
function follow() {  // keep the cursor inside the visible area
  const a = visibleArea(), m = 40, [x, y] = cursorScreen();
  if (x < a.x + m) view.x += a.x + m - x; else if (x > a.x + a.w - m) view.x -= x - (a.x + a.w - m);
  if (y < a.y + m) view.y += a.y + m - y; else if (y > a.y + a.h - m) view.y -= y - (a.y + a.h - m);
  applyView();
}
function flushMove() {
  if (!moveDirty) return;
  moveDirty = false;
  const x = Math.round(cur.x), y = Math.round(cur.y);
  if (x === sentX && y === sentY) return;
  sentX = x;
  sentY = y;
  post(msg(MOVE, 4, v => { v.setUint16(1, x, true); v.setUint16(3, y, true); }));
}
let lastTick = 0;
function tick(now) {  // input is coalesced to the display refresh rate
  const dt = Math.min(now - (lastTick || now), 50);
  lastTick = now;
  if (fling) {  // scroll momentum after a two-finger flick
    wheel.y += fling.vy * dt * 3;
    wheel.x -= fling.vx * dt * 3;
    const k = Math.pow(0.994, dt);
    fling.vx *= k;
    fling.vy *= k;
    if (Math.hypot(fling.vx, fling.vy) < 0.02) fling = null;
  }
  flushMove();
  const dx = Math.trunc(wheel.x), dy = Math.trunc(wheel.y);
  if (dx || dy) {
    wheel.x -= dx;
    wheel.y -= dy;
    post(msg(WHEEL, 4, v => {
      v.setInt16(1, clamp(dx, -32768, 32767), true);
      v.setInt16(3, clamp(dy, -32768, 32767), true);
    }));
  }
  requestAnimationFrame(tick);
}

function ripple(x, y, kind) {  // visual feedback for taps, right clicks and long-press
  const d = document.createElement('div');
  d.className = 'ripple ' + kind;
  d.style.left = x + 'px';
  d.style.top = y + 'px';
  d.addEventListener('animationend', () => d.remove());
  stage.append(d);
}

// ---- touch gestures ----
// trackpad: 1 finger moves the cursor, tap = click, long-press = right click or (then move) drag
// touch:    tap/drag where the finger is, long-press = right click
// both:     2-finger tap = right click, 2-finger drag = scroll (with momentum), pinch = zoom,
//           3-finger drag = pan the view, 3-finger tap = keyboard
const TAP_SLOP = 10, LONG_MS = 450;
const pts = new Map();
let g = null, mode = store.get('mode', 'trackpad'), sens = store.get('sens', 1);

function centroid() {
  let x = 0, y = 0;
  for (const p of pts.values()) { x += p.x; y += p.y; }
  return { x: x / pts.size, y: y / pts.size };
}
function endOneEarly() {  // a second finger arrived: undo what the first one started
  if (g?.n !== 1) return;
  clearTimeout(g.timer);
  if (g.down) sendButton(0, false);
}

function startOne(x, y) {
  g = { n: 1, x0: x, y0: y, lx: x, ly: y, lt: performance.now(), moved: false, long: false, down: false };
  if (mode === 'touch') setCursor(...toRemote(x, y));
  g.timer = setTimeout(() => {
    if (g?.n !== 1 || g.moved) return;
    g.long = true;
    navigator.vibrate?.(15);
    ripple(x, y, 'hold');
  }, LONG_MS);
}
function moveOne(x, y) {
  const now = performance.now(), dx = x - g.lx, dy = y - g.ly, dt = Math.max(now - g.lt, 1);
  g.lx = x;
  g.ly = y;
  g.lt = now;
  if (!g.moved && Math.hypot(x - g.x0, y - g.y0) > TAP_SLOP) {
    g.moved = true;
    clearTimeout(g.timer);
    if (mode === 'touch' || g.long) { sendButton(0, true); g.down = true; }
  }
  if (!g.moved) return;
  if (mode === 'touch') {
    setCursor(...toRemote(x, y));
  } else {
    // Pointer acceleration by finger speed (px/ms): slow = precise, fast = far. Scaled by zoom so the
    // cursor tracks what you see.
    const v = Math.hypot(dx, dy) / dt;
    const gain = sens * clamp(0.55 + 0.9 * v, 0.55, 3.2) / view.s;
    setCursor(cur.x + dx * gain, cur.y + dy * gain);
    follow();
  }
}
function endOne() {
  clearTimeout(g.timer);
  if (g.down) return sendButton(0, false);
  if (g.moved) return;
  const [x, y] = mode === 'touch' ? [g.x0, g.y0] : cursorScreen();
  click(g.long ? 1 : 0);
  ripple(x, y, g.long ? 'right' : 'tap');
}

function startTwo() {
  endOneEarly();
  const c = centroid(), [a, b] = [...pts.values()];
  g = { n: 2, c0: c, lc: c, lt: performance.now(), d0: Math.hypot(a.x - b.x, a.y - b.y), s0: view.s,
        t0: performance.now(), kind: null, vx: 0, vy: 0 };
}
function moveTwo() {
  const [a, b] = [...pts.values()], c = centroid(), d = Math.hypot(a.x - b.x, a.y - b.y);
  const now = performance.now(), dt = Math.max(now - g.lt, 1);
  if (!g.kind) {
    if (Math.abs(d - g.d0) > 18) { g.kind = 'pinch'; g.d0 = d; g.s0 = view.s; }
    else if (Math.hypot(c.x - g.c0.x, c.y - g.c0.y) > 10) g.kind = 'scroll';
    else return;
  }
  const dx = c.x - g.lc.x, dy = c.y - g.lc.y;
  if (g.kind === 'scroll') {  // natural scrolling: content follows the fingers
    wheel.y += dy * 3;
    wheel.x -= dx * 3;
    g.vx = 0.6 * g.vx + 0.4 * dx / dt;
    g.vy = 0.6 * g.vy + 0.4 * dy / dt;
  } else {  // zoom around the fingers, and pan with them
    view.x += dx;
    view.y += dy;
    zoomTo(g.s0 * d / g.d0, c.x, c.y);
  }
  g.lc = c;
  g.lt = now;
}
function endTwo() {
  if (g.kind === 'scroll' && performance.now() - g.lt < 80) fling = { vx: g.vx, vy: g.vy };
  else if (!g.kind && performance.now() - g.t0 < 350) {
    const [x, y] = mode === 'touch' ? [g.c0.x, g.c0.y] : cursorScreen();
    if (mode === 'touch') { setCursor(...toRemote(x, y)); }
    click(1);
    ripple(x, y, 'right');
  }
}

function startThree() {
  endOneEarly();
  const c = centroid();
  g = { n: 3, c0: c, lc: c, t0: performance.now(), moved: false };
}
function moveThree() {
  const c = centroid();
  if (!g.moved && Math.hypot(c.x - g.c0.x, c.y - g.c0.y) > 12) g.moved = true;
  if (g.moved) {
    view.x += c.x - g.lc.x;
    view.y += c.y - g.lc.y;
    atFit = false;
    applyView();
  }
  g.lc = c;
}
function endThree() {
  if (!g.moved && performance.now() - g.t0 < 400) toggleKeyboard();
}

// ---- pointer events (touch, pen, mouse) ----
const MOUSE_BUTTON = [0, 2, 1];  // DOM left/middle/right -> host left/middle/right
let autoFullscreenDone = false;

stage.addEventListener('pointerdown', e => {
  togglePanel(false);
  if (!conn) return;
  fling = null;
  if (e.pointerType === 'mouse') {
    stage.setPointerCapture(e.pointerId);  // touch pointers are captured implicitly
    showCursor = false;
    setCursor(...toRemote(e.clientX, e.clientY));
    if (e.button < 3) sendButton(MOUSE_BUTTON[e.button], true);
    return;
  }
  showCursor = true;
  pts.set(e.pointerId, { x: e.clientX, y: e.clientY });
  if (pts.size === 1) startOne(e.clientX, e.clientY);
  else if (pts.size === 2) startTwo();
  else if (pts.size === 3) startThree();
  drawCursor();
});
stage.addEventListener('pointermove', e => {
  if (!conn) return;
  if (e.pointerType === 'mouse') return setCursor(...toRemote(e.clientX, e.clientY));
  const p = pts.get(e.pointerId);
  if (!p || !g) return;
  p.x = e.clientX;
  p.y = e.clientY;
  if (g.n === 1) moveOne(p.x, p.y);
  else if (g.n === 2 && pts.size === 2) moveTwo();
  else if (g.n === 3 && pts.size >= 3) moveThree();
});
function pointerEnd(e) {
  if (e.pointerType === 'mouse') {
    if (conn && e.button < 3 && e.type === 'pointerup') sendButton(MOUSE_BUTTON[e.button], false);
    return;
  }
  if (e.type === 'pointerup' && !autoFullscreenDone && document.fullscreenEnabled && !document.fullscreenElement) {
    autoFullscreenDone = true;  // first touch goes immersive (Android); needs pointerup, which counts as a user gesture
    toggleFullscreen();
  }
  if (!pts.delete(e.pointerId) || pts.size || !g) return;  // act when the last finger lifts
  if (conn && e.type === 'pointerup') [endOne, endTwo, endThree][g.n - 1]();
  else clearTimeout(g.timer);
  g = null;
}
stage.addEventListener('pointerup', pointerEnd);
stage.addEventListener('pointercancel', pointerEnd);
stage.addEventListener('wheel', e => {
  e.preventDefault();
  if (e.ctrlKey) return zoomTo(view.s * Math.exp(-e.deltaY * 0.002), e.clientX, e.clientY);  // also trackpad pinch
  const k = e.deltaMode ? 40 : 1.2;  // lines or pixels -> 120 per notch
  wheel.y -= e.deltaY * k;
  wheel.x += e.deltaX * k;
}, { passive: false });
stage.addEventListener('contextmenu', e => e.preventDefault());
// Tapping the screen must not take focus from the textarea (that would close the soft keyboard).
stage.addEventListener('touchstart', e => e.preventDefault(), { passive: false });

// ---- keyboard ----
const SC = Object.fromEntries((
  'Escape:1 Digit1:2 Digit2:3 Digit3:4 Digit4:5 Digit5:6 Digit6:7 Digit7:8 Digit8:9 Digit9:a Digit0:b Minus:c Equal:d ' +
  'Backspace:e Tab:f KeyQ:10 KeyW:11 KeyE:12 KeyR:13 KeyT:14 KeyY:15 KeyU:16 KeyI:17 KeyO:18 KeyP:19 BracketLeft:1a ' +
  'BracketRight:1b Enter:1c ControlLeft:1d KeyA:1e KeyS:1f KeyD:20 KeyF:21 KeyG:22 KeyH:23 KeyJ:24 KeyK:25 KeyL:26 ' +
  'Semicolon:27 Quote:28 Backquote:29 ShiftLeft:2a Backslash:2b KeyZ:2c KeyX:2d KeyC:2e KeyV:2f KeyB:30 KeyN:31 KeyM:32 ' +
  'Comma:33 Period:34 Slash:35 ShiftRight:36 NumpadMultiply:37 AltLeft:38 Space:39 CapsLock:3a F1:3b F2:3c F3:3d F4:3e ' +
  'F5:3f F6:40 F7:41 F8:42 F9:43 F10:44 ScrollLock:46 Numpad7:47 Numpad8:48 Numpad9:49 NumpadSubtract:4a Numpad4:4b ' +
  'Numpad5:4c Numpad6:4d NumpadAdd:4e Numpad1:4f Numpad2:50 Numpad3:51 Numpad0:52 NumpadDecimal:53 IntlBackslash:56 ' +
  'F11:57 F12:58 NumpadEnter:e01c ControlRight:e01d NumpadDivide:e035 PrintScreen:e037 AltRight:e038 Home:e047 ' +
  'ArrowUp:e048 PageUp:e049 ArrowLeft:e04b ArrowRight:e04d End:e04f ArrowDown:e050 PageDown:e051 Insert:e052 ' +
  'Delete:e053 MetaLeft:e05b MetaRight:e05c ContextMenu:e05d'
).split(' ').map(p => { const [k, v] = p.split(':'); return [k, parseInt(v, 16)]; }));

const held = new Set();      // physical keys currently down (hardware keyboard)
const latched = new Map();   // sticky modifiers from the key bar: scancode -> button

function releaseAll() {
  for (const sc of held) sendKey(sc, false);
  held.clear();
  releaseLatched();
}
function releaseLatched() {
  for (const [sc, btn] of latched) { sendKey(sc, false); btn.classList.remove('on'); }
  latched.clear();
}
function tapKey(sc) {
  sendKey(sc, true);
  sendKey(sc, false);
  releaseLatched();
}
function combo(...codes) {
  for (const c of codes) sendKey(SC[c], true);
  for (const c of codes.reverse()) sendKey(SC[c], false);
}
function typeText(s) {
  if (!s) return;
  const code = /^[a-z]$/i.test(s) ? 'Key' + s.toUpperCase() : /^[0-9]$/.test(s) ? 'Digit' + s : null;
  if (latched.size && code) return tapKey(SC[code]);  // Ctrl+C etc. need scancodes, not Unicode
  post(cat(Uint8Array.of(TEXT), te.encode(s)));
  releaseLatched();
}

document.addEventListener('keydown', e => {  // hardware keyboard: send scancodes, the host's IME does the rest
  if (!conn || e.target === ime || e.isComposing || e.keyCode === 229) return;
  const sc = SC[e.code];
  if (sc == null) return;
  e.preventDefault();
  held.add(sc);
  sendKey(sc, true);
});
document.addEventListener('keyup', e => {
  const sc = SC[e.code];
  if (!conn || e.target === ime || !held.delete(sc)) return;
  e.preventDefault();
  sendKey(sc, false);
});
addEventListener('blur', () => { if (conn) releaseAll(); });

// Soft keyboard: a hidden textarea. Whatever the phone's IME commits (Chinese or English) is typed on the PC as
// Unicode, so the PC's own IME state never matters (see tests/test_ime.py): switch languages on the phone only.
// A sentinel keeps Backspace working on an "empty" field; the preview shows pinyin / the word being composed,
// which would otherwise be invisible.
const SENTINEL = '​​';
let composing = false, lastCommit = { text: '', t: 0 };
function resetIme() { ime.value = SENTINEL; ime.setSelectionRange(SENTINEL.length, SENTINEL.length); }
function showPreview(text) { previewEl.textContent = text; previewEl.hidden = !text; }
function commit(text) {
  // Some browsers repeat a composition's text as insertText right after compositionend.
  if (!text || (text === lastCommit.text && performance.now() - lastCommit.t < 50)) return;
  lastCommit = { text, t: performance.now() };
  typeText(text);
}
ime.addEventListener('compositionstart', () => { composing = true; });
ime.addEventListener('compositionupdate', e => showPreview(e.data));
ime.addEventListener('compositionend', e => { composing = false; showPreview(''); commit(e.data); resetIme(); });
ime.addEventListener('input', e => {
  if (composing || e.isComposing) return;
  if (e.inputType === 'insertText') commit(e.data);
  else if (e.inputType === 'deleteContentBackward') tapKey(SC.Backspace);
  else if (e.inputType === 'insertLineBreak' || e.inputType === 'insertParagraph') tapKey(SC.Enter);
  resetIme();
});
ime.addEventListener('keydown', e => {
  if (e.isComposing || e.keyCode === 229) return;
  if (e.key.length > 1 && SC[e.code] != null) {  // Enter, Backspace, arrows...
    e.preventDefault();
    tapKey(SC[e.code]);
  }
});
ime.addEventListener('focus', renderKeyboard);
ime.addEventListener('blur', () => { showPreview(''); renderKeyboard(); });

async function pasteFromPhone() {
  try { commit(await navigator.clipboard.readText()); } catch { /* permission denied or unsupported */ }
}

// Keyboard model: the ⌨ button under the menu button (or a 3-finger tap) opens/closes the whole keyboard =
// key bar + the phone's keyboard. Inside the bar, the first button only hides/shows the phone's keyboard, so the
// shortcuts can stay on screen without it covering half the view.
const keyboardOpen = () => kbdEl.classList.contains('show');
function setKeyboard(open, soft = open) {
  kbdEl.classList.toggle('show', open);
  if (open && soft) { resetIme(); ime.focus({ preventScroll: true }); } else ime.blur();
  renderKeyboard();
  placeKeys();
}
const toggleKeyboard = () => setKeyboard(!keyboardOpen());
function renderKeyboard() {
  const soft = document.activeElement === ime;
  kbtn.classList.toggle('on', keyboardOpen());
  softBtn.textContent = soft ? '⌨ 隐藏键盘' : '⌨ 弹出键盘';
  softBtn.classList.toggle('on', soft);
}

// Key bar: [label, action, kind]. kind 'repeat' = auto-repeats while held, 'sticky' = latching modifier,
// 'click' = runs on a completed tap (clipboard access and focusing the textarea need one).
const KEY_BAR = [
  ['', () => setKeyboard(true, document.activeElement !== ime), 'click'],  // label set by renderKeyboard()
  ['手机粘贴', pasteFromPhone, 'click'],
  ['Esc', 'Escape'], ['Tab', 'Tab'], ['⌫', 'Backspace', 'repeat'], ['⏎', 'Enter'],
  ['←', 'ArrowLeft', 'repeat'], ['↑', 'ArrowUp', 'repeat'], ['↓', 'ArrowDown', 'repeat'], ['→', 'ArrowRight', 'repeat'],
  ['Ctrl', 'ControlLeft', 'sticky'], ['Alt', 'AltLeft', 'sticky'], ['Shift', 'ShiftLeft', 'sticky'],
  ['Win', 'MetaLeft', 'sticky'],
  ['复制', () => combo('ControlLeft', 'KeyC')], ['粘贴', () => combo('ControlLeft', 'KeyV')],
  ['撤销', () => combo('ControlLeft', 'KeyZ')], ['全选', () => combo('ControlLeft', 'KeyA')],
  ['切换窗口', () => combo('AltLeft', 'Tab')], ['桌面', () => combo('MetaLeft', 'KeyD')],
  ['Del', 'Delete', 'repeat'], ['Home', 'Home'], ['End', 'End'], ['PgUp', 'PageUp', 'repeat'],
  ['PgDn', 'PageDown', 'repeat'], ['F5', 'F5'], ['✕ 关闭', () => setKeyboard(false), 'click'],
];
const keyButtons = KEY_BAR.map(([label, action, kind]) => {
  const b = document.createElement('button');
  b.textContent = label;
  const run = typeof action === 'function' ? action : () => tapKey(SC[action]);
  let timer = 0;
  const stop = () => clearTimeout(timer);
  b.addEventListener('pointerdown', e => {
    e.preventDefault();  // keep focus (and the phone's keyboard) on the textarea
    if (kind === 'click') return;
    if (kind === 'sticky') {
      const sc = SC[action];
      if (latched.has(sc)) { latched.delete(sc); sendKey(sc, false); b.classList.remove('on'); }
      else { latched.set(sc, b); sendKey(sc, true); b.classList.add('on'); }
      return;
    }
    run();
    if (kind === 'repeat') {
      const again = () => { run(); timer = setTimeout(again, 45); };
      timer = setTimeout(again, 400);
    }
  });
  b.addEventListener('pointerup', stop);
  b.addEventListener('pointercancel', stop);
  b.addEventListener('pointerleave', stop);
  if (kind === 'click') b.addEventListener('click', run);
  keysEl.append(b);
  return b;
});
const softBtn = keyButtons[0];

function placeKeys() {  // sit on top of the soft keyboard, keep the cursor visible above both
  const vv = window.visualViewport;
  kbdEl.style.transform = vv ? `translateY(${vv.height + vv.offsetTop - innerHeight}px)` : '';
  if (W) { applyView(); follow(); }
}
window.visualViewport?.addEventListener('resize', placeKeys);
window.visualViewport?.addEventListener('scroll', placeKeys);

// ---- floating dock (☰ menu, ⌨ keyboard): drag it to any edge; the dot on ☰ shows the round-trip time ----
let fabPos = store.get('fab', { right: true, y: 0.08 });
function placeFab() {
  const a = safeArea(), w = dock.offsetWidth || 44, h = dock.offsetHeight || 98;
  dock.style.left = (fabPos.right ? a.x + a.w - w - 8 : a.x + 8) + 'px';
  dock.style.top = clamp(a.y + fabPos.y * innerHeight, a.y + 8, a.y + a.h - h - 8) + 'px';
}
function placePanel() {
  const r = dock.getBoundingClientRect(), pw = panel.offsetWidth, ph = panel.offsetHeight;
  panel.style.left = (fabPos.right ? r.left - pw - 8 : r.right + 8) + 'px';
  panel.style.top = clamp(r.top, 8, innerHeight - ph - 8) + 'px';
}
function togglePanel(open = !panel.classList.contains('show')) {
  panel.classList.toggle('show', open);
  if (open) placePanel();
}
{
  // A tap is whatever the browser reports as a click on the button (it tolerates finger jitter); only a move
  // beyond 14 px drags. Pointer capture starts with the drag: capturing on pointerdown would retarget the
  // click to the dock, and the buttons would never see it.
  let drag = null, dragged = false;
  dock.addEventListener('pointerdown', e => {
    const r = dock.getBoundingClientRect();
    drag = { x: e.clientX, y: e.clientY, dx: e.clientX - r.left, dy: e.clientY - r.top, moved: false };
  });
  dock.addEventListener('pointermove', e => {
    if (!drag) return;
    if (!drag.moved && Math.hypot(e.clientX - drag.x, e.clientY - drag.y) < 14) return;
    if (!drag.moved) {
      drag.moved = true;
      try { dock.setPointerCapture(e.pointerId); } catch { /* pointer already gone: the drag still works */ }
    }
    togglePanel(false);
    dock.style.left = e.clientX - drag.dx + 'px';  // keep the grab point under the finger: no jump
    dock.style.top = e.clientY - drag.dy + 'px';
  });
  const end = () => {
    if (drag?.moved) {
      const r = dock.getBoundingClientRect();
      fabPos = { right: r.left + r.width / 2 > innerWidth / 2, y: (r.top - safeArea().y) / innerHeight };
      store.set('fab', fabPos);
      placeFab();
      dragged = true;  // swallow the click that may follow the drag
      setTimeout(() => { dragged = false; }, 0);
    }
    drag = null;
  };
  dock.addEventListener('pointerup', end);
  dock.addEventListener('pointercancel', end);
  fab.addEventListener('click', () => { if (!dragged) togglePanel(); });
  kbtn.addEventListener('click', () => { if (!dragged) { togglePanel(false); toggleKeyboard(); } });
}

// ---- menu ----
let quality = store.get('quality', 1);
function renderMenu() {
  $('mode').textContent = mode === 'trackpad' ? '🖱 触控板' : '👆 触控';
  for (const b of $('quality').children) b.classList.toggle('on', +b.dataset.q === quality);
  $('sens').value = sens;
  $('sensv').textContent = sens.toFixed(1) + '×';
}
function toggleFullscreen() {
  if (document.fullscreenElement) return document.exitFullscreen();
  document.documentElement.requestFullscreen?.({ navigationUI: 'hide' })
    .then(() => screen.orientation?.lock?.(W >= H ? 'landscape' : 'portrait'))
    .catch(() => {});
}
panel.addEventListener('click', e => {
  const b = e.target.closest('button');
  if (!b) return;
  if (b.dataset.q != null) {
    quality = +b.dataset.q;
    store.set('quality', quality);
    sendConfig();
  }
  switch (b.dataset.act) {
    case 'mode': mode = mode === 'trackpad' ? 'touch' : 'trackpad'; store.set('mode', mode); break;
    case 'fit': fit(); break;
    case 'full': toggleFullscreen(); break;
    case 'stats': statsEl.hidden = !statsEl.hidden; break;
    case 'close': panel.classList.remove('show'); disconnect(); break;
  }
  renderMenu();
});
$('sens').addEventListener('input', e => { sens = +e.target.value; store.set('sens', sens); renderMenu(); });

setInterval(() => {
  if (!conn) return fab.style.setProperty('--dot', '#8e8e93');
  // A Wi-Fi <-> 4G switch often leaves the socket open but dead: nothing for 6 s (we ping every second) = reconnect.
  const idle = document.hidden ? 0 : performance.now() - conn.lastRx;
  if (idle > 6000) {
    conn.why = '6 秒没收到任何数据';
    return conn.close();
  }
  if (idle > 3000 && conn.rank === 1) rescue(conn);
  post(msg(PING, 8, v => v.setFloat64(1, performance.now(), true)));
  const rtt = stats.rtt;
  fab.style.setProperty('--dot', rtt < 60 ? '#30d158' : rtt < 150 ? '#ffd60a' : '#ff453a');
  statsEl.textContent = `${PATH_NAMES[conn.rank]} · ${stats.frames} fps · ` +
    `${(stats.bytes * 8 / 1e6).toFixed(1)} Mbps · ${rtt.toFixed(0)} ms`;
  stats.frames = stats.bytes = 0;
}, 1000);

document.addEventListener('visibilitychange', () => {
  if (document.hidden || !target) return;
  if (conn) { conn.lastRx = performance.now(); requestKey(); keepAwake(); }  // grace period after background
  else if (retryTimer) { retry = 0; open(); }  // back from background: retry now
});
addEventListener('resize', () => { if (W) atFit ? fit() : applyView(); placeFab(); });

// ---- status UI: a toast over the last frame once something was shown, a full-screen message before ----
let toastTimer = 0;
function toast(text, ms = 0) {
  clearTimeout(toastTimer);
  toastEl.textContent = text;
  toastEl.hidden = !text;
  if (text && ms) toastTimer = setTimeout(() => { toastEl.hidden = true; }, ms);
}
function status(html, actions = []) {
  if (everShown) { hideMsg(); toast(msgText(html)); } else showMsg(html, actions);
}
const msgText = html => { const d = document.createElement('div'); d.innerHTML = html; return d.textContent; };
function showMsg(html, actions = []) {
  toast('');
  msgEl.hidden = false;
  msgEl.querySelector('.text').innerHTML = html;
  msgEl.querySelector('.actions').replaceChildren(...actions.map(([label, fn]) => {
    const b = document.createElement('button');
    b.textContent = label;  // labels may be device names: textContent, never innerHTML
    b.onclick = fn;
    return b;
  }));
}
function hideMsg() { msgEl.hidden = true; }

function firstFrameHints() {
  const ios = /iPhone|iPad/.test(navigator.userAgent), standalone = matchMedia('(display-mode: standalone)').matches ||
    matchMedia('(display-mode: fullscreen)').matches || navigator.standalone;
  if (innerHeight > innerWidth && W > H) toast('横过来使用，画面更大', 3000);
  else if (ios && !standalone && !store.get('a2hs')) {
    store.set('a2hs', 1);
    toast('提示：Safari 分享 → 添加到主屏幕，即可全屏使用', 5000);
  }
}

// ---- start ----
function connect(id) {
  target = id;
  retry = 0;
  everShown = false;
  open();
}

function start() {
  generation++;
  clearTimeout(retryTimer);
  retryTimer = 0;
  dropConn();
  if (!window.isSecureContext || !window.VideoDecoder || !crypto.subtle) {
    return showMsg('需要 HTTPS 访问，以及支持 WebCodecs 的浏览器（Chrome 94+ / Safari 16.4+）。<br>' +
      '用 IP 访问时，请先安装证书：<a href="s/ca.crt">下载证书</a>');
  }
  devices = store.get('devices', {});
  const m = location.hash.match(/^#([\w-]{8,64})\.([\w-]{43})(?:\.(.*))?$/);
  if (m) {
    devices[m[1]] = { key: m[2], name: decodeURIComponent(m[3] || m[1]) };
    store.set('devices', devices);
    history.replaceState(null, '', location.pathname);  // keep the key out of history and screenshots
  }
  const ids = Object.keys(devices);
  if (!ids.length) return showMsg('还没有配对的电脑。<br>在电脑上运行 <code>python host.py --pair</code>，用手机扫码。');
  if (ids.length === 1) return connect(ids[0]);
  showMsg('选择要连接的电脑', ids.map(id => [devices[id].name, () => connect(id)]));
}

renderMenu();
renderKeyboard();
placeFab();
requestAnimationFrame(tick);
addEventListener('hashchange', start);  // a pairing link opened while the page is already loaded
start();
