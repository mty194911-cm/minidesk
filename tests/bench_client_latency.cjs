// Compare the actual app.js functions. No browser, desktop input, or external connection is used.
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { performance } = require('node:perf_hooks');
const args = process.argv.slice(2);
const sourceIndex = args.indexOf('--source');
const sourceDir = path.resolve(sourceIndex >= 0 ? args[sourceIndex + 1] : path.join(__dirname, '..'));
const app = fs.readFileSync(path.join(sourceDir, 'relay/web/app.js'), 'utf8');
const core = { module: { exports: {} }, setTimeout, clearTimeout, performance };
vm.runInNewContext(fs.readFileSync(path.join(sourceDir, 'relay/web/client-core.js'), 'utf8'), core);
const helpers = core.module.exports;
function segment(start, end) {
  const begin = app.indexOf(start), finish = app.indexOf(end, begin);
  if (begin < 0 || finish < 0) throw new Error(`Missing source section ${start}`);
  return app.slice(begin, finish);
}

async function inputBurst() {
  let clock = 0;
  const sent = [];
  const conn = { chain: Promise.resolve(), chan: { seal: async data => {
    await Promise.resolve(); clock += 2; return data;
  } }, send: data => { sent.push({ type: data[0], value: data[1], at: clock }); }, close() {} };
  const context = vm.createContext({ conn, SendQueue: helpers.SendQueue });
  vm.runInContext(`${segment('function post(pt)', 'function msg(')}
    for (let i = 0; i < 24; i++) post(Uint8Array.of(0x30, i));
    for (let i = 0; i < 20; i++) post(Uint8Array.of(0x10, i));
  `, context);
  await conn.chain;
  while (conn.sender?.running) await new Promise(resolve => setTimeout(resolve, 1));
  const moves = sent.filter(item => item.type === 0x10);
  return { model: 'virtual clock: 24 queued ACKs, 20 adjacent moves, fixed 2 ms processing per message',
    first_move_wait_ms: Math.round(moves[0].at), moves_sent: moves.length, final_position: moves.at(-1).value };
}

function decodeBurst() {
  const context = vm.createContext({ ...helpers, performance: { now: () => 1000 },
    setTimeout: () => 1, clearTimeout: () => {},
    ACK: 0x30, stats: { bytes: 0, rtt: 60 }, post() {}, msg: () => new Uint8Array(5),
    sendConfig() {}, requestKey() {}, codecOf: () => 'test',
    EncodedVideoChunk: class { constructor(data) { Object.assign(this, data); } },
    VideoDecoder: class {
      constructor() { this.state = 'unconfigured'; this.decodeQueueSize = 0; }
      configure() { this.state = 'configured'; }
      decode() { this.decodeQueueSize++; }
      close() { this.state = 'closed'; }
    },
  });
  const setup = app.includes('function startDecodeQueue(') ? segment('function startDecodeQueue(', '// Over UDP') : '';
  vm.runInContext(`
    let decoder = null, decodeQueue = null, decoderEpoch = 0, decodeStamp = 0, streamFps = 60, resets = 0;
    const frameTimes = new Map();
    function onFrame() {}
    function resetDecoder() { resets++; decoder?.close(); decoder = null; decodeQueue?.close(); decodeQueue = null; frameTimes.clear(); decoderEpoch++; }
    function decoderOverload() { resetDecoder(); streamFps = Math.max(10, streamFps / 2); }
    ${setup}
    ${segment('let nextSeq =', 'function setScreen(')}
    for (let i = 1; i <= 12; i++) onVideo(i === 1, i, new Uint8Array(1));
    globalThis.result = { fps_after_burst: streamFps, extra_decoder_resets: Math.max(0, resets - 1) };
  `, context);
  return { model: '12 frames delivered before the next decoder callback; temporary burst, not a slow decoder', ...context.result };
}

function gapBudget() {
  let timeout;
  const context = vm.createContext({ ...helpers, ACK: 0x30, stats: { bytes: 0, rtt: 60 },
    performance: { now: () => 0 }, post() {}, msg: () => new Uint8Array(5),
    decodeFrame() {}, resetDecoder() {}, requestKey() {}, clearTimeout() {},
    setTimeout: (callback, delay) => { timeout = delay; return 1; } });
  vm.runInContext(`${segment('let nextSeq =', 'function decodeFrame(')}
    onVideo(true, 1, new Uint8Array(1)); onVideo(false, 3, new Uint8Array(1));`, context);
  return { rtt_ms: 60, missing_frame_deadline_ms: timeout };
}

(async () => {
  const result = { source: sourceDir, input: await inputBurst(), burst: decodeBurst(), gap: gapBudget() };
  const text = JSON.stringify(result, null, 2);
  console.log(text);
  const index = args.indexOf('--output');
  if (index >= 0) { const target = args[index + 1]; fs.mkdirSync(path.dirname(target), { recursive: true }); fs.writeFileSync(target, text + '\n'); }
})().catch(error => { console.error(error); process.exitCode = 1; });
