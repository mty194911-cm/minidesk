const { test } = require('node:test');
const assert = require('node:assert/strict');
const { createInbox, CompositionCommitter, textChunks, SendQueue, DecodeQueue, FrameRenderer, gapDelay }
  = require('../relay/web/client-core.js');

test('closing an inbox wakes current and future receivers', async () => {
  const box = createInbox();
  const pending = [box.recv(), box.recv()];
  box.end();
  assert.deepEqual(await Promise.all(pending), [null, null]);
  assert.equal(await box.recv(), null);
  assert.equal(box.push(new Uint8Array([1])), false);
  box.end();
});

test('queued BYE is drained before end of stream', async () => {
  const box = createInbox();
  assert.equal(box.push(new Uint8Array([0x7F])), true);
  box.end();
  assert.deepEqual(await box.recv(), new Uint8Array([0x7F]));
  assert.equal(await box.recv(), null);
});

test('WebTransport control passes queued video while video completion order is preserved', async () => {
  const box = createInbox();
  box.push(Uint8Array.of(1), true); box.push(Uint8Array.of(2), true);
  box.push(Uint8Array.of(0x7F));
  box.end();
  assert.deepEqual([...await box.recv()], [0x7F]);
  assert.deepEqual([...await box.recv()], [1]);
  assert.deepEqual([...await box.recv()], [2]);
});

test('inbox bounds message count and byte count and frees capacity on recv', async () => {
  const box = createInbox(2, 3);
  assert.equal(box.push(new Uint8Array(2)), true);
  assert.equal(box.push(new Uint8Array(2)), false);
  assert.equal(box.push(new Uint8Array(1)), true);
  assert.equal(box.push(new Uint8Array(0)), false);
  await box.recv();
  assert.equal(box.push(new Uint8Array(2)), true);
});

test('normal repeated characters and pastes are not deduplicated', () => {
  const sent = [], input = new CompositionCommitter(text => sent.push(text), () => 1000);
  input.input('a'); input.input('a'); input.direct('same'); input.direct('same');
  assert.deepEqual(sent, ['a', 'a', 'same', 'same']);
});

test('only the first duplicate following composition end is suppressed', () => {
  const sent = [], input = new CompositionCommitter(text => sent.push(text), () => 1000);
  input.start(); input.end('你好'); input.input('你好'); input.input('你好');
  assert.deepEqual(sent, ['你好', '你好']);
});

test('new composition, another input, timeout and explicit paste cancel deduplication', () => {
  const sent = [];
  let now = 0;
  const input = new CompositionCommitter(text => sent.push(text), () => now);
  input.end('a'); input.start(); input.input('a');
  input.end('b'); input.input('c'); input.input('b');
  input.end('d'); now = 100; input.input('d');
  input.end('e'); input.direct('e');
  assert.deepEqual(sent, ['a', 'a', 'b', 'c', 'b', 'd', 'd', 'e', 'e']);
});

test('large Unicode pastes are split within host limits without splitting surrogate pairs', () => {
  const text = '你🙂a'.repeat(5000), chunks = [...textChunks(text)];
  assert.equal(chunks.join(''), text);
  for (const chunk of chunks) {
    assert(Buffer.byteLength(chunk, 'utf8') <= 16 * 1024);
    assert(!/[\uD800-\uDBFF]$/.test(chunk));
  }
  assert.deepEqual([...textChunks('')], []);
});

test('input bypasses pending ACKs, adjacent moves collapse, and button/key barriers stay ordered', async () => {
  let release;
  const gate = new Promise(resolve => { release = resolve; }), sent = [];
  const queue = new SendQueue(async data => { sent.push([...data]); if (sent.length === 1) await gate; });
  const pending = [queue.push(Uint8Array.of(0x30, 1)), queue.push(Uint8Array.of(0x30, 2))];
  pending.push(queue.push(Uint8Array.of(0x10, 10)), queue.push(Uint8Array.of(0x10, 20)));
  pending.push(queue.push(Uint8Array.of(0x11, 1)));
  pending.push(queue.push(Uint8Array.of(0x10, 30)), queue.push(Uint8Array.of(0x10, 40)));
  pending.push(queue.push(Uint8Array.of(0x20, 1)), queue.push(Uint8Array.of(0x20, 0)));
  release();
  await Promise.all(pending);
  assert.deepEqual(sent, [[0x30, 1], [0x10, 20], [0x11, 1], [0x10, 40], [0x20, 1], [0x20, 0], [0x30, 2]]);
});

test('ACKs cannot be starved by continuous input', async () => {
  let release;
  const gate = new Promise(resolve => { release = resolve; }), sent = [];
  const queue = new SendQueue(async data => { sent.push(data[0]); if (sent.length === 1) await gate; });
  const pending = [queue.push(Uint8Array.of(0x20)), queue.push(Uint8Array.of(0x30))];
  for (let i = 0; i < 30; i++) pending.push(queue.push(Uint8Array.of(0x20)));
  release();
  await Promise.all(pending);
  assert(sent.indexOf(0x30) <= 8);
});

test('send failure rejects all waiting messages without leaving work behind', async () => {
  const queue = new SendQueue(async () => { throw new Error('offline'); });
  const outcomes = await Promise.allSettled([queue.push(Uint8Array.of(0x20)), queue.push(Uint8Array.of(0x30))]);
  assert(outcomes.every(outcome => outcome.status === 'rejected'));
  assert(queue.closed && queue.input.length === 0 && queue.acks.length === 0);
});

function virtualTimers() {
  let now = 0, serial = 0;
  const timers = new Map();
  return {
    now: () => now,
    setTimer: (callback, delay) => { timers.set(++serial, { callback, due: now + delay }); return serial; },
    clearTimer: id => timers.delete(id),
    advance(ms) {
      const end = now + ms;
      for (;;) {
        const next = [...timers].filter(([, timer]) => timer.due <= end).sort((a, b) => a[1].due - b[1].due)[0];
        if (!next) break;
        timers.delete(next[0]); now = next[1].due; next[1].callback();
      }
      now = end;
    },
  };
}

test('a normal burst is decoded in reference order with only two frames in flight and no false backoff', () => {
  const clock = virtualTimers(), submitted = [];
  let active = 0, highest = 0, stalled = 0;
  const queue = new DecodeQueue({ ...clock, size: () => active,
    submit: frame => { active++; highest = Math.max(highest, active); submitted.push(frame); }, stall: () => stalled++ });
  for (let i = 0; i < 12; i++) queue.push(i);
  for (let i = 0; i < 12; i++) { clock.advance(4); active--; queue.drain(); }
  assert.deepEqual(submitted, Array.from({ length: 12 }, (_, i) => i));
  assert.equal(highest, 2);
  assert.equal(stalled, 0);
});

test('persistent decode overload expires at the time budget and clears queued frames', () => {
  const clock = virtualTimers();
  let stalled = 0;
  const queue = new DecodeQueue({ ...clock, size: () => 2, submit: () => {}, stall: () => stalled++ });
  queue.push('frame'); clock.advance(149); assert.equal(stalled, 0);
  clock.advance(1); assert.equal(stalled, 1);
  clock.advance(1000); assert.equal(stalled, 1);
  assert(queue.closed && queue.pending.length === 0);
});

test('catch-up rendering closes superseded GPU frames and paints the latest once', () => {
  const drawn = [], closed = [], callbacks = new Map();
  let serial = 0;
  const renderer = new FrameRenderer(frame => drawn.push(frame.id), callback => { callbacks.set(++serial, callback); return serial; },
    id => callbacks.delete(id));
  const frame = id => ({ id, close: () => closed.push(id) });
  renderer.push(frame(1), true); renderer.push(frame(2), true);
  callbacks.values().next().value();
  assert.deepEqual(drawn, [2]);
  renderer.push(frame(3));
  renderer.push(frame(4), true); renderer.clear();
  assert.deepEqual(drawn, [2, 3]);
  assert.deepEqual(closed.sort(), [1, 2, 3, 4]);
});

test('missing-frame recovery adapts to RTT and stays within an interactive budget', () => {
  assert.equal(gapDelay(0), 120);
  assert.equal(gapDelay(60), 130);
  assert.equal(gapDelay(300), 400);
  assert.equal(gapDelay(NaN), 120);
});
