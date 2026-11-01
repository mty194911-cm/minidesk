async (page) => {
  const assert = (condition, message) => { if (!condition) throw new Error(message); };
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.waitForFunction(() => typeof everShown !== 'undefined' && everShown, null, { timeout: 15000 });
  const rank = await page.evaluate(() => conn.rank);
  if (page.url().startsWith('https:')) assert(rank === 1, 'WebTransport was not selected');
  const initialRevision = await page.evaluate(async () => (await (await fetch('/test/state')).json()).revision);
  await page.evaluate(() => fetch('/test/clear', { method: 'POST' }));
  assert(await page.locator('#screen').getAttribute('width') === '640', 'synthetic screen was not decoded');

  // Ordinary repeated input and the composition duplicate need different handling.
  await page.evaluate(() => {
    ime.dispatchEvent(new InputEvent('input', { inputType: 'insertText', data: 'a' }));
    ime.dispatchEvent(new InputEvent('input', { inputType: 'insertText', data: 'a' }));
    ime.dispatchEvent(new CompositionEvent('compositionstart'));
    ime.dispatchEvent(new CompositionEvent('compositionend', { data: '你好' }));
    ime.dispatchEvent(new InputEvent('input', { inputType: 'insertText', data: '你好' }));
  });
  await page.waitForFunction(async () => {
    const state = await (await fetch('/test/state')).json();
    return state.input.filter(call => call[0] === 'text').length >= 3;
  });

  // Cancel a touch drag, then lose focus while a hardware modifier is held.
  await page.evaluate(() => {
    mode = 'touch';
    stage.dispatchEvent(new PointerEvent('pointerdown', { pointerId: 7, pointerType: 'touch', clientX: 100, clientY: 100 }));
    stage.dispatchEvent(new PointerEvent('pointermove', { pointerId: 7, pointerType: 'touch', clientX: 150, clientY: 100 }));
    stage.dispatchEvent(new PointerEvent('pointercancel', { pointerId: 7, pointerType: 'touch' }));
    document.dispatchEvent(new KeyboardEvent('keydown', { code: 'ControlLeft', key: 'Control' }));
    window.dispatchEvent(new Event('blur'));
  });
  await page.waitForFunction(async () => {
    const { input } = await (await fetch('/test/state')).json();
    return input.some(call => call[0] === 'button' && call[2] === 0)
      && input.some(call => call[0] === 'key' && call[1] === 29 && call[2] === 0);
  });
  const state = await page.evaluate(async () => (await fetch('/test/state')).json());
  assert(JSON.stringify(state.input.filter(call => call[0] === 'text').map(call => call[1]))
    === JSON.stringify(['a', 'a', '你好']), 'committed text was lost or duplicated');
  await page.evaluate(() => typeText('你🙂'.repeat(6000)));
  await page.waitForFunction(async () => {
    const state = await (await fetch('/test/state')).json();
    return state.input.filter(call => call[0] === 'text').slice(3).map(call => call[1]).join('') === '你🙂'.repeat(6000);
  });

  // Replay twelve genuine access units in one burst; a healthy decoder must catch up without halving FPS.
  await page.evaluate(() => {
    window.testVideo = { original: onVideo, first: 0, frames: new Map() };
    onVideo = (key, seq, au, received) => {
      if (key && !testVideo.first) testVideo.first = seq;
      if (testVideo.first && seq >= testVideo.first && testVideo.frames.size < 32) {
        testVideo.frames.set(seq, [key, seq, au.slice()]);
      }
      testVideo.original(key, seq, au, received);
    };
    post(msg(KEYFRAME, 0));
  });
  await page.waitForFunction(() => testVideo.first && Array.from({ length: 12 }, (_, i) => testVideo.first + i)
    .every(seq => testVideo.frames.has(seq)));
  const replayFps = await page.evaluate(async () => {
    const recorded = testVideo, original = recorded.original;
    onVideo = (_key, seq) => post(msg(ACK, 4, view => view.setUint32(1, seq, true)));
    try {
      resetDecoder(); resetReorder();
      for (let i = 0; i < 12; i++) original(...recorded.frames.get(recorded.first + i));
      await new Promise((resolve, reject) => {
        const started = performance.now();
        const check = () => {
          if (!decodeQueue?.pending.length && !frameTimes.size) return resolve();
          if (performance.now() - started > 2000) return reject(new Error('burst decoder did not drain'));
          setTimeout(check, 5);
        };
        check();
      });
      return streamFps;
    } finally { onVideo = original; delete window.testVideo; requestKey(); }
  });
  assert(replayFps === 60, 'temporary frame burst incorrectly reduced the capture FPS');

  // A slow decoder must trigger recovery and reduce the stream rate instead of adding more queued frames.
  const overload = await page.evaluate(() => {
    resetDecoder();
    decoder = { state: 'configured', decodeQueueSize: 6, close() { this.state = 'closed'; } };
    startDecodeQueue(decoder);
    decodeQueue.push({ key: false, au: new Uint8Array([1]), arrived: performance.now() }, performance.now() - 200);
    return { fps: streamFps, reset: decoder === null };
  });
  assert(overload.reset && overload.fps === 30, 'slow decoder was not recovered');
  await page.waitForFunction(() => decoder?.state === 'configured');
  await page.evaluate(() => { lastDecodeBackoff = -Infinity; nextFpsProbe = 0; stats.videoDelay = 0; stats.frames = 1; });
  await page.waitForFunction(() => streamFps === 35);

  await page.evaluate(() => fetch('/test/kick', { method: 'POST' }));
  await page.waitForFunction(() => !msgEl.hidden && msgEl.textContent.includes('电脑端断开'));
  await page.waitForTimeout(1500);
  assert(await page.evaluate(() => conn === null && retryTimer === 0), 'kicked client automatically reconnected');
  await page.getByRole('button', { name: '重新连接', exact: true }).click();
  await page.waitForFunction(() => conn && decoder?.state === 'configured');
  const pairing = await page.evaluate(async () => (await fetch('/test/reset', { method: 'POST' })).json());
  await page.waitForFunction(() => !msgEl.hidden && msgEl.textContent.includes('电脑端断开'));
  await page.getByRole('button', { name: '重新连接', exact: true }).click();
  await page.waitForFunction(() => msgEl.textContent.includes('配对已失效'));
  await page.evaluate(key => { location.hash = `browserhost01.${key}.BrowserTest`; }, pairing.key);
  await page.waitForFunction(() => conn && decoder?.state === 'configured');
  const finalState = await page.evaluate(async () => (await fetch('/test/state')).json());
  assert(finalState.revision === initialRevision + 1 && finalState.active, 'live key rotation did not accept the new pairing');
  await page.evaluate(() => fetch('/test/kick', { method: 'POST' }));
  await page.waitForFunction(() => conn === null && retryTimer === 0);
  assert(errors.length === 0, `browser errors: ${errors.join('; ')}`);
  return { transport: rank === 1 ? 'WebTransport' : 'WebSocket', decoded: true, input: state.input,
    unicodePaste: true, burstFps: replayFps, slowDecoderFps: overload.fps, recoveredFps: 35,
    kickedWithoutReconnect: true, liveKeyRevocation: true, errors };
}
