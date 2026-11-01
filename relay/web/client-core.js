// Small state machines shared by the browser and the dependency-free Node regression tests.
((root) => {
  'use strict';
  function createInbox(maxMessages = 128, maxBytes = 16 << 20) {
    const queue = [], video = [], waiters = [];
    let ended = false, bytes = 0;
    return {
      push(data, isVideo = false) {
        if (ended) return false;
        if (waiters.length) { waiters.shift()(data); return true; }
        if (queue.length + video.length >= maxMessages || bytes + data.length > maxBytes) return false;
        (isVideo ? video : queue).push(data);
        bytes += data.length;
        return true;
      },
      recv() {
        if (queue.length || video.length) {
          const data = (queue.length ? queue : video).shift(); bytes -= data.length; return Promise.resolve(data);
        }
        return ended ? Promise.resolve(null) : new Promise(resolve => waiters.push(resolve));
      },
      end() { ended = true; waiters.splice(0).forEach(resolve => resolve(null)); },
    };
  }

  class CompositionCommitter {
    constructor(send, now = () => performance.now()) { this.send = send; this.now = now; this.pending = null; }
    start() { this.pending = null; }
    end(text) {
      this.pending = text ? { text, until: this.now() + 50 } : null;
      if (text) this.send(text);
    }
    input(text) {
      const previous = this.pending;
      this.pending = null;
      if (previous && previous.text === text && this.now() <= previous.until) return;
      if (text) this.send(text);
    }
    direct(text) { this.pending = null; if (text) this.send(text); }
  }

  function* textChunks(text, size = 4096) {
    let chunk = '', count = 0;
    for (const point of text) {
      chunk += point;
      if (++count === size) { yield chunk; chunk = ''; count = 0; }
    }
    if (chunk) yield chunk;
  }

  class SendQueue {
    constructor(send, maxMessages = 256) {
      this.send = send;
      this.maxMessages = maxMessages;
      this.input = [];
      this.acks = [];
      this.running = this.closed = false;
      this.inputBurst = 0;
    }
    push(data) {
      if (this.closed) return Promise.resolve();
      const queue = data[0] === 0x30 ? this.acks : this.input;
      const previous = queue[queue.length - 1];
      // Only adjacent, unsent mouse moves may collapse. Button/key order is a strict barrier.
      if (data[0] === 0x10 && previous?.data[0] === 0x10) {
        previous.data = data;
        return previous.promise;
      }
      if (this.input.length + this.acks.length >= this.maxMessages) return Promise.reject(new Error('发送队列过长'));
      const item = { data };
      item.promise = new Promise((resolve, reject) => { item.resolve = resolve; item.reject = reject; });
      queue.push(item);
      this.pump();
      return item.promise;
    }
    async pump() {
      if (this.running || this.closed) return;
      this.running = true;
      try {
        while (!this.closed && (this.input.length || this.acks.length)) {
          const input = this.input.length && (!this.acks.length || this.inputBurst < 8);
          const item = (input ? this.input : this.acks).shift();
          this.inputBurst = input ? this.inputBurst + 1 : 0;
          try { await this.send(item.data); item.resolve(); }
          catch (error) {
            this.closed = true;
            item.reject(error);
            for (const pending of [...this.input, ...this.acks]) pending.reject(error);
            this.input.length = this.acks.length = 0;
          }
        }
      } finally { this.running = false; }
    }
    close() {
      this.closed = true;
      for (const item of [...this.input, ...this.acks]) item.resolve();
      this.input.length = this.acks.length = 0;
    }
  }

  class DecodeQueue {
    constructor({ size, submit, stall, depth = 2, maxFrames = 32, maxWait = 150,
      now = () => performance.now(), setTimer = (callback, delay) => setTimeout(callback, delay), clearTimer = id => clearTimeout(id) }) {
      Object.assign(this, { size, submit, stall, depth, maxFrames, maxWait, now, setTimer, clearTimer });
      this.pending = [];
      this.timer = 0;
      this.closed = false;
    }
    push(frame, arrived = this.now()) {
      if (this.closed) return;
      this.pending.push({ frame, arrived });
      this.drain();
    }
    drain() {
      if (this.closed) return;
      this.clearTimer(this.timer);
      this.timer = 0;
      if (this.pending.length > this.maxFrames || this.pending.length && this.now() - this.pending[0].arrived >= this.maxWait) {
        this.close();
        this.stall();
        return;
      }
      while (this.pending.length && this.size() < this.depth) this.submit(this.pending.shift().frame);
      if (this.pending.length) {
        this.timer = this.setTimer(() => this.drain(), Math.max(1, this.maxWait - (this.now() - this.pending[0].arrived)));
      }
    }
    close() { this.closed = true; this.pending.length = 0; this.clearTimer(this.timer); this.timer = 0; }
  }

  class FrameRenderer {
    constructor(draw, schedule = callback => requestAnimationFrame(callback), cancel = id => cancelAnimationFrame(id)) {
      this.draw = draw;
      this.schedule = schedule;
      this.cancel = cancel;
      this.pending = null;
      this.tick = 0;
    }
    push(frame, defer = false) {
      if (this.pending) this.pending.close();
      this.pending = frame;
      if (!defer) { this.cancel(this.tick); this.tick = 0; this.flush(); }
      else if (!this.tick) this.tick = this.schedule(() => { this.tick = 0; this.flush(); });
    }
    flush() {
      const frame = this.pending;
      this.pending = null;
      if (frame) { try { this.draw(frame); } finally { frame.close(); } }
    }
    clear() { this.cancel(this.tick); this.tick = 0; this.pending?.close(); this.pending = null; }
  }

  const gapDelay = rtt => Math.min(400, Math.max(120, (Number.isFinite(rtt) ? rtt : 0) * 1.5 + 40));
  const api = { createInbox, CompositionCommitter, textChunks, SendQueue, DecodeQueue, FrameRenderer, gapDelay };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.MiniDeskCore = api;
})(globalThis);
