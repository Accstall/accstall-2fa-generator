const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function sha1(bytes) {
  const bitLen = bytes.length * 8;
  const paddedLen = Math.ceil((bytes.length + 9) / 64) * 64;
  const padded = new Uint8Array(paddedLen);
  padded.set(bytes);
  padded[bytes.length] = 128;
  const view = new DataView(padded.buffer);
  view.setUint32(paddedLen - 8, Math.floor(bitLen / 4294967296));
  view.setUint32(paddedLen - 4, bitLen % 4294967296);

  let h0 = 1732584193;
  let h1 = 4023233417;
  let h2 = 2562383102;
  let h3 = 271733878;
  let h4 = 3285377520;
  const w = new Int32Array(80);

  for (let offset = 0; offset < paddedLen; offset += 64) {
    for (let i = 0; i < 16; i++) w[i] = view.getInt32(offset + i * 4);
    for (let i = 16; i < 80; i++) {
      const x = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
      w[i] = (x << 1) | (x >>> 31);
    }

    let a = h0;
    let b = h1;
    let c = h2;
    let d = h3;
    let e = h4;

    for (let i = 0; i < 80; i++) {
      let f;
      let k;
      if (i < 20) {
        f = (b & c) | (~b & d);
        k = 1518500249;
      } else if (i < 40) {
        f = b ^ c ^ d;
        k = 1859775393;
      } else if (i < 60) {
        f = (b & c) | (b & d) | (c & d);
        k = 2400959708;
      } else {
        f = b ^ c ^ d;
        k = 3395469782;
      }
      const temp = ((a << 5) | (a >>> 27)) + f + e + k + w[i] | 0;
      e = d;
      d = c;
      c = (b << 30) | (b >>> 2);
      b = a;
      a = temp;
    }

    h0 = h0 + a | 0;
    h1 = h1 + b | 0;
    h2 = h2 + c | 0;
    h3 = h3 + d | 0;
    h4 = h4 + e | 0;
  }

  const digest = new Uint8Array(20);
  const out = new DataView(digest.buffer);
  out.setInt32(0, h0);
  out.setInt32(4, h1);
  out.setInt32(8, h2);
  out.setInt32(12, h3);
  out.setInt32(16, h4);
  return digest;
}

export function hmacSha1(key, message) {
  const block = 64;
  const keyed = key.length > block ? sha1(key) : key;
  const inner = new Uint8Array(block + message.length);
  const outer = new Uint8Array(block + 20);
  for (let i = 0; i < block; i++) {
    const b = i < keyed.length ? keyed[i] : 0;
    inner[i] = b ^ 54;
    outer[i] = b ^ 92;
  }
  inner.set(message, block);
  outer.set(sha1(inner), block);
  return sha1(outer);
}

export function base32Decode(input) {
  const out = new Uint8Array(Math.floor(input.length * 5 / 8));
  let bits = 0;
  let value = 0;
  let written = 0;
  for (let i = 0; i < input.length; i++) {
    const n = BASE32.indexOf(input[i]);
    if (n === -1) return null;
    value = (value << 5) | n;
    bits += 5;
    if (bits >= 8) {
      out[written++] = (value >>> (bits - 8)) & 255;
      bits -= 8;
    }
  }
  return out.subarray(0, written);
}

export function hotp(key, counter, digits) {
  const buf = new Uint8Array(8);
  let n = counter;
  for (let i = 7; i >= 0; i--) {
    buf[i] = n % 256;
    n = Math.floor(n / 256);
  }
  const digest = hmacSha1(key, buf);
  const offset = digest[19] & 15;
  const truncated =
    (digest[offset] & 127) * 16777216 +
    (digest[offset + 1] & 255) * 65536 +
    (digest[offset + 2] & 255) * 256 +
    (digest[offset + 3] & 255);
  let code = String(truncated % Math.pow(10, digits));
  while (code.length < digits) code = '0' + code;
  return code;
}

export function totp(key, unixSeconds, digits, period) {
  return hotp(key, Math.floor(unixSeconds / period), digits);
}

export function normalizeSecret(raw) {
  return (raw || '').toUpperCase().replace(/[\s-]/g, '').replace(/=+$/, '');
}

export function parseSecretInput(raw) {
  const trimmed = (raw || '').trim();
  if (!/^otpauth:\/\//i.test(trimmed)) {
    return { secret: trimmed, unsupported: '' };
  }

  let query = '';
  const q = trimmed.indexOf('?');
  if (q !== -1) query = trimmed.slice(q + 1);

  const params = {};
  query.split('&').forEach((part) => {
    if (!part) return;
    const pieces = part.split('=');
    const key = decodeURIComponent((pieces[0] || '').replace(/\+/g, ' ')).toLowerCase();
    const value = decodeURIComponent((pieces.slice(1).join('=') || '').replace(/\+/g, ' '));
    params[key] = value;
  });

  const digits = params.digits || '6';
  const period = params.period || '30';
  const algorithm = (params.algorithm || 'SHA1').replace(/-/g, '').toUpperCase();
  if (digits !== '6' || period !== '30' || algorithm !== 'SHA1') {
    return { secret: '', unsupported: [digits, period, params.algorithm || 'SHA1'].join('|') };
  }
  return { secret: params.secret || '', unsupported: '' };
}

export function isValidSecret(normalized) {
  return normalized.length >= 8 && /^[A-Z2-7]+$/.test(normalized);
}

export function copyText(text) {
  if (typeof navigator !== 'undefined' && navigator.clipboard && window.isSecureContext) {
    return navigator.clipboard.writeText(text);
  }
  return new Promise((resolve, reject) => {
    try {
      const area = document.createElement('textarea');
      area.value = text;
      area.setAttribute('readonly', '');
      area.style.position = 'fixed';
      area.style.top = '-9999px';
      document.body.appendChild(area);
      area.select();
      document.execCommand('copy');
      document.body.removeChild(area);
      resolve();
    } catch (err) {
      reject(err);
    }
  });
}

export function createTotp(options) {
  const opts = options || {};
  return {
    secret: opts.secret || '',
    digits: 6,
    period: 30,
    clockOffset: 0,
    clockFailed: false,
    code: '',
    nextCode: '',
    remaining: 30,
    progress: 0,
    invalid: false,
    unsupported: false,
    unsupportedDetail: '',
    queryStripped: false,
    copied: '',
    ticker: null,
    copyTimer: null,
    lastCounter: null,
    onVisible: null,

    init() {
      this.stripQuerySecret();
      this.syncClock();
      this.refresh(true);
      this.ticker = setInterval(this.refresh.bind(this, false), 200);
      this.onVisible = (function onVisible() {
        if (document.visibilityState === 'visible') this.refresh(true);
      }).bind(this);
      document.addEventListener('visibilitychange', this.onVisible);
      this.$watch('secret', (function watchSecret() {
        this.lastCounter = null;
        this.refresh(true);
      }).bind(this));
    },

    destroy() {
      if (this.ticker) {
        clearInterval(this.ticker);
        this.ticker = null;
      }
      if (this.copyTimer) {
        clearTimeout(this.copyTimer);
        this.copyTimer = null;
      }
      if (this.onVisible) {
        document.removeEventListener('visibilitychange', this.onVisible);
        this.onVisible = null;
      }
    },

    stripQuerySecret() {
      try {
        const url = new URL(window.location.href);
        if (url.searchParams.has('secret')) {
          url.searchParams.delete('secret');
          window.history.replaceState({}, '', url.pathname + url.search + url.hash);
          this.queryStripped = true;
        }
      } catch {
        /* ignore */
      }
    },

    syncClock() {
      if (!opts.clockUrl) return;
      const t0 = Date.now();
      fetch(opts.clockUrl, {
        cache: 'no-store',
        credentials: 'same-origin',
        headers: { Accept: 'application/json' },
      })
        .then((res) => {
          if (!res.ok) throw new Error('clock');
          return res.json();
        })
        .then((function applyClock(json) {
          const t1 = Date.now();
          const serverT = Number(json && json.t);
          if (!Number.isFinite(serverT)) throw new Error('clock');
          this.clockOffset = serverT - (t0 + (t1 - t0) / 2);
          this.clockFailed = false;
          this.refresh(true);
        }).bind(this))
        .catch((function clockFail() {
          this.clockOffset = 0;
          this.clockFailed = true;
          this.refresh(true);
        }).bind(this));
    },

    get parsed() {
      return parseSecretInput(this.secret);
    },

    get cleanSecret() {
      return normalizeSecret(this.parsed.secret);
    },

    get isValidSecret() {
      return isValidSecret(this.cleanSecret);
    },

    get isEmpty() {
      return (this.secret || '').trim() === '';
    },

    get hasCode() {
      return this.code !== '';
    },

    get expiringSoon() {
      return this.hasCode && this.remaining <= 5;
    },

    get formattedCode() {
      if (!this.hasCode) return '——— ———';
      const mid = Math.ceil(this.code.length / 2);
      return this.code.slice(0, mid) + ' ' + this.code.slice(mid);
    },

    refresh(force) {
      this.unsupported = false;
      this.unsupportedDetail = '';
      if (this.isEmpty) {
        this.code = '';
        this.nextCode = '';
        this.invalid = false;
        this.remaining = this.period;
        this.progress = 0;
        this.lastCounter = null;
        return;
      }

      const parsed = this.parsed;
      if (parsed.unsupported) {
        this.code = '';
        this.nextCode = '';
        this.invalid = false;
        this.unsupported = true;
        this.unsupportedDetail = parsed.unsupported;
        this.lastCounter = null;
        return;
      }

      if (!this.isValidSecret) {
        this.code = '';
        this.nextCode = '';
        this.invalid = true;
        this.lastCounter = null;
        return;
      }

      const nowSeconds = (Date.now() + this.clockOffset) / 1000;
      const counter = Math.floor(nowSeconds / this.period);
      const intoWindow = nowSeconds - counter * this.period;
      this.remaining = Math.max(1, Math.ceil(this.period - intoWindow));
      this.progress = Math.min(100, (intoWindow / this.period) * 100);
      if (!force && counter === this.lastCounter) return;

      const key = base32Decode(this.cleanSecret);
      if (key === null || key.length === 0) {
        this.code = '';
        this.nextCode = '';
        this.invalid = true;
        this.lastCounter = null;
        return;
      }

      this.invalid = false;
      this.lastCounter = counter;
      this.code = hotp(key, counter, this.digits);
      this.nextCode = hotp(key, counter + 1, this.digits);
    },

    flagCopied(kind) {
      this.copied = kind;
      if (this.copyTimer) clearTimeout(this.copyTimer);
      this.copyTimer = setTimeout((function clearCopied() {
        this.copied = '';
      }).bind(this), 1800);
    },

    copyCode() {
      if (!this.hasCode) return;
      copyText(this.code).then(this.flagCopied.bind(this, 'code')).catch(() => {});
    },
  };
}
