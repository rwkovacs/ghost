const crypto = require('crypto');

const SECRET = process.env.CAPTCHA_SECRET || crypto.randomBytes(32).toString('hex');
const TOKEN_TTL_MS = 10 * 60 * 1000;
const MIN_SOLVE_MS = 3000;
const POW_DIFFICULTY = 18;

function sign(payload) {
  return crypto.createHmac('sha256', SECRET).update(payload).digest('hex');
}

function issue() {
  const a = 1 + Math.floor(Math.random() * 9);
  const b = 1 + Math.floor(Math.random() * 9);
  const op = ['+', '-', '*'][Math.floor(Math.random() * 3)];
  const question = `${a} ${op} ${b}`;
  const answer = op === '+' ? a + b : op === '-' ? a - b : a * b;

  const powChallenge = crypto.randomBytes(16).toString('hex');
  const issuedAt = Date.now();
  const nonceId = crypto.randomBytes(12).toString('hex');

  const payload = JSON.stringify({
    answer,
    powChallenge,
    powDifficulty: POW_DIFFICULTY,
    issuedAt,
    nonceId,
  });
  const token = Buffer.from(payload).toString('base64url') + '.' + sign(payload);

  return {
    token,
    question,
    powChallenge,
    powDifficulty: POW_DIFFICULTY,
    issuedAt,
  };
}

function countLeadingZeroBits(hexDigest) {
  let bits = 0;
  for (const ch of hexDigest) {
    const nibble = parseInt(ch, 16);
    if (nibble === 0) {
      bits += 4;
      continue;
    }
    bits += Math.clz32(nibble) - 28;
    break;
  }
  return bits;
}

function verify({ token, answer, powNonce, honeypot, usedTokens }) {
  if (honeypot && honeypot.trim() !== '') return { ok: false, reason: 'honeypot' };
  if (!token || typeof token !== 'string') return { ok: false, reason: 'missing token' };

  const [b64, sig] = token.split('.');
  if (!b64 || !sig) return { ok: false, reason: 'malformed token' };

  let payload;
  try {
    payload = Buffer.from(b64, 'base64url').toString('utf8');
  } catch {
    return { ok: false, reason: 'malformed token' };
  }
  const expected = sign(payload);
  const a = Buffer.from(sig, 'hex');
  const b = Buffer.from(expected, 'hex');
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return { ok: false, reason: 'bad signature' };
  }

  let data;
  try {
    data = JSON.parse(payload);
  } catch {
    return { ok: false, reason: 'bad payload' };
  }

  const age = Date.now() - data.issuedAt;
  if (age > TOKEN_TTL_MS) return { ok: false, reason: 'expired — reload the page' };
  if (age < MIN_SOLVE_MS) return { ok: false, reason: 'too fast — slow down' };

  if (usedTokens && usedTokens.has(data.nonceId)) {
    return { ok: false, reason: 'token already used' };
  }

  const parsedAnswer = parseInt(String(answer).trim(), 10);
  if (Number.isNaN(parsedAnswer) || parsedAnswer !== data.answer) {
    return { ok: false, reason: 'wrong math answer' };
  }

  if (!powNonce || typeof powNonce !== 'string') {
    return { ok: false, reason: 'missing proof-of-work' };
  }
  const hash = crypto.createHash('sha256').update(data.powChallenge + powNonce).digest('hex');
  if (countLeadingZeroBits(hash) < data.powDifficulty) {
    return { ok: false, reason: 'invalid proof-of-work' };
  }

  if (usedTokens) usedTokens.add(data.nonceId);
  return { ok: true };
}

const usedTokens = new Set();
setInterval(() => {
  if (usedTokens.size > 100000) usedTokens.clear();
}, 60 * 60 * 1000).unref?.();

module.exports = { issue, verify, usedTokens };
