(function () {
  const tokenInput = document.querySelector('input[name="captcha_token"]');
  if (!tokenInput) return;
  const challenge = document.getElementById('pow_challenge').value;
  const difficulty = parseInt(document.getElementById('pow_difficulty').value, 10);
  const status = document.getElementById('pow_status');
  const form = tokenInput.closest('form');
  const submit = form ? form.querySelector('button[type="submit"]') : null;
  if (submit) submit.disabled = true;

  function leadingZeroBits(bytes) {
    let bits = 0;
    for (const b of bytes) {
      if (b === 0) { bits += 8; continue; }
      let n = b, c = 0;
      while ((n & 0x80) === 0) { c++; n <<= 1; }
      bits += c;
      break;
    }
    return bits;
  }

  async function sha256Bytes(str) {
    const data = new TextEncoder().encode(str);
    const buf = await crypto.subtle.digest('SHA-256', data);
    return new Uint8Array(buf);
  }

  (async () => {
    status.textContent = 'solving proof-of-work (difficulty ' + difficulty + ')…';
    const started = Date.now();
    let nonce = 0;
    while (true) {
      const batchEnd = nonce + 2000;
      for (; nonce < batchEnd; nonce++) {
        const candidate = nonce.toString(36);
        const digest = await sha256Bytes(challenge + candidate);
        if (leadingZeroBits(digest) >= difficulty) {
          document.getElementById('pow_nonce').value = candidate;
          const elapsed = ((Date.now() - started) / 1000).toFixed(1);
          status.textContent = '✓ proof-of-work solved in ' + elapsed + 's (nonce ' + nonce + ')';
          if (submit) submit.disabled = false;
          return;
        }
      }
      await new Promise(r => setTimeout(r, 0));
      status.textContent = 'solving proof-of-work… (tried ' + nonce + ')';
    }
  })();
})();
