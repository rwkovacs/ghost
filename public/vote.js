document.querySelectorAll('button.vote').forEach(btn => {
  btn.addEventListener('click', async () => {
    const kind = btn.dataset.kind;
    const id = btn.dataset.id;
    const value = parseInt(btn.dataset.value, 10);
    const body = new URLSearchParams({ kind, target_id: id, value: String(value) });
    const res = await fetch('/vote', { method: 'POST', body });
    if (!res.ok) return;
    const json = await res.json();
    const scoreEl = kind === 'post'
      ? document.getElementById('post-score')
      : document.getElementById('c-score-' + id);
    if (scoreEl) scoreEl.textContent = json.score;
  });
});
