<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>Admin Login — Jojin's Kitty Thrift</title>
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg'><text y='32' font-size='32'>🐾</text></svg>">

<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Special+Elite&family=Libre+Baskerville:ital,wght@0,400;0,700;1,400&family=IBM+Plex+Mono:wght@400;500&display=swap" rel="stylesheet">

<style>
  :root {
    --paper: #E3D1AA;
    --paper-dark: #C2A16E;
    --card: #F7F0E0;
    --ink: #2B2420;
    --ink-soft: #6B5A45;
    --stamp: #A63A2E;
    --thread: #6E7C5E;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    font-family: 'Libre Baskerville', serif;
    color: var(--ink);
    background: var(--paper);
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
  }
  .card {
    width: 100%;
    max-width: 340px;
    background: var(--card);
    border-radius: 8px;
    padding: 28px 24px;
    margin: 20px;
    box-shadow: 0 8px 24px rgba(43,36,32,0.18);
    text-align: center;
  }
  .eyebrow {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 11px;
    letter-spacing: 0.14em;
    text-transform: uppercase;
    color: var(--stamp);
    margin: 0 0 6px;
  }
  h1 {
    font-family: 'Special Elite', monospace;
    font-size: 22px;
    margin: 0 0 18px;
  }
  input {
    width: 100%;
    font-family: 'IBM Plex Mono', monospace;
    font-size: 15px;
    text-align: center;
    letter-spacing: 0.1em;
    padding: 12px;
    border: 1.5px solid var(--paper-dark);
    border-radius: 6px;
    background: #fff;
    color: var(--ink);
  }
  button {
    width: 100%;
    margin-top: 12px;
    font-family: 'IBM Plex Mono', monospace;
    font-weight: 600;
    font-size: 13.5px;
    letter-spacing: 0.05em;
    text-transform: uppercase;
    color: #fff;
    background: var(--thread);
    border: none;
    border-radius: 6px;
    padding: 12px;
    cursor: pointer;
  }
  button:disabled { opacity: .6; cursor: default; }
  .err {
    margin-top: 12px;
    font-size: 13px;
    color: var(--stamp);
    display: none;
  }
</style>
</head>
<body>
  <div class="card">
    <p class="eyebrow">Staff only</p>
    <h1>🔒 Enter Key</h1>
    <input type="password" id="keyInput" placeholder="Access key" autofocus />
    <button id="submitBtn">Unlock</button>
    <p class="err" id="errBox"></p>
  </div>

<script>
(function () {
  const keyInput = document.getElementById('keyInput');
  const submitBtn = document.getElementById('submitBtn');
  const errBox = document.getElementById('errBox');

  async function submit() {
    const password = keyInput.value.trim();
    if (!password) return;

    submitBtn.disabled = true;
    submitBtn.textContent = 'Checking…';
    errBox.style.display = 'none';

    try {
      const res = await fetch('/api/admin-login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Incorrect key');

      const params = new URLSearchParams(window.location.search);
      const next = params.get('next') || '/admin.html';
      window.location.href = next;
    } catch (err) {
      errBox.textContent = err.message;
      errBox.style.display = 'block';
      submitBtn.disabled = false;
      submitBtn.textContent = 'Unlock';
      keyInput.value = '';
      keyInput.focus();
    }
  }

  submitBtn.addEventListener('click', submit);
  keyInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') submit(); });
})();
</script>
</body>
</html>
