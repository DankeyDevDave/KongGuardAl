// Lightweight overlay for demo recordings
(function () {
  const style = document.createElement('style');
  style.innerHTML = `
    #kg-overlay { position: fixed; left: 20px; bottom: 20px; z-index: 999999; font-family: ui-sans-serif, system-ui, -apple-system; }
    #kg-card { background: rgba(0,0,0,0.6); color: #fff; padding: 12px 14px; border-radius: 12px; box-shadow: 0 10px 30px rgba(0,0,0,0.35); min-width: 340px; }
    #kg-title { font-weight: 600; font-size: 14px; letter-spacing: .2px; }
    #kg-sub { font-size: 12px; opacity: 0.9; margin-top: 2px; }
    #kg-progress { width: 100%; height: 6px; background: rgba(255,255,255,0.2); border-radius: 999px; margin-top: 10px; overflow: hidden; }
    #kg-bar { height: 100%; width: 0%; background: linear-gradient(90deg,#a1c4fd,#c2e9fb); transition: width .2s ease; }
    .kg-highlight { outline: 3px solid #8ab4ff; border-radius: 8px; transition: outline-color .2s; animation: kgPulse 1s infinite alternate; }
    @keyframes kgPulse { from { outline-color: #8ab4ff; } to { outline-color: #c2e9fb; } }
    #kg-shot { position: fixed; inset: 0; background: rgba(255,255,255,0.8); z-index: 2147483647; opacity: 0; transition: opacity .15s; pointer-events:none; }
  `;
  document.head.appendChild(style);

  const overlay = document.createElement('div');
  overlay.id = 'kg-overlay';
  overlay.innerHTML = `<div id="kg-card">
    <div id="kg-title">Kong Guard AI</div>
    <div id="kg-sub">Ready</div>
    <div id="kg-progress"><div id="kg-bar"></div></div>
  </div>`;
  document.body.appendChild(overlay);

  const flash = document.createElement('div');
  flash.id = 'kg-shot';
  document.body.appendChild(flash);

  const $, $$ = (sel) => document.querySelector(sel), (sel) => document.querySelectorAll(sel);
  function setText(id, text) { const el = document.getElementById(id); if (el) el.textContent = text; }
  function setProgress(pct) { const bar = document.getElementById('kg-bar'); if (bar) bar.style.width = Math.max(0, Math.min(100, pct)) + '%'; }

  window.kgVisualEffects = {
    setScene: (title, sub) => { setText('kg-title', title || 'Kong Guard AI'); setText('kg-sub', sub || ''); },
    updateProgress: (pct) => setProgress(pct),
    highlight: (selector, ms=1600) => {
      const el = document.querySelector(selector);
      if (!el) return false;
      el.classList.add('kg-highlight');
      setTimeout(() => el.classList.remove('kg-highlight'), ms);
      return true;
    },
    showScreenshotFlash: () => {
      const el = document.getElementById('kg-shot');
      if (!el) return;
      el.style.opacity = '1';
      setTimeout(() => { el.style.opacity = '0'; }, 150);
    }
  };
})();
