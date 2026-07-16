/* ===================================================================
   THE BLACKWALL BAZAAR — matrix rain + ICE FLARE client
   =================================================================== */
(function () {
  // ---- matrix rain --------------------------------------------------
  const canvas = document.getElementById('matrix');
  if (canvas) {
    const ctx = canvas.getContext('2d');
    const glyphs = 'ｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉ0123456789$#%&@ABCDEF'.split('');
    let cols, drops, fontSize = 14;

    function resize() {
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
      cols = Math.floor(canvas.width / fontSize);
      drops = new Array(cols).fill(1);
    }
    resize();
    window.addEventListener('resize', resize);

    function draw() {
      ctx.fillStyle = 'rgba(7,9,10,0.08)';
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.fillStyle = '#39ff14';
      ctx.font = fontSize + 'px monospace';
      for (let i = 0; i < drops.length; i++) {
        const ch = glyphs[Math.floor(Math.random() * glyphs.length)];
        ctx.fillText(ch, i * fontSize, drops[i] * fontSize);
        if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) drops[i] = 0;
        drops[i]++;
      }
    }
    setInterval(draw, 55);
  }

  // ---- ICE FLARE (VHS chromatic strip glitch) -----------------------
  let overlay = document.getElementById('ice-flare');
  if (!overlay) {
    overlay = document.createElement('div');
    overlay.id = 'ice-flare';
    overlay.innerHTML = '<div class="ice-stage"></div>';
    document.body.appendChild(overlay);
  }
  const stage = overlay.querySelector('.ice-stage');
  const N_STRIPS = 12;
  const DURATION = 2400; // ms — long enough to read

  function escapeHtml(s) {
    return String(s).replace(/[&<>"]/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c];
    });
  }

  let firing = false;
  window.fireIceFlare = function (text) {
    if (firing) return;
    firing = true;
    const msg = '▓▓ ' + escapeHtml(text || 'TRACE SPIKE') + ' ▓▓';
    const band = 100 / N_STRIPS;
    let html = '';
    for (let i = 0; i < N_STRIPS; i++) {
      const left = (i * band).toFixed(3);
      const right = (100 - (i + 1) * band).toFixed(3);
      // unique negative delay per strip -> each sits at a different phase of the
      // jitter loop, so the strips slide offset from one another
      const delay = -(i * 0.043 + (i % 4) * 0.021).toFixed(3);
      const clip = 'inset(0 ' + right + '% 0 ' + left + '%)';
      html += '<div class="ice-strip" style="clip-path:' + clip + ';-webkit-clip-path:' + clip
            + ';animation-delay:' + delay + 's">' + msg + '</div>';
    }
    stage.innerHTML = html;
    overlay.classList.remove('active');
    void overlay.offsetWidth; // reflow to restart
    overlay.classList.add('active');
    setTimeout(() => { overlay.classList.remove('active'); firing = false; }, DURATION);
  };

  // ---- poll the server for breach events ----------------------------
  async function pollFlares() {
    try {
      const r = await fetch('/api/flare', { credentials: 'same-origin' });
      if (!r.ok) return;
      const data = await r.json();
      if (data.flares && data.flares.length) {
        // fire them one at a time
        data.flares.forEach((f, i) => setTimeout(() => window.fireIceFlare(f.msg), i * 900));
      }
    } catch (e) { /* ignore */ }
  }
  setInterval(pollFlares, 2000);
  pollFlares();
})();
