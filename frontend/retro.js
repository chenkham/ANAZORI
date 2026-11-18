export function initRetro() {
  const root = document.documentElement;
  const deck = document.querySelector('.culture-tech');
  const mix = document.querySelector('#frequency-mix');
  const output = document.querySelector('#frequency-status');
  if (deck && mix) {
    let previousValue;
    const tune = () => {
      const value = Number(mix.value);
      if (value === previousValue) return;
      previousValue = value;
      deck.dataset.frequency = String(value);
      deck.style.setProperty('--mix', value / 100);
      deck.style.setProperty('--mix-hue', `${value * 1.65}deg`);
      deck.style.setProperty('--record-speed', `${26 - value * .16}s`);
      const label = value < 35 ? 'Rooted in culture' : value > 65 ? 'Wired for tomorrow' : 'In harmony';
      if (output && output.textContent !== label) output.textContent = label;
      mix.setAttribute('aria-valuetext', `${value}% tech, ${100 - value}% culture. ${label}`);
    };
    mix.addEventListener('input', tune);
    tune();
    let inView = false, suspended = false;
    const syncVisibility = () => deck.classList.toggle('is-in-view', inView && !document.hidden && !suspended);
    const observer = new IntersectionObserver(entries => {
      inView = entries[0].isIntersecting;
      syncVisibility();
    }, {rootMargin: '40px'});
    observer.observe(deck);
    const stage = deck.querySelector('.record-stage');
    const interactive = matchMedia('(hover:hover) and (pointer:fine)');
    const legacyTilt = stage && !stage.querySelector('.portal-canvas');
    let frame = 0, geometryDirty = true, centerX = 0, centerY = 0, pointerX = 0, pointerY = 0, tiltX = '0deg', tiltY = '0deg';
    const invalidateGeometry = () => { geometryDirty = true; };
    const renderTilt = () => {
      frame = 0;
      if (!legacyTilt || !interactive.matches || document.hidden || suspended || root.classList.contains('motion-paused')) return;
      if (geometryDirty) {
        const box = stage.getBoundingClientRect();
        centerX = box.left + box.width / 2; centerY = box.top + box.height / 2;
        geometryDirty = false;
      }
      const nextX = `${Math.max(-10, Math.min(10, -(pointerY - centerY) / 22)).toFixed(3)}deg`;
      const nextY = `${Math.max(-10, Math.min(10, (pointerX - centerX) / 22)).toFixed(3)}deg`;
      if (nextX !== tiltX) { tiltX = nextX; stage.style.setProperty('--tilt-x', nextX); }
      if (nextY !== tiltY) { tiltY = nextY; stage.style.setProperty('--tilt-y', nextY); }
    };
    const move = event => {
      if (!legacyTilt || !interactive.matches || document.hidden || suspended || root.classList.contains('motion-paused')) return;
      pointerX = event.clientX; pointerY = event.clientY;
      if (!frame) frame = requestAnimationFrame(renderTilt);
    };
    const resetTilt = () => {
      cancelAnimationFrame(frame); frame = 0;
      if (!stage) return;
      tiltX = tiltY = '0deg';
      stage.style.setProperty('--tilt-x', '0deg');
      stage.style.setProperty('--tilt-y', '0deg');
      geometryDirty = true;
    };
    const visibility = () => { syncVisibility(); if (document.hidden) resetTilt(); };
    const motion = () => { if (root.classList.contains('motion-paused')) resetTilt(); };
    deck.addEventListener('pointerenter', invalidateGeometry, {passive: true});
    deck.addEventListener('pointermove', move, {passive: true});
    deck.addEventListener('pointerleave', resetTilt);
    addEventListener('scroll', invalidateGeometry, {passive: true});addEventListener('resize', invalidateGeometry, {passive: true});
    document.addEventListener('visibilitychange', visibility);document.addEventListener('anazori:motion', motion);
    interactive.addEventListener('change', resetTilt);
    addEventListener('pagehide', event => {
      suspended = true;resetTilt();syncVisibility();if (event.persisted) return;
      observer.disconnect();mix.removeEventListener('input', tune);
      deck.removeEventListener('pointerenter', invalidateGeometry);deck.removeEventListener('pointermove', move);deck.removeEventListener('pointerleave', resetTilt);
      removeEventListener('scroll', invalidateGeometry);removeEventListener('resize', invalidateGeometry);
      document.removeEventListener('visibilitychange', visibility);document.removeEventListener('anazori:motion', motion);
      interactive.removeEventListener('change', resetTilt);
    });
    addEventListener('pageshow', event => { if (event.persisted) { suspended = false;invalidateGeometry();syncVisibility(); } });
  }
}
