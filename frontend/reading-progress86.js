// Use the browser's scroll timeline when available. The fallback only measures
// document height after layout changes, never on the ordinary scroll path.
export function initReadingProgress(progress) {
  if (!progress) return () => {};
  if (typeof ScrollTimeline === 'function' && typeof progress.animate === 'function') {
    try {
      const animation = progress.animate([{transform: 'scaleX(0)'}, {transform: 'scaleX(1)'}], {
        timeline: new ScrollTimeline({source: document.scrollingElement, axis: 'block'}),
        duration: 1000, fill: 'both', easing: 'linear'
      });
      return () => animation.cancel();
    } catch {}
  }

  let frame = 0, documentHeight = 0, layoutNeeded = true, lastProgress = -1;
  let viewportWidth = innerWidth, suspended = false, destroyed = false;
  const update = () => {
    frame = 0;
    if (suspended || destroyed || document.hidden) return;
    if (layoutNeeded) {
      documentHeight = document.documentElement.scrollHeight;
      layoutNeeded = false;
    }
    const total = documentHeight - innerHeight;
    const value = total > 0 ? Math.max(0, Math.min(1, scrollY / total)) : 0;
    if (value !== lastProgress) {
      progress.style.transform = `scaleX(${value})`;
      lastProgress = value;
    }
  };
  const schedule = () => {
    if (!frame && !suspended && !destroyed && !document.hidden) frame = requestAnimationFrame(update);
  };
  const invalidate = () => { layoutNeeded = true; schedule(); };
  const sizing = typeof ResizeObserver === 'function' ? new ResizeObserver(invalidate) : null;
  sizing?.observe(document.documentElement);
  if (document.body) sizing?.observe(document.body);
  const resize = () => {
    if (innerWidth !== viewportWidth || !sizing) {
      viewportWidth = innerWidth;
      layoutNeeded = true;
    }
    schedule();
  };
  const loaded = event => {
    if (event.target instanceof HTMLImageElement && event.target.closest('.content-performance,.animation-sprite')) return;
    invalidate();
  };
  const visibility = () => {
    if (document.hidden) { cancelAnimationFrame(frame); frame = 0; }
    else invalidate();
  };
  const hide = () => { suspended = true; cancelAnimationFrame(frame); frame = 0; };
  const show = event => { if (event.persisted) { suspended = false; invalidate(); } };
  addEventListener('scroll', schedule, {passive: true});
  addEventListener('resize', resize, {passive: true});
  addEventListener('pagehide', hide);
  addEventListener('pageshow', show);
  document.addEventListener('visibilitychange', visibility);
  document.addEventListener('load', loaded, true);
  document.addEventListener('anazori:layout', invalidate);
  document.addEventListener('toggle', invalidate, true);
  document.fonts?.ready.then(() => { if (!destroyed) invalidate(); });
  update();
  return () => {
    destroyed = true;
    cancelAnimationFrame(frame);
    sizing?.disconnect();
    removeEventListener('scroll', schedule);
    removeEventListener('resize', resize);
    removeEventListener('pagehide', hide);
    removeEventListener('pageshow', show);
    document.removeEventListener('visibilitychange', visibility);
    document.removeEventListener('load', loaded, true);
    document.removeEventListener('anazori:layout', invalidate);
    document.removeEventListener('toggle', invalidate, true);
  };
}
