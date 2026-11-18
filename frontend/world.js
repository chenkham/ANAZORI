export function initWorld() {
  const root = document.documentElement;
  const paused = () => root.classList.contains('motion-paused');
  const reduced = matchMedia('(prefers-reduced-motion: reduce)');
  const fine = matchMedia('(hover: hover) and (pointer: fine)');

  // One delegated pointer listener adds local holographic lighting to content modules.
  let surface, bounds, listening = false, suspended = false, destroyed = false;
  const surfaces = '.event-card,.gallery-item,.person-card';
  const clear = () => {
    surface?.style.removeProperty('--card-x'); surface?.style.removeProperty('--card-y');
    surface = bounds = null;
  };
  const light = event => {
    if (!fine.matches || reduced.matches || paused()) return;
    const next = event.target.closest(surfaces);
    if (next !== surface) { clear(); surface = next; bounds = next?.getBoundingClientRect(); }
    if (!bounds) return;
    surface.style.setProperty('--card-x', `${Math.round((event.clientX-bounds.left)/bounds.width*100)}%`);
    surface.style.setProperty('--card-y', `${Math.round((event.clientY-bounds.top)/bounds.height*100)}%`);
  };
  const sync = () => {
    const enabled = fine.matches && !paused() && !reduced.matches && !document.hidden && !suspended && !destroyed;
    if (enabled === listening) return;
    listening = enabled;
    if (enabled) {
      document.addEventListener('pointermove',light,{passive:true});
      document.addEventListener('pointerleave',clear);
    } else {
      document.removeEventListener('pointermove',light);
      document.removeEventListener('pointerleave',clear);
      clear();
    }
  };
  document.addEventListener('anazori:motion',sync);
  document.addEventListener('visibilitychange',sync);
  reduced.addEventListener('change',sync);
  fine.addEventListener('change',sync);
  const hide = event => {
    suspended = true; sync(); clear();
    if (event.persisted) return;
    destroyed = true;
    document.removeEventListener('pointermove',light); document.removeEventListener('pointerleave',clear);
    document.removeEventListener('anazori:motion',sync); document.removeEventListener('visibilitychange',sync);
    reduced.removeEventListener('change',sync);
    fine.removeEventListener('change',sync);
    removeEventListener('pagehide',hide); removeEventListener('pageshow',show);
  };
  const show = event => { if (event.persisted) { suspended = false; sync(); } };
  addEventListener('pagehide',hide); addEventListener('pageshow',show);
  sync();
}
