// An SVG/HTML festival world: no rendering loop, downloads, or WebGL requirement.
export function initWorldAtlas() {
  const atlas = document.querySelector('[data-world-atlas]');
  if (!atlas || atlas.dataset.initialized) return;
  atlas.dataset.initialized = 'true';
  const root = document.documentElement;
  const choices = [...atlas.querySelectorAll('[data-atlas-select]')];
  const worlds = [...atlas.querySelectorAll('[data-atlas-world]')];
  const routes = [...atlas.querySelectorAll('[data-atlas-route]')];
  const name = atlas.querySelector('.atlas-core-name');
  const count = atlas.querySelector('.atlas-core-count');
  const status = atlas.querySelector('.atlas-status');
  const reduced = matchMedia('(prefers-reduced-motion: reduce)');
  const connection = navigator.connection;
  let visible = false;
  let active = '';
  const syncMotion = () => {
    atlas.classList.toggle('atlas-still', !visible || document.hidden || reduced.matches || root.classList.contains('motion-paused') || !!connection?.saveData);
  };
  const select = (category, announce = true) => {
    const selected = worlds.find(world => world.dataset.atlasWorld === category);
    if (!selected || active === category) return;
    active = category;
    atlas.dataset.world = category;
    for (const world of worlds) world.hidden = world !== selected;
    for (const choice of choices) choice.setAttribute('aria-pressed', String(choice.dataset.atlasSelect === category));
    for (const route of routes) route.classList.toggle('is-active', route.dataset.atlasRoute === category);
    name.textContent = selected.dataset.atlasLabel;
    const total = Number(selected.dataset.atlasCount);
    count.textContent = `${total} ${total === 1 ? 'event' : 'events'}`;
    if (announce) status.textContent = `${selected.dataset.atlasLabel}: ${total} ${total === 1 ? 'experience' : 'experiences'} shown.`;
    document.dispatchEvent(new Event('anazori:layout'));
  };
  const click = event => {
    const choice = event.target.closest('[data-atlas-select]');
    if (choice && atlas.contains(choice)) select(choice.dataset.atlasSelect);
  };
  // All event links remain readable when JavaScript is unavailable.
  for (const choice of choices) choice.hidden = false;
  select(worlds.find(world => Number(world.dataset.atlasCount) > 0)?.dataset.atlasWorld || worlds[0]?.dataset.atlasWorld, false);
  atlas.classList.add('atlas-ready');
  atlas.addEventListener('click', click);
  const observer = typeof IntersectionObserver === 'function' ? new IntersectionObserver(entries => {
    visible = entries[0].isIntersecting;
    syncMotion();
  }, { threshold: .05 }) : null;
  if (observer) observer.observe(atlas); else visible = true;
  reduced.addEventListener('change', syncMotion);
  connection?.addEventListener?.('change', syncMotion);
  document.addEventListener('anazori:motion', syncMotion);
  document.addEventListener('visibilitychange', syncMotion);
  syncMotion();
  const hide = event => {
    atlas.classList.add('atlas-still');
    if (event.persisted) return;
    observer?.disconnect();
    reduced.removeEventListener('change', syncMotion);
    connection?.removeEventListener?.('change', syncMotion);
    document.removeEventListener('anazori:motion', syncMotion);
    document.removeEventListener('visibilitychange', syncMotion);
    atlas.removeEventListener('click', click);
    removeEventListener('pagehide', hide);
    removeEventListener('pageshow', show);
  };
  const show = event => { if (event.persisted) syncMotion(); };
  addEventListener('pagehide', hide);
  addEventListener('pageshow', show);
}
