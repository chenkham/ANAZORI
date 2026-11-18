// Keep the same decorative animation while visible, and sleep its clocks outside the viewport.
export function initAmbientMotion() {
  if (typeof IntersectionObserver !== 'function') return;
  const sections = [...document.querySelectorAll('.festival-glass-background,.hero,.ticker,.festival-clock,.intro,.programme-section,.culture-tech,.memories,.partners,.visit,.site-footer,.gallery-section')];
  const visible = new Set();
  let suspended = false;
  const sync = () => sections.forEach(section => section.classList.toggle('motion-outside', suspended || document.hidden || !visible.has(section)));
  sections.forEach(section => section.classList.add('motion-outside'));
  const observer = new IntersectionObserver(entries => {
    for (const entry of entries) {
      if (entry.isIntersecting) visible.add(entry.target); else visible.delete(entry.target);
      entry.target.classList.toggle('motion-outside', suspended || document.hidden || !entry.isIntersecting);
    }
  }, {rootMargin: '160px'});
  sections.forEach(section => observer.observe(section));
  const hide = event => {
    suspended = true; sync();
    if (event.persisted) return;
    observer.disconnect();
    document.removeEventListener('visibilitychange', sync);
    removeEventListener('pagehide', hide); removeEventListener('pageshow', show);
  };
  const show = event => { if (event.persisted) { suspended = false; sync(); } };
  document.addEventListener('visibilitychange', sync);
  addEventListener('pagehide', hide); addEventListener('pageshow', show);
}
