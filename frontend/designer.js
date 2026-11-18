// Local lighting follows the pointer, without an animation loop or layout reads per move.
export function initDesigner() {
  const frame = document.querySelector('.nav-shell');
  if (!frame || !matchMedia('(hover: hover) and (pointer: fine)').matches) return;
  const reduced = matchMedia('(prefers-reduced-motion: reduce)');
  let bounds;
  frame.addEventListener('pointerenter', () => { bounds = frame.getBoundingClientRect(); });
  frame.addEventListener('pointermove', event => {
    if (!bounds || reduced.matches || document.documentElement.classList.contains('motion-paused')) return;
    frame.style.setProperty('--light-x', `${Math.round((event.clientX - bounds.left) / bounds.width * 100)}%`);
    frame.style.setProperty('--light-y', `${Math.round((event.clientY - bounds.top) / bounds.height * 100)}%`);
  });
  frame.addEventListener('pointerleave', () => {
    frame.style.removeProperty('--light-x');
    frame.style.removeProperty('--light-y');
  });
}
