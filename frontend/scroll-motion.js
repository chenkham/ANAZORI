// Native scroll timelines run without per-scroll JavaScript. Older browsers share one cached fallback.
export function initScrollMotion() {
  const root = document.documentElement;
  if (!document.body.matches('.page-home,.page-events,.page-gallery,.page-teams')) return;
  if (typeof Element.prototype.animate !== 'function' || typeof IntersectionObserver !== 'function') return;
  if (!CSS.supports('translate', '0px 0px') || !CSS.supports('scale', '1') || !CSS.supports('rotate', '0deg')) return;
  const reduced = matchMedia('(prefers-reduced-motion: reduce)');
  const compact = matchMedia('(max-width: 760px)');
  const printing = matchMedia('print');
  const connection = navigator.connection;
  const anchors = new Map();
  const actors = [];
  const activeScenes = new Set();
  let timeline = null;
  if (typeof ScrollTimeline === 'function' && 'rangeStart' in Animation.prototype) {
    try { timeline = new ScrollTimeline({source: document.scrollingElement, axis: 'block'}); } catch {}
  }
  root.dataset.scrollEngine = timeline ? 'native' : 'fallback';
  let frame = 0, measureNeeded = true, viewportNeeded = true, enabled = false, destroyed = false, suspended = false;
  let viewport = innerHeight, layoutWidth = innerWidth, distance = compact.matches ? .45 : 1;
  const clamp = value => Math.max(0, Math.min(1, value));
  const px = value => `${(value * distance).toFixed(2)}px`;
  const xy = (x, y) => `${px(x)} ${px(y)}`;
  const tilt = value => `${(value * distance).toFixed(2)}deg`;
  const allowed = () => !printing.matches && !reduced.matches && !root.classList.contains('motion-paused') && !connection?.saveData;
  const layoutTop = (element, offsets) => {
    if (!element) return 0;
    if (offsets.has(element)) return offsets.get(element);
    const top = element.offsetTop + layoutTop(element.offsetParent, offsets);
    offsets.set(element, top);
    return top;
  };

  const add = (element, anchor, name, keys, start = .08, end = .4, mode = 'view') => {
    if (!element || !anchor) return;
    if (!anchors.has(anchor)) anchors.set(anchor, {element: anchor, top: 0, height: 1, visible: false, actors: []});
    const scene = anchors.get(anchor);
    const actor = {element, scene, name, keys, start, end, mode, animation: null, focused: false};
    element.dataset.scrollMotion = name;
    scene.actors.push(actor); actors.push(actor);
  };
  const enter = (x = 0, y = 45, rotation = 0, scale = 1) => () => [
    {translate: xy(x, y), rotate: tilt(rotation), scale: String(scale), easing: 'cubic-bezier(.2,.75,.25,1)'},
    {translate: '0px 0px', rotate: '0deg', scale: '1'}
  ];
  const heading = (section, selector = 'h2') => {
    const title = section?.querySelector(selector);
    add(title, title, 'section-heading', enter(0, 44), .02, .3);
  };

  const hero = document.querySelector('.hero');
  const page = document.querySelector('main');
  // Scenery moves across the full page using the same timeline and motion controls.
  add(document.querySelector('.voxel-world-island'), page, 'voxel-island', () => [
    {translate: '0px 0px'}, {translate: xy(-30, -115)}
  ], 0, 1, 'hero');
  add(document.querySelector('.voxel-world-island-small'), page, 'voxel-small-island', () => [
    {translate: '0px 0px'}, {translate: xy(28, 65)}
  ], 0, 1, 'hero');
  add(hero?.querySelector('#hero-film'), hero, 'hero-film', () => [
    {translate: '0px 0px', scale: '1.035'}, {translate: xy(0, 45), scale: compact.matches ? '1.075' : '1.11'}
  ], 0, 1, 'hero');
  add(hero?.querySelector('.hero-wordmark'), hero, 'hero-title', () => [
    {translate: '0px 0px', scale: '1'}, {translate: xy(0, -100), scale: '.97'}
  ], 0, 1, 'hero');
  add(hero?.querySelector('.hero-copy h2'), hero, 'hero-headline', () => [
    {translate: '0px 0px'}, {translate: xy(0, -36)}
  ], 0, 1, 'hero');
  const clock = document.querySelector('.festival-clock');
  add(clock?.querySelector('.clock-card'), clock, 'clock-card', enter(-48, 38, -2, .97), .06, .36);
  add(clock?.querySelector('.duration-card'), clock, 'duration-card', enter(48, 38, 2, .97), .1, .4);
  const intro = document.querySelector('.intro');
  heading(intro);
  add(intro?.querySelector('.intro-bottom'), intro, 'intro-copy', enter(0, 28), .1, .38);

  heading(document.querySelector('.programme-section'));

  const culture = document.querySelector('.culture-tech');
  add(culture?.querySelector('.record-stage'), culture, 'vinyl-stage', enter(0, 48, -5, .91), .04, .35);
  add(culture?.querySelector('.record-orbit'), culture, 'vinyl-orbit', () => [
    {rotate: tilt(-28)}, {rotate: tilt(28)}
  ], 0, 1);
  const memories = document.querySelector('.memories');
  heading(memories);
  memories?.querySelectorAll('.memory-main > img').forEach(photo => add(photo, memories, 'memory-photo', () => [
    {translate: xy(0, -12), scale: '1.085'},
    {translate: xy(0, 12), scale: '1.085'}
  ], 0, 1));
  add(memories?.querySelector('.memory-side'), memories, 'memory-side', enter(36, 28), .07, .38);
  const partners = document.querySelector('.partners');
  heading(partners);
  partners?.querySelectorAll('.sponsor-bento > *').forEach((card, index) => {
    // Each tile has its own stable grid cell. Stagger still works in the mobile bento layout.
    add(card, card, `sponsor-${index}`, enter(0, index === 0 ? 54 : 72, index === 1 ? -2 : index === 2 ? 2 : 0, .98), .06 + index * .035, .44 + index * .035);
  });
  const visit = document.querySelector('.visit');
  heading(visit);
  add(visit?.querySelector('.faq'), visit, 'visit-faq', enter(0, 36), .1, .4);
  const footer = document.querySelector('.site-footer');
  add(footer?.querySelector('.footer-wordmark'), footer, 'footer-wordmark', enter(0, 52, 0, .98), .04, .43);

  // Other public pages get restrained entrances; account, checkout and Studio remain static.
  document.querySelectorAll('.event-list .event-card,.gallery-grid .gallery-item,.team-section .person-card').forEach((card, index) => {
    add(card, card, 'catalogue-card', enter(0, 36), .03 + index % 3 * .02, .45 + index % 3 * .02);
  });
  if (!actors.length) return;

  const seek = (actor, progress) => {
    const value = actor.focused ? 1 : progress;
    if (actor.animation && actor.lastProgress !== value) {
      actor.animation.currentTime = value * 1000; actor.lastProgress = value;
    }
  };
  const ranges = actor => {
    const {top, height} = actor.scene;
    const origin = actor.mode === 'hero' ? top : top - viewport;
    const span = actor.mode === 'hero' ? height : viewport + height;
    return {rangeStart: `${origin + span * actor.start}px`, rangeEnd: `${origin + span * actor.end}px`};
  };
  const stop = actor => { actor.animation?.cancel(); actor.animation = null; actor.lastProgress = null; actor.range = null; };
  const compositorKeys = actor => actor.keys().map(({translate, rotate, scale, ...key}) => ({
    ...key,
    transform: [translate && `translate(${translate.replace(' ', ',')})`, rotate && `rotate(${rotate})`, scale && `scale(${scale})`].filter(Boolean).join(' ') || 'none',
    // Add to existing CSS transforms, preserving circular-node positioning and pointer tilt.
    composite: 'add'
  }));
  const activate = (scene, refreshRanges) => {
    for (const actor of scene.actors) {
      if ((timeline && actor.focused)) { stop(actor); continue; }
      if (actor.animation) {
        if (timeline && refreshRanges) {
          const range = ranges(actor);
          if (actor.range?.rangeStart !== range.rangeStart) actor.animation.rangeStart = range.rangeStart;
          if (actor.range?.rangeEnd !== range.rangeEnd) actor.animation.rangeEnd = range.rangeEnd;
          actor.range = range;
        }
        continue;
      }
      actor.range = timeline ? ranges(actor) : null;
      actor.animation = actor.element.animate(timeline ? compositorKeys(actor) : actor.keys(), {
        duration: 1000, fill: 'both', easing: 'linear', ...(timeline ? {timeline, ...actor.range} : {})
      });
      if (!timeline) { actor.animation.pause(); seek(actor, actor.mode === 'hero' ? 0 : 1); }
    }
  };
  const render = () => {
    frame = 0;
    if (!enabled || suspended || destroyed || document.hidden) return;
    const scroll = scrollY;
    const refreshRanges = measureNeeded || viewportNeeded;
    if (refreshRanges) viewport = innerHeight;
    if (measureNeeded) {
      // Natural layout offsets exclude animated translations, including on a tile used as its own anchor.
      // Share ancestor offsets and finish every geometry read before touching animations.
      const offsets = new Map();
      layoutWidth = innerWidth;
      for (const scene of anchors.values()) {
        scene.top = layoutTop(scene.element, offsets);
        scene.height = Math.max(1, scene.element.offsetHeight);
      }
    }
    if (refreshRanges) {
      for (const scene of anchors.values()) {
        const entering = scene.top <= scroll + viewport + 240 && scene.top + scene.height >= scroll - 240;
        const retained = activeScenes.has(scene) && scene.top <= scroll + viewport + 360 && scene.top + scene.height >= scroll - 360;
        scene.visible = entering || retained;
        if (scene.visible) activeScenes.add(scene);
        else { activeScenes.delete(scene); scene.actors.forEach(stop); }
      }
    }
    for (const scene of activeScenes) {
      activate(scene, refreshRanges);
      if (timeline) continue;
      const view = clamp((scroll + viewport - scene.top) / (viewport + scene.height));
      for (const actor of scene.actors) {
        const progress = actor.mode === 'hero' ? clamp((scroll - scene.top) / scene.height) : view;
        seek(actor, clamp((progress - actor.start) / (actor.end - actor.start)));
      }
    }
    measureNeeded = false;
    viewportNeeded = false;
  };
  const schedule = () => {
    if (enabled && !frame && !document.hidden && !suspended && !destroyed) frame = requestAnimationFrame(render);
  };
  const measure = () => { measureNeeded = true; schedule(); };
  const resize = () => {
    // Mobile address-bar movement changes the viewport without changing the page layout.
    // Actual element-size changes still invalidate geometry through ResizeObserver.
    viewportNeeded = true;
    if (innerWidth !== layoutWidth || !sizing) measureNeeded = true;
    schedule();
  };
  const mediaLoaded = event => {
    // Still/motion swaps keep the same reserved box. ResizeObserver detects any
    // actual size change; remeasuring every anchor on these loads forces layout.
    if (event.target instanceof HTMLImageElement && event.target.closest('.content-performance,.animation-sprite')) return;
    measure();
  };
  const observer = new IntersectionObserver(entries => {
    for (const entry of entries) {
      const scene = anchors.get(entry.target);
      if (entry.isIntersecting) { scene.visible = true; activeScenes.add(scene); }
    }
    schedule();
  }, {rootMargin: '240px'});
  // A self-animated tile can cross the entry boundary while moving. A wider exit boundary
  // prevents cancel/recreate oscillation without reading layout on every scroll event.
  const exitObserver = new IntersectionObserver(entries => {
    for (const entry of entries) {
      if (entry.isIntersecting) continue;
      const scene = anchors.get(entry.target);
      scene.visible = false; activeScenes.delete(scene); scene.actors.forEach(stop);
    }
  }, {rootMargin: '360px'});
  const sizing = typeof ResizeObserver === 'function' ? new ResizeObserver(measure) : null;
  for (const scene of anchors.values()) { observer.observe(scene.element); exitObserver.observe(scene.element); sizing?.observe(scene.element); }
  const cancel = () => {
    cancelAnimationFrame(frame); frame = 0;
    actors.forEach(stop);
  };
  const sync = () => {
    if (destroyed) return;
    enabled = allowed();
    root.classList.toggle('scroll-motion-enabled', enabled);
    root.classList.toggle('scroll-motion-static', !enabled);
    cancel();
    if (!enabled) return;
    distance = compact.matches ? .45 : 1;
    measureNeeded = true;
    render();
  };
  const focus = () => {
    for (const actor of actors) {
      actor.focused = actor.element.contains(document.activeElement);
      if (actor.focused && !timeline) seek(actor, 1);
    }
    schedule();
  };
  const visibility = () => { if (document.hidden) { cancelAnimationFrame(frame); frame = 0; } else measure(); };
  const hide = event => {
    suspended = true; cancelAnimationFrame(frame); frame = 0;
    if (event.persisted) return;
    destroyed = true; cancel(); observer.disconnect(); exitObserver.disconnect(); sizing?.disconnect();
    removeEventListener('scroll', schedule); removeEventListener('resize', resize);
    removeEventListener('pagehide', hide); removeEventListener('pageshow', show);
    document.removeEventListener('anazori:motion', sync); document.removeEventListener('visibilitychange', visibility);
    document.removeEventListener('focusin', focus); document.removeEventListener('focusout', focus);
    document.removeEventListener('load', mediaLoaded, true);
    document.removeEventListener('anazori:layout', measure);
    reduced.removeEventListener('change', sync); compact.removeEventListener('change', sync);
    printing.removeEventListener('change', sync);
    connection?.removeEventListener?.('change', sync);
  };
  const show = event => { if (event.persisted) { suspended = false; measure(); } };
  if (!timeline) addEventListener('scroll', schedule, {passive: true});
  addEventListener('resize', resize, {passive: true});
  addEventListener('pagehide', hide); addEventListener('pageshow', show);
  document.addEventListener('anazori:motion', sync); document.addEventListener('visibilitychange', visibility);
  document.addEventListener('focusin', focus); document.addEventListener('focusout', focus);
  document.addEventListener('load', mediaLoaded, true);
  document.addEventListener('anazori:layout', measure);
  reduced.addEventListener('change', sync); compact.addEventListener('change', sync);
  printing.addEventListener('change', sync);
  connection?.addEventListener?.('change', sync);
  document.fonts?.ready.then(() => { if (!destroyed) measure(); });
  sync();
}
