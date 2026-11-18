import assert from 'node:assert/strict';
import {initAmbientMotion} from '../frontend/ambient-motion.js';
import {initFestivalScenes} from '../frontend/festival-scenes.js';

// Exercise the real scene lifecycle without starting a browser or changing CMS data.
const classes = () => {
  const values = new Set();
  return {
    add: (...names) => names.forEach(name => values.add(name)),
    remove: (...names) => names.forEach(name => values.delete(name)),
    contains: name => values.has(name),
    toggle(name, force) {
      const on = force ?? !values.has(name);
      on ? values.add(name) : values.delete(name);
      return on;
    },
  };
};
const element = () => ({
  classList: classes(), dataset: {},
  querySelectorAll: () => [], querySelector: () => null,
  setAttribute() {}, remove() {}, append() {},
});
const scene = element(), ambient = element(), root = element();
const doc = new EventTarget(), win = new EventTarget();
Object.assign(doc, {
  documentElement: root, hidden: false,
  body: {...element(), dataset: {sceneMotion: 'on'}},
  querySelector: () => null,
  querySelectorAll: selector => selector === '[data-festival-scene]' ? [scene]
    : selector.startsWith('.festival-glass-background,') ? [ambient] : [],
  createElement: element,
});
const observers = [];
class VisibilityObserver {
  constructor(callback) {this.callback = callback; this.targets = new Set(); observers.push(this);}
  observe(target) {this.targets.add(target);}
  disconnect() {this.targets.clear();}
  show(target, isIntersecting) {this.callback([{target, isIntersecting}]);}
}
const media = new Map();
const globals = {
  document: doc,
  navigator: {connection: new EventTarget()},
  location: {pathname: '/'},
  IntersectionObserver: VisibilityObserver,
  MutationObserver: class {observe() {} disconnect() {}},
  matchMedia(query) {
    if (!media.has(query)) {
      const result = new EventTarget();
      result.matches = query.includes('max-width');
      media.set(query, result);
    }
    return media.get(query);
  },
  addEventListener: win.addEventListener.bind(win),
  removeEventListener: win.removeEventListener.bind(win),
};
const original = new Map(Object.keys(globals).map(key => [key, Object.getOwnPropertyDescriptor(globalThis, key)]));
const lifecycle = (type, persisted = false) => {
  const event = new Event(type);
  Object.defineProperty(event, 'persisted', {value: persisted});
  win.dispatchEvent(event);
};
const running = () => {
  assert(scene.classList.contains('scene-running'), 'A visible scene must animate.');
  assert(!scene.classList.contains('scene-dormant'), 'A visible scene must not stay dormant.');
  assert(!ambient.classList.contains('motion-outside'), 'The visible background must animate.');
};
try {
  for (const [key, value] of Object.entries(globals)) Object.defineProperty(globalThis, key, {value, configurable: true});
  initAmbientMotion();
  initFestivalScenes();
  const sceneObserver = observers.find(observer => observer.targets.has(scene));
  const ambientObserver = observers.find(observer => observer.targets.has(ambient));
  sceneObserver.show(scene, true);
  ambientObserver.show(ambient, true);
  running();

  // A scene entering the viewport during touch scrolling used to remain dormant.
  root.classList.add('is-scrolling81');
  win.dispatchEvent(new Event('scroll'));
  sceneObserver.show(scene, true);
  ambientObserver.show(ambient, true);
  running();
  root.classList.remove('is-scrolling81');
  doc.dispatchEvent(new Event('anazori:scroll-activity'));
  running();
  console.log('PASS Visible scenes and backgrounds keep playing throughout scrolling.');

  sceneObserver.show(scene, false);
  ambientObserver.show(ambient, false);
  assert(scene.classList.contains('scene-dormant'));
  assert(ambient.classList.contains('motion-outside'));
  sceneObserver.show(scene, true);
  ambientObserver.show(ambient, true);
  running();
  doc.hidden = true;
  doc.dispatchEvent(new Event('visibilitychange'));
  assert(scene.classList.contains('scene-dormant'));
  doc.hidden = false;
  doc.dispatchEvent(new Event('visibilitychange'));
  running();
  lifecycle('pagehide', true);
  assert(scene.classList.contains('scene-dormant'));
  assert(ambient.classList.contains('motion-outside'));
  lifecycle('pageshow', true);
  running();
  console.log('PASS Offscreen, hidden-tab and browser-back lifecycle resumes correctly.');

  root.classList.add('motion-paused');
  doc.dispatchEvent(new Event('anazori:motion'));
  assert(scene.classList.contains('scene-dormant'));
  root.classList.remove('motion-paused');
  doc.dispatchEvent(new Event('anazori:motion'));
  running();
  const reduced = media.get('(prefers-reduced-motion: reduce)');
  reduced.matches = true;
  reduced.dispatchEvent(new Event('change'));
  assert(scene.classList.contains('scene-dormant'));
  reduced.matches = false;
  reduced.dispatchEvent(new Event('change'));
  running();
  console.log('PASS Explicit pause and accessibility preferences remain effective.');
} finally {
  lifecycle('pagehide');
  for (const [key, descriptor] of original) {
    if (descriptor) Object.defineProperty(globalThis, key, descriptor);
    else delete globalThis[key];
  }
}
