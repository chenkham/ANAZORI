import assert from 'node:assert/strict';
import {chromium} from 'playwright';
import {spawn} from 'node:child_process';
import {mkdtemp, mkdir, readdir, unlink, rmdir} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';

const root = resolve('.');
const temp = await mkdtemp(join(tmpdir(), 'anazori-scroll-'));
const base = 'http://127.0.0.1:8109';
const server = spawn('php', ['-S', '127.0.0.1:8109', '-t','src','scripts/router.php'], {cwd: root, env: {...process.env, ANAZORI_DB_PATH: join(temp, 'qa.sqlite')}, windowsHide: true, stdio: 'ignore'});
let browser, passed = 0;
const failures = [], browserErrors = [];
const check = async (label, work) => {
  try { await work(); passed++; console.log('PASS ' + label); }
  catch (error) { failures.push({label, error: error.stack || String(error)}); console.error('FAIL ' + label + '\n' + error.message); }
};
const installPreferences = ({saveData = false, paused = false, nativeUnavailable = false} = {}) => {
  localStorage.setItem('anazori-motion', paused ? 'paused' : 'on');
  localStorage.setItem('anazori-sound', 'off');
  if (nativeUnavailable) Object.defineProperty(window, 'ScrollTimeline', {value: undefined, configurable: true});
  const connection = new EventTarget();
  connection.saveData = saveData;
  connection.effectiveType = '4g';
  Object.defineProperty(navigator, 'connection', {value: connection, configurable: true});
  Object.defineProperty(navigator, 'deviceMemory', {get: () => 8, configurable: true});
  window.__scrollTestConnection = connection;
};
const track = page => page.on('pageerror', error => browserErrors.push(error.message));
const scrollTo = async (page, y) => page.evaluate(async value => {
  window.scrollTo({top: value, behavior: 'instant'});
  for (let i = 0; i < 4; i++) await new Promise(resolve => requestAnimationFrame(resolve));
}, y);
const documentTop = (page, selector) => page.locator(selector).first().evaluate(element => element.getBoundingClientRect().top + scrollY);
const sample = (page, selector) => page.locator(selector).evaluate(element => {
  const style = getComputedStyle(element);
  const matrix = new DOMMatrixReadOnly(style.transform === 'none' ? undefined : style.transform);
  const numbers = value => (value.match(/-?\d+(?:\.\d+)?/g) || []).map(Number);
  const translate = numbers(style.translate); while (translate.length < 3) translate.push(0);
  let scale = numbers(style.scale); if (!scale.length) scale = [1, 1, 1]; else if (scale.length === 1) scale = [scale[0], scale[0], 1]; else if (scale.length === 2) scale.push(1);
  let rotate = numbers(style.rotate); if (!rotate.length) rotate = [0, 0, 1, 0]; else if (rotate.length === 1) rotate = [0, 0, 1, rotate[0]];
  return {transform: style.transform, translate: style.translate, scale: style.scale, rotate: style.rotate, opacity: Number(style.opacity), values: [matrix.m11, matrix.m12, matrix.m13, matrix.m14, matrix.m21, matrix.m22, matrix.m23, matrix.m24, matrix.m31, matrix.m32, matrix.m33, matrix.m34, matrix.m41, matrix.m42, matrix.m43, matrix.m44, ...translate, ...scale, ...rotate]};
});
const matrixDistance = (first, second) => Math.max(...first.values.map((value, index) => Math.abs(value - second.values[index])));
const visibleOpacity = (page, selector) => page.locator(selector).first().evaluate(element => {
  let opacity = 1;
  for (let current = element; current; current = current.parentElement) opacity *= Number(getComputedStyle(current).opacity);
  return opacity;
});
const staticContent = async page => {
  for (const selector of ['#hero-title', '.hero-copy', '.programme-heading h2', '.frequency-record', '.bento-invitation']) {
    assert.equal(await page.locator(selector).isVisible(), true, selector + ' remains visible');
    assert(await visibleOpacity(page, selector) >= .95, selector + ' remains fully readable');
  }
};
const eventCopy = '.programme-link:visible,.programme-mobile-title:visible';
const category = async (page, value) => {
  const slug = {tech:'goc',culture:'prativa',gaming:'joystick',sports:'futsal'}[value];
  const link = page.locator(`[data-programme-select="${slug}"]`);
  if(await link.isVisible()) await link.focus();
  else {
    await page.getByRole('region',{name:'Festival events'}).focus();
    for(let i=0;i<7 && !await page.locator(`[data-programme-pane="${slug}"]`).isVisible();i++) await page.keyboard.press('ArrowRight');
  }
  assert.equal(await page.locator(`[data-programme-pane="${slug}"]`).isVisible(), true);
  assert.equal(await page.locator('.programme-pane:visible').count(), 1);
};

try {
  let ready = false;
  for (let i = 0; i < 60; i++) {
    try { if ((await fetch(base)).ok) { ready = true; break; } } catch {}
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  assert(ready, 'Isolated PHP server did not start on port 8109');
  browser = await chromium.launch();
  await mkdir('.local/scroll', {recursive: true});
  const context = await browser.newContext({viewport: {width: 1440, height: 960}});
  await context.addInitScript(installPreferences);
  const page = await context.newPage(); track(page);
  const load = async () => {
    await page.goto(base, {waitUntil: 'networkidle'});
    await page.locator('.programme-section').waitFor();
    // Let introductory entrance motion finish before measuring scroll-only changes.
    await page.waitForTimeout(1100);
  };
  await load();
  assert.equal(await page.locator('html').evaluate(html => html.classList.contains('scroll-motion-enabled')), true);

  await check('Supported browsers use the native scroll timeline.', async () => {
    const engine = await page.evaluate(() => ({supported: typeof ScrollTimeline === 'function', selected: document.documentElement.dataset.scrollEngine}));
    if (engine.supported) assert.equal(engine.selected, 'native', 'Native timelines keep animation progress out of the scroll handler');
    else assert.notEqual(engine.selected, 'native');
  });

  await check('Hero video moves with scroll progress and returns to its original pose.', async () => {
    await scrollTo(page, 0);
    const start = await sample(page, '[data-scroll-motion="hero-film"]');
    const height = await page.locator('.hero').evaluate(hero => hero.offsetHeight);
    const distance = Math.min(360, Math.round(height * .4));
    await scrollTo(page, distance);
    const moved = await sample(page, '[data-scroll-motion="hero-film"]');
    assert(matrixDistance(start, moved) > 1, 'Hero media must visibly scrub with document scrolling');
    assert.equal(Math.round(await page.evaluate(() => scrollY)), distance, 'Native scroll position is preserved');
    await page.screenshot({path: '.local/scroll/hero-desktop.png'});
    await scrollTo(page, 0);
    const returned = await sample(page, '[data-scroll-motion="hero-film"]');
    assert(matrixDistance(start, returned) < .05, 'Reverse scrolling restores the hero pose');
    await page.mouse.wheel(0, 180);
    await page.waitForFunction(() => scrollY > 120);
    assert((await page.evaluate(() => scrollY)) < 250, 'Wheel scrolling stays native instead of jumping to a pinned scene');
    await scrollTo(page, 0);
  });

  await check('Programme heading motion follows scroll progress and reverses cleanly.', async () => {
    const top = await documentTop(page, '.programme-heading h2');
    const height = await page.evaluate(() => innerHeight);
    const firstY = Math.max(0, Math.round(top - height * .78));
    const secondY = Math.max(0, Math.round(top - height * .22));
    await scrollTo(page, firstY);
    const entering = await sample(page, '.programme-heading h2');
    await scrollTo(page, secondY);
    const advanced = await sample(page, '.programme-heading h2');
    assert(matrixDistance(entering, advanced) > .3 || Math.abs(entering.opacity - advanced.opacity) > .1, 'Programme heading must respond visibly to scroll progress');
    await page.screenshot({path: '.local/scroll/atlas-desktop.png'});
    await scrollTo(page, firstY);
    const reversed = await sample(page, '.programme-heading h2');
    assert(matrixDistance(entering, reversed) < .05 && Math.abs(entering.opacity - reversed.opacity) < .02, 'Programme heading returns to the same earlier scroll state');
  });

  await check('Keyboard focus reveals event links immediately and event previews stay usable.', async () => {
    await scrollTo(page, 0);
    const first = page.locator('.programme-link:visible').first();
    await first.focus();
    for (let i = 0; i < 4; i++) await page.evaluate(() => new Promise(resolve => requestAnimationFrame(resolve)));
    assert.equal(await first.evaluate(element => element === document.activeElement), true);
    assert(await visibleOpacity(page, '.programme-link:visible') >= .95, 'Focused event is fully readable');
    for (const value of ['culture', 'gaming', 'sports', 'tech']) {
      await category(page, value);
      const link = page.locator('.programme-link:visible').first();
      await link.focus();
      assert.equal(await link.evaluate(element => element === document.activeElement), true);
      assert(await visibleOpacity(page, '.programme-link:visible') >= .95, value + ' focused event stays readable');
      assert.match(await link.getAttribute('href'), /^\/event\.php\?name=/);
    }
  });

  await check('Scroll effects preserve five responsive widths and restored design choices.', async () => {
    for (const width of [360, 390, 768, 1024, 1440]) {
      await page.setViewportSize({width, height: width < 600 ? 844 : 960});
      await load();
      for (const selector of ['.hero', '.programme-section', '.culture-tech', '.sponsor-bento', '.site-footer']) {
        await page.locator(selector).scrollIntoViewIfNeeded();
        await page.evaluate(() => new Promise(resolve => requestAnimationFrame(resolve)));
        const overflow = await page.evaluate(() => document.documentElement.scrollWidth > innerWidth);
        if (overflow) {
          const details = await page.evaluate(() => ({viewport: innerWidth, document: document.documentElement.scrollWidth, elements: [...document.querySelectorAll('main > section,[data-scroll-motion],.site-header')].map(element => { const box = element.getBoundingClientRect(); const style = getComputedStyle(element); return {element: element.dataset.scrollMotion || element.className, left: Math.round(box.left), right: Math.round(box.right), translate: style.translate, overflow: style.overflowX}; }).filter(element => element.left < -1 || element.right > innerWidth + 1).slice(0, 20)}));
          await page.screenshot({path: `.local/scroll/overflow-${width}.png`});
          assert.fail(`${width}px overflow at ${selector}: ${JSON.stringify(details)}`);
        }
      }
      assert.equal(await page.locator('.frequency-record').isVisible(), true);
      assert.equal(await page.locator('.desktop-nav svg, .mobile-nav svg, .atlas-node svg, .programme-link svg').count(), 0);
      assert.equal(await page.locator('.atlas-controls, .atlas-choice').count(), 0, 'The retired category interface is absent');
      assert(!['fixed', 'sticky'].includes(await page.locator('.site-header').evaluate(header => getComputedStyle(header).position)), 'Stationary header is preserved');
      if (width === 390) {
        const top = await documentTop(page, '.programme-section');
        await scrollTo(page, top);
        await page.screenshot({path: '.local/scroll/atlas-mobile.png'});
      }
    }
  });

  await check('Mobile headings and event copy remain fully readable as they enter the screen.', async () => {
    const mobileContext = await browser.newContext({viewport: {width: 390, height: 844}});
    try {
      await mobileContext.addInitScript(installPreferences);
      const mobile = await mobileContext.newPage(); track(mobile);
      await mobile.goto(base, {waitUntil: 'domcontentloaded'});
      assert(await visibleOpacity(mobile, '#hero-title') >= .99, 'Brand name appears immediately');
      assert(await visibleOpacity(mobile, '.hero-copy') >= .99, 'Hero copy appears immediately');
      await mobile.locator('.programme-section').waitFor();
      for (const selector of ['.intro h2', '.programme-heading h2', eventCopy, '.culture-half h2', '.bento-invitation h3', '.visit h2']) {
        const top = await documentTop(mobile, selector);
        for (const position of [.82, .62, .4]) {
          await scrollTo(mobile, Math.max(0, Math.round(top - 844 * position)));
          const box = await mobile.locator(selector).first().boundingBox();
          assert(box && box.y < 844 && box.y + box.height > 0, selector + ' reaches the visible screen');
          assert(await visibleOpacity(mobile, selector) >= .99, selector + ' does not fade or delay readable content');
        }
      }
    } finally { await mobileContext.close(); }
  });

  await check('Browsers without native scroll timelines retain reverse motion and keyboard event previews.', async () => {
    const fallbackContext = await browser.newContext({viewport: {width: 390, height: 844}});
    try {
      await fallbackContext.addInitScript(installPreferences, {nativeUnavailable: true});
      const fallback = await fallbackContext.newPage(); track(fallback);
      await fallback.goto(base, {waitUntil: 'networkidle'});
      await fallback.locator('.programme-section').waitFor();
      assert.equal(await fallback.evaluate(() => typeof ScrollTimeline), 'undefined');
      assert.notEqual(await fallback.locator('html').getAttribute('data-scroll-engine'), 'native');
      await scrollTo(fallback, 0);
      const heroStart = await sample(fallback, '[data-scroll-motion="hero-film"]');
      await scrollTo(fallback, 250);
      assert(matrixDistance(heroStart, await sample(fallback, '[data-scroll-motion="hero-film"]')) > 1, 'Fallback hero follows scrolling');
      await scrollTo(fallback, 0);
      assert(matrixDistance(heroStart, await sample(fallback, '[data-scroll-motion="hero-film"]')) < .05, 'Fallback hero restores its original pose');
      const top = await documentTop(fallback, '.programme-heading h2');
      const entry = Math.max(0, Math.round(top - 844 * .78));
      const advance = Math.max(0, Math.round(top - 844 * .22));
      await scrollTo(fallback, entry);
      const atlasStart = await sample(fallback, '.programme-heading h2');
      assert(await visibleOpacity(fallback, '.programme-heading h2') >= .99, 'Fallback heading stays readable during entry');
      await scrollTo(fallback, advance);
      assert(matrixDistance(atlasStart, await sample(fallback, '.programme-heading h2')) > .3, 'Fallback atlas moves through its entry');
      await scrollTo(fallback, entry);
      assert(matrixDistance(atlasStart, await sample(fallback, '.programme-heading h2')) < .05, 'Fallback atlas reverses to the earlier pose');
      for (const value of ['culture', 'gaming', 'sports', 'tech']) {
        await category(fallback, value);
        assert(await visibleOpacity(fallback, eventCopy) >= .99, value + ' event copy stays readable');
      }
      await category(fallback, 'culture');
      assert.equal(await fallback.locator('[data-programme-pane="prativa"]').isVisible(), true);
    } finally { await fallbackContext.close(); }
  });

  await check('Print preview clears scroll transforms and returning to the screen resumes motion.', async () => {
    await page.setViewportSize({width: 1440, height: 960}); await load();
    await scrollTo(page, 260);
    const animated = await sample(page, '[data-scroll-motion="hero-film"]');
    try {
      await page.emulateMedia({media: 'print'});
      await page.waitForFunction(() => document.documentElement.classList.contains('scroll-motion-static'));
      assert.equal(await page.locator('html').evaluate(html => html.classList.contains('scroll-motion-enabled')), false);
      const printed = await sample(page, '[data-scroll-motion="hero-film"]');
      assert.equal(printed.transform, 'none', 'Print preview removes native additive transforms');
      assert(matrixDistance(animated, printed) > 1, 'Print preview clears the active scroll pose');
      assert.equal(await page.locator('[data-scroll-motion="hero-film"]').evaluate(element => element.getAnimations().length), 0, 'Print preview leaves no active hero scroll animation');
      await staticContent(page);
    } finally {
      await page.emulateMedia({media: 'screen'});
    }
    await page.waitForFunction(() => document.documentElement.classList.contains('scroll-motion-enabled'));
    await scrollTo(page, 0);
    const restored = await sample(page, '[data-scroll-motion="hero-film"]');
    await scrollTo(page, 260);
    assert(matrixDistance(restored, await sample(page, '[data-scroll-motion="hero-film"]')) > 1, 'Screen mode resumes scroll-driven motion');
  });

  await check('An idle heading near the prewarm boundary keeps a stable animation and pose.', async () => {
    await load();
    const boundary = await page.locator('.intro h2').evaluate(element => {
      let top = 0;
      for (let node = element; node; node = node.offsetParent) top += node.offsetTop;
      return Math.max(0, Math.round(top - innerHeight - 235));
    });
    await scrollTo(page, boundary);
    await page.waitForTimeout(300);
    assert.equal(await page.locator('.intro h2').evaluate(element => {
      window.__boundaryAnimation = element.getAnimations()[0];
      return Boolean(window.__boundaryAnimation);
    }), true, 'The heading is prepared before entering the viewport');
    const initial = await sample(page, '.intro h2');
    await page.waitForTimeout(400);
    assert.equal(await page.locator('.intro h2').evaluate(element => element.getAnimations()[0] === window.__boundaryAnimation), true, 'A stationary heading does not repeatedly cancel and recreate its animation');
    assert(matrixDistance(initial, await sample(page, '.intro h2')) < .01, 'A stationary heading does not flicker between poses');
    assert.equal(Math.round(await page.evaluate(() => scrollY)), boundary, 'The idle scroll position stays unchanged');
    assert(await visibleOpacity(page, '.intro h2') >= .99, 'Prepared heading text stays readable');
  });

  await check('Pause motion clears scroll transforms and resume restores scrubbing.', async () => {
    await page.setViewportSize({width: 1440, height: 960}); await load();
    await scrollTo(page, 260);
    await page.locator('.motion-toggle').evaluate(button => button.click());
    assert.equal(await page.locator('html').evaluate(html => html.classList.contains('motion-paused')), true);
    assert.equal(await page.locator('html').evaluate(html => html.classList.contains('scroll-motion-static')), true);
    const first = await sample(page, '[data-scroll-motion="hero-film"]');
    await scrollTo(page, 80);
    const second = await sample(page, '[data-scroll-motion="hero-film"]');
    assert(matrixDistance(first, second) < .01, 'Paused hero stays in its static pose');
    await staticContent(page);
    await page.locator('.motion-toggle').evaluate(button => button.click());
    assert.equal(await page.locator('html').evaluate(html => html.classList.contains('motion-paused')), false);
    await scrollTo(page, 100);
    const resumed = await sample(page, '[data-scroll-motion="hero-film"]');
    await scrollTo(page, 280);
    assert(matrixDistance(resumed, await sample(page, '[data-scroll-motion="hero-film"]')) > 1, 'Motion resumes after explicit user choice');
  });

  await check('Reduced-motion preference keeps every section static and controls functional.', async () => {
    const reducedContext = await browser.newContext({viewport: {width: 390, height: 844}, reducedMotion: 'reduce'});
    try {
      await reducedContext.addInitScript(installPreferences);
      const reduced = await reducedContext.newPage(); track(reduced);
      await reduced.goto(base, {waitUntil: 'networkidle'});
      assert.equal(await reduced.locator('html').evaluate(html => html.classList.contains('scroll-motion-static')), true);
      await staticContent(reduced);
      await scrollTo(reduced, 0); const start = await sample(reduced, '[data-scroll-motion="hero-film"]');
      await scrollTo(reduced, 240); assert(matrixDistance(start, await sample(reduced, '[data-scroll-motion="hero-film"]')) < .01);
      await category(reduced, 'gaming');
      assert(await visibleOpacity(reduced, eventCopy) >= .95);
      assert.equal(await reduced.locator('.frequency-record').evaluate(element => { const style = getComputedStyle(element); return style.animationName === 'none' || style.animationPlayState === 'paused'; }), true);
    } finally { await reducedContext.close(); }
  });

  await check('Save-Data produces visible static content and disables scroll scrubbing.', async () => {
    const saverContext = await browser.newContext({viewport: {width: 390, height: 844}});
    try {
      await saverContext.addInitScript(installPreferences, {saveData: true});
      const saver = await saverContext.newPage(); track(saver);
      await saver.goto(base, {waitUntil: 'networkidle'});
      assert.equal(await saver.locator('html').evaluate(html => html.classList.contains('scroll-motion-static')), true);
      await staticContent(saver);
      await scrollTo(saver, 0); const start = await sample(saver, '[data-scroll-motion="hero-film"]');
      await scrollTo(saver, 220); assert(matrixDistance(start, await sample(saver, '[data-scroll-motion="hero-film"]')) < .01);
      await category(saver, 'culture');
      assert(await visibleOpacity(saver, eventCopy) >= .95);
    } finally { await saverContext.close(); }
  });

  await check('Changing Save-Data while open clears motion and restores it when disabled.', async () => {
    await load(); await scrollTo(page, 250);
    await page.evaluate(() => { window.__scrollTestConnection.saveData = true; window.__scrollTestConnection.dispatchEvent(new Event('change')); });
    assert.equal(await page.locator('html').evaluate(html => html.classList.contains('scroll-motion-static')), true);
    const stopped = await sample(page, '[data-scroll-motion="hero-film"]');
    await scrollTo(page, 80);
    assert(matrixDistance(stopped, await sample(page, '[data-scroll-motion="hero-film"]')) < .01);
    await staticContent(page);
    await page.evaluate(() => { window.__scrollTestConnection.saveData = false; window.__scrollTestConnection.dispatchEvent(new Event('change')); });
    await scrollTo(page, 100); const resumed = await sample(page, '[data-scroll-motion="hero-film"]');
    await scrollTo(page, 280);
    assert(matrixDistance(resumed, await sample(page, '[data-scroll-motion="hero-film"]')) > 1);
  });

  await check('Without JavaScript headings, vinyl, sponsor content and every event stay visible.', async () => {
    const staticContext = await browser.newContext({viewport: {width: 390, height: 844}, javaScriptEnabled: false});
    try {
      const staticPage = await staticContext.newPage();
      await staticPage.goto(base, {waitUntil: 'networkidle'});
      await staticContent(staticPage);
      assert.equal(await staticPage.locator('.programme-link:visible').count(), 7);
      await staticPage.locator('.programme-link').first().click();
      await staticPage.waitForURL('**/event.php?name=*');
      assert.equal(await staticPage.locator('h1').isVisible(), true);
    } finally { await staticContext.close(); }
  });

  await check('Persisted pagehide/pageshow lifecycle resumes scroll effects without duplicate state.', async () => {
    await load(); await scrollTo(page, 120);
    await page.evaluate(() => { dispatchEvent(new PageTransitionEvent('pagehide', {persisted: true})); dispatchEvent(new PageTransitionEvent('pageshow', {persisted: true})); });
    await scrollTo(page, 0); const before = await sample(page, '[data-scroll-motion="hero-film"]');
    await scrollTo(page, 280); const after = await sample(page, '[data-scroll-motion="hero-film"]');
    assert(matrixDistance(before, after) > 1);
    await category(page, 'sports');
    assert.equal(await page.locator('.programme-link.is-selected').count(), 1);
  });

  await check('Scroll interactions produce no uncaught browser errors.', async () => assert.deepEqual(browserErrors, []));
  console.log(`${passed} scroll check groups passed. Persisted lifecycle is simulated because Playwright Chromium disables real bfcache. Screenshots saved in .local/scroll.`);
  assert.deepEqual(failures, [], 'Scroll-motion verification failures');
} finally {
  await browser?.close();
  if (server.exitCode === null) { const ended = new Promise(resolve => server.once('exit', resolve)); server.kill(); await ended; }
  for (const filename of await readdir(temp)) await unlink(join(temp, filename));
  await rmdir(temp);
}
