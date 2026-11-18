import {createTaskQueue} from './task-scheduler83.js';

// Flat artwork and short 2D performances. No rendering engine, scroll loop or physics.
export function initFestivalScenes() {
  const root = document.documentElement;
  const reduced = matchMedia('(prefers-reduced-motion: reduce)');
  const fine = matchMedia('(hover: hover) and (pointer: fine)');
  const compact = matchMedia('(max-width: 700px)');
  const connection = navigator.connection;
  const scenes = [...document.querySelectorAll('[data-festival-scene]')];
  const visible = new Set(), animations = new Set(), timers = new Set();
  const spriteLoads = new WeakMap();
  const performanceLoads = new WeakMap(), performanceTimers = new WeakMap(), entered = new WeakSet();
  const performances = [...document.querySelectorAll('[data-performance]')];
  const performanceInfo = new Map(performances.map(node => [node, {
    img: node.querySelector('img'), owner: node.closest('[data-festival-scene]'), dialog: node.closest('dialog')
  }]));
  const performanceStarts = new WeakSet();
  let suspended = false, destroyed = false;
  const decodeInTurn=createTaskQueue();
  const motionContext = () => ({
    enabled: !destroyed && !suspended && !document.hidden && !reduced.matches && !root.classList.contains('motion-paused') && !connection?.saveData && document.body.dataset.sceneMotion !== 'off',
    dialog: document.querySelector('dialog[open]')
  });
  const allowed = () => { const context=motionContext();return context.enabled&&!context.dialog; };
  const later = (callback, delay) => { const timer = setTimeout(() => { timers.delete(timer); if (!destroyed) callback(); }, delay); timers.add(timer); return timer; };
  const animate = (node, keys, options) => {
    if (!node || !allowed() || typeof node.animate !== 'function') return;
    const animation = node.animate(keys, options);
    animations.add(animation);
    const done = () => { animations.delete(animation); animation.cancel(); };
    animation.onfinish = done; animation.oncancel = () => animations.delete(animation);
  };
  const performanceAllowed = (node, context) => {
    const dialog=performanceInfo.get(node)?.dialog;
    const quality=root.dataset.motionQuality;
    if(node.dataset.performancePlay==='loop'&&(quality==='low'||(quality==='medium'&&['festival-snow','stitch-light'].includes(node.dataset.performance))))return false;
    return context.enabled&&!node.closest('[hidden]')&&(!dialog||dialog.open)&&(!context.dialog||context.dialog.contains(node));
  };
  const performanceVisible = (node, context=motionContext()) => visible.has(performanceInfo.get(node)?.owner) && performanceAllowed(node,context);
  const performancePlaying = node => performanceVisible(node) && (node.dataset.performancePlay === 'loop' || node.classList.contains('is-playing'));
  const stopPerformance = node => {
    const img=performanceInfo.get(node)?.img;if(!img)return;
    if(img.dataset.stillSrc && img.getAttribute('src')!==img.dataset.stillSrc) img.src=img.dataset.stillSrc;
    node.classList.remove('is-animated');
  };
  const preparePerformance = node => {
    if (!performanceLoads.has(node)) performanceLoads.set(node, decodeInTurn(async () => {
      const context = motionContext();
      if (!performanceAllowed(node, context)) return null;
      try {
        const preview = new Image();
        preview.decoding = 'async'; preview.src = performanceInfo.get(node).img.dataset.performanceSrc;
        await preview.decode(); return true;
      } catch { return false; }
    }));
    return performanceLoads.get(node);
  };
  const startPerformance = node => {
    // Repeated visibility notifications share one pending start and one decode.
    if(performanceStarts.has(node)||node.classList.contains('is-animated'))return;
    const img=performanceInfo.get(node)?.img;if(!img)return;
    img.dataset.stillSrc ||= img.getAttribute('src');
    performanceStarts.add(node);
    preparePerformance(node).then(ready=>{
      performanceStarts.delete(node);
      if(ready===null){performanceLoads.delete(node);if(!destroyed&&performancePlaying(node))startPerformance(node);return;}if(!ready)return;if(destroyed || !performancePlaying(node))return;
      if(!node.classList.contains('is-animated')) {img.loading='eager';img.src=img.dataset.performanceSrc;node.classList.add('is-animated');}
      if(node.dataset.performancePlay!=='loop' && !performanceTimers.has(node)) {
        const timer=later(()=>{performanceTimers.delete(node);node.classList.remove('is-playing');stopPerformance(node);},Math.max(800,Number(node.dataset.performanceDuration)*1000));
        performanceTimers.set(node,timer);
      }
    });
  };
  const playPerformance = node => {
    if(!node || !performanceVisible(node)) return;
    node.classList.add('is-playing');startPerformance(node);
  };
  const syncPerformances = () => {
    const context=motionContext();
    for(const node of performances) {
      const isVisible=performanceVisible(node,context);
      if(node.dataset.performancePlay==='enter' && isVisible && !entered.has(node)) {entered.add(node);node.classList.add('is-playing');}
      if(isVisible&&(node.dataset.performancePlay==='loop'||node.classList.contains('is-playing'))) startPerformance(node);else {
        stopPerformance(node);
        if(!isVisible) {node.classList.remove('is-playing');const timer=performanceTimers.get(node);if(timer){clearTimeout(timer);timers.delete(timer);performanceTimers.delete(node);}}
      }
    }
  };
  const hydrateSprites = scene => {
    if(scene.dataset.spritesLoading)return;
    const sprites=[...scene.querySelectorAll('[data-sprite-src]')];
    if(!sprites.length) return;
    scene.dataset.spritesLoading='true';
    Promise.all(sprites.map(img=>{
      if(spriteLoads.has(img)) return spriteLoads.get(img);
      const load=decodeInTurn(async()=>{
        try{
          const atlas=new Image();atlas.src=img.dataset.spriteSrc;await atlas.decode();
          if(destroyed) return false;
          img.loading='eager';img.src=atlas.src;await img.decode();
          if(destroyed) return false;
          img.closest('.animation-sprite').classList.add('sprite-ready');
          return true;
        }catch{return false;} // Preserve the supplied poster if an atlas cannot be decoded.
      });spriteLoads.set(img,load);return load;
    })).then(results=>{if(!destroyed && results.every(Boolean))scene.classList.add('sprites-ready');});
  };
  const sync = () => {
    const enabled = allowed();
    for (const scene of scenes) {
      const active = enabled && visible.has(scene);
      scene.classList.toggle('scene-running', active);
      scene.classList.toggle('scene-dormant', !active);
      scene.classList.toggle('scene-still', !enabled);
      if(active) hydrateSprites(scene);
      if (!active) scene.classList.remove('scene-reacting');
    }
    for (const animation of [...animations]) {
      const owner = animation.effect?.target?.closest('[data-festival-scene]');
      if (!enabled || (owner && !visible.has(owner))) animation.cancel();
    }
    syncPerformances();
  };
  const sceneObserver = typeof IntersectionObserver === 'function' ? new IntersectionObserver(entries => {
    for (const entry of entries) {
      if (entry.isIntersecting) visible.add(entry.target); else {
        visible.delete(entry.target);
        entry.target.querySelectorAll('[data-performance-play="enter"]').forEach(node => entered.delete(node));
      }
    }
    sync();
  }, {threshold: .03}) : null;
  for (const scene of scenes) { scene.classList.add('scene-dormant'); if (sceneObserver) sceneObserver.observe(scene); else visible.add(scene); }
  // Decode the authored artwork shortly before entry, rather than parsing a
  // complex SVG in the first frame of a fast fling. Playback still starts only
  // when its own scene is visible; hidden panes and interaction-only artwork
  // remain deferred until the user requests them.
  const warmObserver = typeof IntersectionObserver === 'function' ? new IntersectionObserver(entries => {
    for (const entry of entries) {
      if (!entry.isIntersecting) continue;
      for (const node of performances) {
        if (!['loop', 'enter'].includes(node.dataset.performancePlay)) continue;
        if (performanceInfo.get(node)?.owner !== entry.target || performanceLoads.has(node)) continue;
        preparePerformance(node).then(ready => { if (ready === null) performanceLoads.delete(node); });
      }
    }
  }, {rootMargin: '320px'}) : null;
  for (const scene of scenes) warmObserver?.observe(scene);
  const dialogs = new MutationObserver(sync);
  document.querySelectorAll('dialog').forEach(dialog => dialogs.observe(dialog, {attributes: true, attributeFilter: ['open']}));

  const programme = document.querySelector('[data-programme]');
  const theatre = programme?.querySelector('.programme-theatre');
  const links = [...(programme?.querySelectorAll('[data-programme-select]') || [])];
  const panes = [...(programme?.querySelectorAll('[data-programme-pane]') || [])];
  const swipeControls = programme?.querySelector('.programme-swipe-controls');
  const scrubber = swipeControls?.querySelector('[data-programme-scrub]');
  let selected = panes[0]?.dataset.programmePane;
  let gesture = null, suppressClickUntil = 0;
  const renderSelection = () => {
    const index = panes.findIndex(pane => pane.dataset.programmePane === selected);
    if (index < 0 || !swipeControls) return;
    swipeControls.querySelector('[data-programme-count]').textContent = `${String(index + 1).padStart(2,'0')} / ${String(panes.length).padStart(2,'0')}`;
    const name = links[index]?.querySelector('h3')?.textContent || '';
    swipeControls.querySelector('[data-programme-name]').textContent = name;
    swipeControls.style.setProperty('--programme-progress', `${panes.length>1?index/(panes.length-1)*100:0}%`);
    if(scrubber) {
      scrubber.value = String(index+1);
      scrubber.setAttribute('aria-valuetext',`${index+1} of ${panes.length}: ${name}`);
    }
  };
  const hydrate = pane => {pane?.querySelectorAll('[data-character-src]').forEach(img => {img.src=img.dataset.characterSrc;img.removeAttribute('data-character-src');});pane?.querySelectorAll('[data-character-href]').forEach(img=>{img.setAttribute('href',img.dataset.characterHref);img.removeAttribute('data-character-href');});};
  const select = slug => {
    const pane = panes.find(item => item.dataset.programmePane === slug);
    if (!pane) return;
    hydrate(pane);
    theatre.dataset.category = pane.dataset.category;
    if (selected === slug) return;
    selected = slug;
    panes.forEach(item => item.hidden = item !== pane);
    links.forEach(link => link.classList.toggle('is-selected', link.dataset.programmeSelect === slug));
    renderSelection();
    syncPerformances();
    // Replace any unfinished preview transition instead of accumulating animations.
    for (const animation of [...animations]) if (animation.effect?.target?.closest('.programme-pane')) animation.cancel();
    animate(pane.querySelector('.theatre-character'), [{transform:'translateY(12px) rotate(-3deg)',opacity:.6},{transform:'translateY(0) rotate(0)',opacity:1}], {duration:320,easing:'cubic-bezier(.2,.7,.2,1)'});
  };
  if(panes[0]){theatre.dataset.category=panes[0].dataset.category;const artObserver=new IntersectionObserver(entries=>{if(entries.some(entry=>entry.isIntersecting)){hydrate(panes.find(pane=>!pane.hidden));artObserver.disconnect();}},{rootMargin:'200px'});artObserver.observe(theatre);}
  const step = direction => {
    if (panes.length < 2) return;
    const index = panes.findIndex(pane => pane.dataset.programmePane === selected);
    select(panes[(index + direction + panes.length) % panes.length].dataset.programmePane);
  };
  const carouselMode = () => {
    gesture = null;
    if (!theatre || !swipeControls) return;
    swipeControls.hidden = !compact.matches || panes.length < 2;
    if (compact.matches) {
      theatre.setAttribute('role','region'); theatre.setAttribute('aria-roledescription','carousel'); theatre.setAttribute('aria-label','Festival events'); theatre.tabIndex=0;
    } else {
      theatre.removeAttribute('role'); theatre.removeAttribute('aria-roledescription'); theatre.setAttribute('aria-label','Event artwork'); theatre.removeAttribute('tabindex');
    }
    renderSelection();
  };
  const swipeStart = event => {
    if (!compact.matches || event.pointerType === 'mouse' || event.isPrimary === false || event.target.closest('button,input')) return;
    gesture = {id:event.pointerId,x:event.clientX,y:event.clientY};
  };
  const swipeEnd = event => {
    const start = gesture; gesture=null;
    if (!compact.matches || !start || start.id!==event.pointerId) return;
    const dx=event.clientX-start.x, dy=event.clientY-start.y;
    if (Math.abs(dx)<45 || Math.abs(dx)<Math.abs(dy)*1.3) return;
    suppressClickUntil=performance.now()+300; step(dx<0?1:-1);
  };
  const cancelSwipe = () => { gesture=null; };
  const carouselClick = event => {
    if (performance.now()<suppressClickUntil) {event.preventDefault();event.stopPropagation();return;}
    const button=event.target.closest('[data-programme-step]');
    if (button) step(Number(button.dataset.programmeStep));
  };
  const scrub = () => {
    const pane = panes[Number(scrubber.value)-1];
    if(pane) select(pane.dataset.programmePane);
  };
  const carouselKey = event => {
    if (!compact.matches || event.target.closest('a,button,input') || !['ArrowLeft','ArrowRight','Home','End'].includes(event.key)) return;
    event.preventDefault();
    if(event.key==='Home'||event.key==='End') select(panes[event.key==='Home'?0:panes.length-1].dataset.programmePane);
    else step(event.key==='ArrowRight'?1:-1);
  };
  scrubber?.addEventListener('input',scrub);
  theatre?.addEventListener('pointerdown',swipeStart,{passive:true});
  theatre?.addEventListener('pointerup',swipeEnd,{passive:true});
  theatre?.addEventListener('pointercancel',cancelSwipe,{passive:true});
  theatre?.addEventListener('click',carouselClick,true);
  theatre?.addEventListener('keydown',carouselKey);
  compact.addEventListener('change',carouselMode);carouselMode();
  const preview = event => {
    if (event.type === 'pointerover' && !fine.matches) return;
    const link = event.target.closest('[data-programme-select]');
    if (link && programme?.contains(link)) select(link.dataset.programmeSelect);
  };
  programme?.addEventListener('pointerover', preview, {passive:true});
  programme?.addEventListener('focusin', preview);
  const imageError = event => {
    if (event.target.matches?.('.festival-character,.gaming-character,.theatre-photo')) event.target.hidden = true;
  };
  document.addEventListener('error', imageError, true);

  const passport = document.querySelector('#festival-passport');
  let eventList = [], goals = {}, state = {enabled:false,events:[],actions:[]}, storageWorks = true;
  const discoveries = ['cable','door','guardian','leaf'];
  try { eventList = JSON.parse(passport?.dataset.passportEvents || '[]'); goals = JSON.parse(passport?.dataset.passportGoals || '{}'); } catch {}
  const key = `anazori-passport-${passport?.dataset.passportSeason || 'v16'}`;
  const allowedActions = ['story','memory','people','visit',...discoveries.map(id => `rune:${id}`)];
  const validate = value => ({enabled: value?.enabled === true, events: Array.isArray(value?.events) ? [...new Set(value.events.filter(id => eventList.some(event => event.id === id)))] : [], actions: Array.isArray(value?.actions) ? [...new Set(value.actions.filter(id => allowedActions.includes(id)))] : []});
  if (passport) try { state = validate(JSON.parse(localStorage.getItem(key) || '{}')); } catch { storageWorks = false; }
  const save = () => { try { localStorage.setItem(key,JSON.stringify(state)); } catch { storageWorks = false; } };
  const score = () => {
    let earned = 0, total = Object.values(goals).reduce((sum,value) => sum + Number(value), 0);
    if (goals.events && eventList.length) earned += goals.events * state.events.length / eventList.length;
    for (const action of state.actions) earned += goals[action] || 0;
    return total ? Math.min(100, Math.round(earned / total * 100)) : 0;
  };
  const renderPassport = message => {
    if (!passport) return;
    passport.querySelector('.passport-start').hidden = state.enabled;
    passport.querySelector('.passport-active').hidden = !state.enabled;
    const points = score();
    const journey=passport.querySelector('.passport-journey');
    if(journey) journey.style.setProperty('--journey-progress',String(points));
    passport.querySelector('[data-passport-score]').textContent = String(points);
    passport.querySelector('progress').value = points;
    passport.querySelector('[data-passport-level]').textContent = points>=100?'Part of the story':points>=75?'Memory maker':points>=50?'Finding your frequency':points>=25?'Curiosity looks good on you':'Just arrived';
    passport.querySelector('[data-passport-event-count]').textContent = `${state.events.length} / ${eventList.length}`;
    passport.querySelectorAll('[data-passport-task]').forEach(item => {
      const task = item.dataset.passportTask;
      item.hidden = !goals[task];
      item.classList.toggle('is-collected', task === 'events' ? eventList.length>0 && state.events.length===eventList.length : state.actions.includes(task));
    });
    const runeKeys = discoveries.map(id => `rune:${id}`).filter(id => goals[id]);
    passport.querySelector('[data-passport-runes]').textContent = `${runeKeys.filter(id => state.actions.includes(id)).length} / ${runeKeys.length}`;
    passport.querySelector('.passport-secrets').hidden = !runeKeys.length;
    passport.querySelectorAll('[data-rune-link]').forEach(link => link.hidden = !goals[`rune:${link.dataset.runeLink}`]);
    if (message) passport.querySelector('.passport-message').textContent = message;
    passport.querySelector('.passport-note').textContent = storageWorks ? 'A keepsake, not an entry pass. Progress stays on this browser.' : 'A keepsake, not an entry pass. Browser storage is unavailable; discoveries last for this page only.';
  };
  const collect = (id, type = 'actions') => {
    if (!passport || !state.enabled || state[type].includes(id)) return;
    if (type === 'events' ? !eventList.some(event=>event.id===id) : !goals[id]) return;
    state[type].push(id); save(); renderPassport('Another moment for your passport.');
    playPerformance(passport.querySelector('[data-performance="mario-discovery"]'));
  };
  const collectRoute = () => {
    if (location.pathname.endsWith('/event.php')) collect(new URLSearchParams(location.search).get('name'), 'events');
    if (document.body.classList.contains('page-teams')) collect('people');
  };
  const knownSections = new Set();
  const discoveryObserver = typeof IntersectionObserver === 'function' ? new IntersectionObserver(entries => {
    for (const entry of entries) if (entry.isIntersecting) { const id = entry.target.id === 'about' ? 'story' : 'visit'; knownSections.add(id); collect(id); }
  }, {threshold:.2}) : null;
  document.querySelectorAll('#about,#visit').forEach(section => discoveryObserver?.observe(section));
  const announce = document.createElement('span'); announce.className = 'sr-only'; announce.setAttribute('role','status'); announce.setAttribute('aria-live','polite');
  if (scenes.length) document.body.append(announce);
  const reactionTimers = new WeakMap();
  const react = button => {
    const id = button.dataset.discovery;
    if (!discoveries.includes(id)) return;
    const scene = button.closest('[data-festival-scene]');
    if (!scene || reactionTimers.has(scene)) return;
    scene.classList.add('is-discovered');
    if (id === 'cable') theatre?.classList.add('is-powered');
    if (allowed()) {
      scene.classList.add('scene-reacting');
      const timer = later(() => { scene.classList.remove('scene-reacting'); reactionTimers.delete(scene); }, 1650);
      reactionTimers.set(scene,timer);
    }
    collect(`rune:${id}`);
    const labels = {cable:'The stage is awake. You found the crew’s secret.',door:'A door to another possibility. Secret discovered.',guardian:'The gallery guardian is awake. Secret discovered.',leaf:'You found the little festival leaf.'};
    announce.textContent = labels[id];
  };
  let previousFocus = null;
  const openPassport = button => {
    if (!passport) return;
    previousFocus = button; renderPassport(); passport.showModal(); document.body.classList.add('modal-open');
    const journey=passport.querySelector('.passport-journey');if(journey)visible.add(journey);
    playPerformance(passport.querySelector('[data-performance="mario-discovery"]'));sync();
  };
  const escapeXml = value => String(value).replace(/[<>&"']/g,char=>({'<':'&lt;','>':'&gt;','&':'&amp;','"':'&quot;',"'":'&apos;'}[char]));
  const download = () => {
    const points = score(), rich = points >= 75;
    const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="800" viewBox="0 0 1200 800"><defs><linearGradient id="paper"><stop stop-color="${rich?'#e7d1ef':'#f1e4c8'}"/><stop offset="1" stop-color="#bfdbc4"/></linearGradient></defs><rect width="1200" height="800" fill="#142b27"/><rect x="32" y="32" width="1136" height="736" rx="10" fill="url(#paper)"/><rect x="49" y="49" width="1102" height="702" rx="5" fill="none" stroke="#7c8871"/><circle cx="1000" cy="195" r="240" fill="#eef0c3" opacity=".5"/><path d="M-20 650Q360 190 680 590T1250 440" fill="none" stroke="#346653" stroke-width="2"/><path d="M-20 680Q360 220 680 620T1250 470" fill="none" stroke="#8e627b" stroke-width="2"/><g fill="#213d31" font-family="Arial,sans-serif"><text x="92" y="156" font-size="25" letter-spacing="6">ANAZORI · FESTIVAL PASSPORT</text><text x="85" y="300" font-size="87" font-weight="bold" letter-spacing="-4">I found my</text><text x="85" y="396" font-size="87" font-weight="bold" letter-spacing="-4">frequency.</text><text x="94" y="475" font-size="26">Old roots. New frequencies.</text><text x="94" y="650" font-size="24">${points} / 100 moments collected · ${escapeXml(passport.dataset.passportSeason)}</text><text x="94" y="704" font-size="16" letter-spacing="2">A FESTIVAL KEEPSAKE — NOT AN ENTRY TICKET</text></g></svg>`;
    const url = URL.createObjectURL(new Blob([svg],{type:'image/svg+xml'}));
    const link = document.createElement('a'); link.href=url; link.download='anazori-festival-postcard.svg'; link.click();
    later(()=>URL.revokeObjectURL(url),2000);
    renderPassport('Your festival postcard is ready.');
    const reward=passport.querySelector('[data-passport-reward]');if(reward)reward.hidden=false;
  };
  const click = event => {
    if (passport?.open && event.target.closest('a') && passport.contains(event.target)) { previousFocus=null; passport.close(); }
    const button = event.target.closest('button');
    if (button?.matches('[data-discovery]')) react(button);
    if (button?.matches('[data-passport-open]')) openPassport(button);
    if (button?.matches('[data-passport-start]')) { state.enabled=true; save(); collectRoute(); knownSections.forEach(id=>collect(id)); renderPassport('Your story starts here.');playPerformance(passport.querySelector('[data-performance="mario-discovery"]')); }
    if (button?.matches('[data-passport-reset]')) { state={enabled:false,events:[],actions:[]}; try { localStorage.removeItem(key); } catch {} renderPassport('');const reward=passport.querySelector('[data-passport-reward]');if(reward)reward.hidden=true;syncPerformances();passport.querySelector('[data-passport-start]').focus(); }
    if (button?.matches('[data-passport-download]')) download();
    if (event.target.closest('.gallery-item')) collect('memory');
    if (button?.matches('[data-companion-action="sponsor"]')) {const installation=button.closest('.sponsor-installation');installation.classList.add('scene-reacting');playPerformance(button.querySelector('[data-performance]'));later(()=>installation.classList.remove('scene-reacting'),3000);}
  };
  const faqToggle = event => {
    if(event.target.matches?.('.faq details') && event.target.open) playPerformance(document.querySelector('.faq-helper [data-performance="baymax-help"]'));
  };
  const sponsorHover = event => {
    const mark=event.target.closest('.sponsor-mark');
    if(mark && !mark.contains(event.relatedTarget)) playPerformance(mark.closest('.sponsor-installation').querySelector('[data-performance="stitch-light"]'));
  };
  const close = () => { previousFocus?.focus(); previousFocus=null; sync(); };
  passport?.addEventListener('close',close);
  document.addEventListener('click',click);
  document.addEventListener('toggle',faqToggle,true);
  document.querySelector('.sponsor-installation')?.addEventListener('pointerover',sponsorHover,{passive:true});
  document.addEventListener('anazori:motion',sync);
  document.addEventListener('anazori:quality',sync);
  document.addEventListener('visibilitychange',sync);
  reduced.addEventListener('change',sync); connection?.addEventListener?.('change',sync);
  const hide = event => {
    suspended=true; sync();
    if (event.persisted) return;
    destroyed=true; sceneObserver?.disconnect(); warmObserver?.disconnect(); discoveryObserver?.disconnect(); dialogs.disconnect();
    timers.forEach(clearTimeout); timers.clear();
    programme?.removeEventListener('pointerover',preview); programme?.removeEventListener('focusin',preview);
    theatre?.removeEventListener('pointerdown',swipeStart);theatre?.removeEventListener('pointerup',swipeEnd);theatre?.removeEventListener('pointercancel',cancelSwipe);theatre?.removeEventListener('click',carouselClick,true);theatre?.removeEventListener('keydown',carouselKey);scrubber?.removeEventListener('input',scrub);compact.removeEventListener('change',carouselMode);
    document.removeEventListener('click',click); document.removeEventListener('error',imageError,true);
    document.removeEventListener('toggle',faqToggle,true);document.querySelector('.sponsor-installation')?.removeEventListener('pointerover',sponsorHover);
    document.removeEventListener('anazori:motion',sync); document.removeEventListener('visibilitychange',sync);
    document.removeEventListener('anazori:quality',sync);
    reduced.removeEventListener('change',sync); connection?.removeEventListener?.('change',sync);
    passport?.removeEventListener('close',close); announce.remove();
    removeEventListener('pagehide',hide); removeEventListener('pageshow',show); removeEventListener('storage',storage);
  };
  const refresh = () => {
    if (!passport || !storageWorks) return;
    try { state=validate(JSON.parse(localStorage.getItem(key)||'{}')); } catch { storageWorks=false; }
    collectRoute(); renderPassport();
  };
  const storage = event => { if (event.key===key || event.key===null) refresh(); };
  const show = event => { if (event.persisted) { suspended=false; refresh(); sync(); } };
  addEventListener('storage',storage);
  addEventListener('pagehide',hide); addEventListener('pageshow',show);
  renderPassport(); collectRoute(); sync();
}
