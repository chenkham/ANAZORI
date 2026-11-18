<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
  <meta name="theme-color" content="#0c151f">
  <title><?= portal_escape($title) ?></title>
  <meta name="description" content="<?= portal_escape($description) ?>">
  <meta property="og:title" content="<?= portal_escape($title) ?>">
  <meta property="og:description" content="<?= portal_escape($description) ?>">
  <meta property="og:type" content="website">
  <meta property="og:image" content="<?= portal_escape($portal['url'] . portal_url('assets/portal/social.svg')) ?>">
  <meta name="twitter:card" content="summary_large_image">
  <meta name="twitter:title" content="<?= portal_escape($title) ?>">
  <meta name="twitter:description" content="<?= portal_escape($description) ?>">
  <meta name="twitter:image" content="<?= portal_escape($portal['url'] . portal_url('assets/portal/social.svg')) ?>">
  <meta name="csrf-token" content="<?= portal_escape($_SESSION['portal_csrf']) ?>">
  <link rel="icon" href="<?= portal_url('assets/portal/mark.svg') ?>" type="image/svg+xml">
  <link rel="preload" href="<?= portal_url('assets/ClashDisplay_Complete/Fonts/WEB/fonts/ClashDisplay-Variable.woff2') ?>" as="font" type="font/woff2" crossorigin>
  <link rel="stylesheet" href="<?= portal_url('assets/portal/portal.css') ?>">
  <script type="module" src="<?= portal_url('assets/portal/app.js') ?>"></script>
</head>
<body data-base="<?= portal_escape($portal['base_path']) ?>" data-start="<?= portal_escape($portal['starts_at']) ?>">
<a class="skip-link" href="#programme">Skip the 3D world — browse the programme</a>
<header class="site-header">
  <a href="<?= portal_url() ?>" class="brand" aria-label="Anazori home"><img src="<?= portal_url('assets/portal/mark.svg') ?>" width="42" height="42" alt=""><span>ANAZORI<small>CCSA · DIBRUGARH UNIVERSITY</small></span></a>
  <nav class="main-nav" aria-label="Main navigation"><a class="active" href="#world">The world <span class="tiny-dot"></span></a><a href="#programme">Programme</a><a href="#heritage">Our story</a></nav>
  <a class="header-cta" href="#programme">Find your experience <i data-lucide="arrow-up-right"></i></a>
  <button class="icon-button mobile-menu" aria-label="Open navigation" aria-expanded="false" aria-controls="mobile-nav"><i data-lucide="menu"></i></button>
</header>
<nav id="mobile-nav" aria-label="Mobile navigation" hidden><a href="#world">The world</a><a href="#programme">Programme</a><a href="#heritage">Our story</a><button data-open="settings">Experience settings</button></nav>
<main>
  <section id="world" class="world-shell" aria-labelledby="world-title">
    <div id="world-canvas" aria-hidden="true"></div>
    <div class="world-atmosphere" aria-hidden="true"></div>
    <canvas id="rain-overlay" aria-hidden="true"></canvas>
    <div class="world-vignette" aria-hidden="true"></div>
    <aside class="world-tools" aria-label="World controls">
      <button class="tool active" id="home-view" aria-label="Return to central portal"><i data-lucide="orbit"></i><span>HOME</span></button>
      <button class="tool" data-open="map" aria-label="Open world map"><i data-lucide="map"></i><span>MAP</span></button>
      <button class="tool" id="sound-toggle" aria-label="Enable ambient sound" aria-pressed="false"><i data-lucide="volume-x"></i><span>SOUND</span></button>
      <button class="tool" data-open="settings" aria-label="Experience settings"><i data-lucide="sliders-horizontal"></i><span>SETTINGS</span></button>
      <span class="rail-line"></span><span class="rail-text">EST. CCSA / ASSAM</span>
    </aside>
    <div class="world-topline"><span><span class="status-dot"></span> A NEW WORLD. FAMILIAR ROOTS.</span><span class="coordinates">27.45° N &nbsp; 94.90° E <span class="divider">/</span> ASSAM, INDIA</span></div>
    <div class="hero-copy">
      <div class="edition-label"><span class="stitch">◇</span> CULTURE × TECHNOLOGY <span class="edition"><?= portal_escape($portal['edition']) ?></span></div>
      <h1 id="world-title">ANAZORI<span class="title-period">.</span></h1>
      <p class="assamese" lang="as">এনাজৰী <span lang="en">/ a bond that brings us together</span></p>
      <h2>Rooted in culture.<br>Wired for <em>tomorrow.</em></h2>
      <p class="hero-description">Follow the river. Find your people.<br>A new dimension of technology, creativity, and<br class="desktop-break"> Assamese spirit awaits at Dibrugarh University.</p>
      <div class="hero-actions"><button class="primary-button" id="explore-world">Enter Neo-Axom <i data-lucide="arrow-up-right"></i></button><button class="text-button" data-open="teaser"><i data-lucide="circle-play"></i> The festival film</button></div>
      <div class="festival-status"><span class="status-dot"></span><span id="countdown">Next edition · dates to be announced</span></div>
    </div>
    <div class="scene-label"><span class="label-line"></span><span>THE JAAPI BEACON<small>HERITAGE, IN A NEW LIGHT</small></span><span class="label-cross">+</span></div>
    <div class="world-meta"><span class="live-indicator"></span><span id="render-status">PREPARING YOUR WORLD</span><span class="meta-line"></span><button id="mode-toggle" aria-pressed="false">Switch to light mode <i data-lucide="layers-2"></i></button></div>
    <div class="exploration-hud" hidden>
      <div><span class="eyebrow">CURRENT DESTINATION</span><h2 id="zone-name">The central portal</h2><p id="zone-description">The heart of Neo-Axom. Follow a light to discover your next experience.</p><div class="flex gap-3"><button id="zone-action" class="primary-button">Explore programmes <i data-lucide="arrow-up-right"></i></button><button id="leave-explore" class="small-button">Exit flight</button></div></div>
      <div class="flight-help"><span><kbd>W</kbd><kbd>A</kbd><kbd>S</kbd><kbd>D</kbd> or arrows to fly</span><span>Drag to look · tap a beacon to travel</span><button id="collect-crystal" class="crystal-button"><i data-lucide="gem"></i> Collect this island’s Data-Gamosa</button></div>
    </div>
    <div class="joystick" id="joystick" aria-label="Touch flight control" role="group" hidden><span></span></div>
    <div class="journey-progress"><button data-open="badge"><i data-lucide="gem"></i><span id="collection-count">0 / 5</span><span class="collection-caption">DATA-GAMOSAS</span></button><span class="journey-line"></span><span class="journey-note">A little curiosity goes a long way.</span></div>
    <nav class="destination-bar" aria-label="Quick fly destinations">
      <a href="#world" data-zone="hub" class="destination selected" aria-current="true"><span class="destination-number">01</span><span class="destination-icon"><i data-lucide="orbit"></i></span><span>Central portal<small>YOUR JOURNEY STARTS HERE</small></span><i data-lucide="arrow-up-right" class="destination-arrow"></i></a>
      <a href="#zone-tech" data-zone="tech" class="destination"><span class="destination-number">02</span><span class="destination-icon"><i data-lucide="code-2"></i></span><span>Tech dome<small>BUILD. BREAK. BREAK THROUGH.</small></span><i data-lucide="arrow-up-right" class="destination-arrow"></i></a>
      <a href="#zone-culture" data-zone="culture" class="destination"><span class="destination-number">03</span><span class="destination-icon"><i data-lucide="audio-lines"></i></span><span>Sanskriti arena<small>FIND YOUR RHYTHM</small></span><i data-lucide="arrow-up-right" class="destination-arrow"></i></a>
      <a href="#zone-workshops" data-zone="workshops" class="destination"><span class="destination-number">04</span><span class="destination-icon"><i data-lucide="lightbulb"></i></span><span>Idea islands<small>COME CURIOUS. LEAVE INSPIRED.</small></span><i data-lucide="arrow-up-right" class="destination-arrow"></i></a>
      <a href="#heritage" data-zone="heritage" class="destination"><span class="destination-number">05</span><span class="destination-icon"><i data-lucide="fingerprint"></i></span><span>Our roots<small>THE PEOPLE. THE PURPOSE.</small></span><i data-lucide="arrow-up-right" class="destination-arrow"></i></a>
    </nav>
  </section>
  <div class="announcement"><span class="eyebrow"><i data-lucide="radio"></i> FROM THE BEACON</span><p><?= portal_escape($portal['announcement']) ?></p><a href="#programme">Discover what’s ahead <i data-lucide="arrow-right"></i></a></div>
  <section id="programme" class="programme section-wrap" aria-labelledby="programme-title">
    <div class="section-heading"><div><p class="eyebrow"><span class="stitch">◇</span> FIND YOUR FREQUENCY</p><h2 id="programme-title">Many worlds.<br><span>One Anazori.</span></h2></div><p>For the builders, the dreamers, and everyone<br>in between. Make space for what moves you.<br><span class="programme-notice">Programme preview · schedules to be announced</span></p></div>
    <div class="programme-filters" role="group" aria-label="Filter programmes"><button data-filter="all" class="selected" aria-pressed="true">All experiences <span>06</span></button><button data-filter="tech" aria-pressed="false" id="zone-tech">Technology</button><button data-filter="culture" aria-pressed="false" id="zone-culture">Culture</button><button data-filter="workshops" aria-pressed="false" id="zone-workshops">Workshops</button></div>
    <div class="event-grid">
      <?php foreach ($portal['events'] as $event): ?>
      <article class="event-card <?= portal_escape($event['category']) ?>" data-category="<?= portal_escape($event['category']) ?>">
        <div class="event-art" aria-hidden="true"><span class="art-grid"></span><span class="art-orbit orbit-one"></span><span class="art-orbit orbit-two"></span><i data-lucide="<?= portal_escape($event['icon']) ?>"></i><span class="art-caption"><?= portal_escape($event['tag']) ?></span><span class="art-corner">›</span></div>
        <div class="event-info"><div class="event-meta"><span><?= portal_escape($event['format']) ?></span><span>COMING TO ANAZORI</span></div><h3><?= portal_escape($event['title']) ?></h3><p><?= portal_escape($event['description']) ?></p><button class="event-register" data-register="<?= portal_escape($event['id']) ?>">Register your interest <i data-lucide="arrow-up-right"></i></button></div>
      </article>
      <?php endforeach; ?>
    </div>
    <noscript><p>The programme is available above. Enable JavaScript to use 3D navigation and submit a registration.</p></noscript>
  </section>
  <section id="heritage" class="heritage section-wrap" aria-labelledby="heritage-title"><div class="heritage-art" aria-hidden="true"><div class="woven-mark">◇<span>◇</span>◇</div><p>এনাজৰী</p><span>ROOTS RUN DEEP. IDEAS TRAVEL FAR.</span></div><div class="heritage-copy"><p class="eyebrow">MADE OF MORE THAN CODE</p><h2 id="heritage-title">A shared spirit.<br>An open future.</h2><p>Anazori is a bond. Between people and ideas. Between the place we call home and the worlds we want to build.</p><p>From the Centre for Computer Science and Applications at Dibrugarh University, our festival brings technology and cultural expression into the same conversation. Come for an experience. Stay for the community.</p><a class="text-link" href="<?= portal_url('teams.php') ?>">Meet the people behind Anazori <i data-lucide="arrow-up-right"></i></a></div></section>
  <section class="closing section-wrap"><p class="eyebrow">YOUR NEXT GREAT STORY STARTS HERE</p><h2>Come curious.<br>Leave <em>connected.</em></h2><a class="primary-button" href="#programme">Find your experience <i data-lucide="arrow-up-right"></i></a><div class="closing-stitch" aria-hidden="true">◇ ◈ ◇ ◈ ◇ ◈ ◇ ◈ ◇ ◈ ◇ ◈ ◇</div></section>
</main>
<footer class="site-footer"><a class="brand" href="#world"><img src="<?= portal_url('assets/portal/mark.svg') ?>" width="36" height="36" alt=""><span>ANAZORI<small>CULTURE × TECHNOLOGY</small></span></a><p>CCSA, Dibrugarh University<br>Dibrugarh, Assam · India</p><div><button class="text-button" data-open="feedback">Share feedback <i data-lucide="arrow-up-right"></i></button><button class="text-button" data-open="settings">Accessibility & settings</button></div><span>© <?= date('Y') ?> ANAZORI<br>Rooted in Assam. Open to everyone.</span></footer>
<dialog id="register-dialog" class="glass-dialog"><button class="dialog-close icon-button" aria-label="Close registration"><i data-lucide="x"></i></button><p class="eyebrow">MAKE THE FIRST CONNECTION</p><h2>Count me in.</h2><p class="dialog-intro">Register your interest. Dates, fees, and entry details will be announced by the organisers.</p><form id="register-form"><label>Choose your experience<select name="event" required><?php foreach ($portal['events'] as $event): ?><option value="<?= portal_escape($event['id']) ?>"><?= portal_escape($event['title']) ?></option><?php endforeach; ?></select></label><label>Your name<input name="name" autocomplete="name" minlength="2" maxlength="100" placeholder="Full name" required></label><label>Email address<input name="email" type="email" autocomplete="email" maxlength="254" placeholder="you@example.com" required></label><label>College or organisation<input name="college" autocomplete="organization" minlength="2" maxlength="160" placeholder="Where you’re joining us from" required></label><label class="checkbox-label"><input name="consent" type="checkbox" required><span>I agree that the organisers may store these details for this programme. This records interest and does not confirm a seat or payment.</span></label><button class="primary-button" type="submit">Register my interest <i data-lucide="arrow-up-right"></i></button><p class="form-message" role="status" aria-live="polite"></p></form></dialog>
<dialog id="settings-dialog" class="glass-dialog"><button class="dialog-close icon-button" aria-label="Close settings"><i data-lucide="x"></i></button><p class="eyebrow">MAKE YOURSELF AT HOME</p><h2>Your experience.</h2><label class="setting-row"><span>World atmosphere<small>A different light on the same river.</small></span><select id="atmosphere"><option value="dusk">River dusk</option><option value="midnight">Neon midnight</option><option value="monsoon">Monsoon mist</option></select></label><label class="setting-row"><span>Graphics<small>Auto adapts to your device.</small></span><select id="quality"><option value="auto">Adaptive</option><option value="low">Low</option><option value="high">High</option></select></label><label class="setting-row"><span>Ambient volume</span><input id="volume" type="range" min="0" max="100" value="25" aria-label="Ambient volume"></label><label class="setting-row"><span>High contrast</span><input id="contrast" type="checkbox" role="switch"></label><label class="setting-row"><span>Reduce motion<small>Pause ambient movement and shorten travel.</small></span><input id="reduce-motion" type="checkbox" role="switch"></label><label class="setting-row"><span>Light / screen-reader mode<small>Use the full HTML programme without 3D.</small></span><input id="light-mode" type="checkbox" role="switch"></label><label class="setting-row"><span>Chromatic glow<small>A subtle spectral edge on the world.</small></span><input id="chromatic" type="checkbox" role="switch"></label><p class="settings-help">Keyboard: Tab to choose a destination, Enter to travel. During flight, use WASD or arrows; drag to look. Escape closes panels.</p></dialog>
<dialog id="map-dialog" class="glass-dialog map-dialog"><button class="dialog-close icon-button" aria-label="Close map"><i data-lucide="x"></i></button><p class="eyebrow">FIVE ISLANDS. ENDLESS POSSIBILITIES.</p><h2>A world to explore.</h2><div class="world-map"><svg viewBox="0 0 500 260" aria-hidden="true"><path d="M50 210Q130 10 250 135T460 40"/><path d="M250 135 130 62M250 135 395 80M250 135 380 210M250 135 85 210" class="map-routes"/></svg><button data-zone="hub" class="map-hub"><i data-lucide="orbit"></i>Central portal</button><button data-zone="tech" class="map-tech"><i data-lucide="code-2"></i>Tech dome</button><button data-zone="culture" class="map-culture"><i data-lucide="audio-lines"></i>Sanskriti</button><button data-zone="workshops" class="map-workshops"><i data-lucide="lightbulb"></i>Idea islands</button><button data-zone="heritage" class="map-heritage"><i data-lucide="fingerprint"></i>Our roots</button></div><p class="dialog-intro">Choose an island to quick fly. Every island holds a Data-Gamosa — find all five to unlock your explorer badge.</p></dialog>
<dialog id="badge-dialog" class="glass-dialog badge-dialog"><button class="dialog-close icon-button" aria-label="Close collection"><i data-lucide="x"></i></button><i data-lucide="gem" class="badge-gem"></i><p class="eyebrow">A LITTLE PIECE OF EACH WORLD</p><h2 id="badge-title">Follow your curiosity.</h2><p id="badge-description">Collect a Data-Gamosa on each of the five islands to earn your Neo-Axom Explorer badge.</p><div id="badge-slots" class="badge-slots" aria-label="Collection progress"></div><button id="download-badge" class="primary-button" hidden>Download explorer badge <i data-lucide="download"></i></button><p class="dialog-intro">Your collection is saved on this device. The badge is a digital keepsake, with no purchase or discount attached.</p></dialog>
<dialog id="teaser-dialog" class="glass-dialog teaser-dialog"><button class="dialog-close icon-button" aria-label="Close festival film"><i data-lucide="x"></i></button><p class="eyebrow">A GLIMPSE OF THE ANAZORI SPIRIT</p><h2>The festival film.</h2><video controls playsinline preload="none" poster="<?= portal_url('assets/teaser.jpg') ?>"><source src="<?= portal_url('anazori.mp4') ?>" type="video/mp4"></video><p class="dialog-intro">From the Anazori archive.</p></dialog>
<dialog id="feedback-dialog" class="glass-dialog"><button class="dialog-close icon-button" aria-label="Close feedback"><i data-lucide="x"></i></button><p class="eyebrow">HELP SHAPE THE NEXT CHAPTER</p><h2>We’re listening.</h2><form id="feedback-form"><label>Your feedback<textarea name="message" minlength="10" maxlength="2000" rows="5" placeholder="What would you love to see at Anazori?" required></textarea></label><p class="dialog-intro">Please leave out personal or sensitive information.</p><button class="primary-button" type="submit">Send feedback <i data-lucide="arrow-up-right"></i></button><p class="form-message" role="status" aria-live="polite"></p></form></dialog>
<div id="toast" class="toast" role="status" aria-live="polite"></div>
</body></html>
