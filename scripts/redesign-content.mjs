import {readFileSync,writeFileSync,mkdirSync} from 'node:fs';
let home=readFileSync('index.php','utf8');
const hero=`<?php $activePage='home'; $pageTitle='ANAZORI 2026 — Culture × Tech'; require_once __DIR__.'/includes/header.php'; ?>
<section class="hero section-pad" aria-labelledby="hero-title">
 <div class="hero-media" aria-hidden="true"><video id="hero-film" muted loop playsinline preload="none" poster="/assets/2026/hero-poster.jpg" data-src="/assets/2026/hero-loop.mp4" tabindex="-1"></video></div>
 <div class="hero-topline"><span><span class="status-dot"></span> CCSA, DIBRUGARH UNIVERSITY PRESENTS</span><span>ASSAM, INDIA <span class="coordinate-cross">+</span> 27.45° N / 94.90° E</span></div>
 <div class="hero-wordmark"><h1 id="hero-title">ANAZORI</h1><div class="edition-badge"><span>THE NEXT CHAPTER</span><strong>’26</strong></div></div>
 <div class="hero-grid"><div class="hero-copy"><p class="eyebrow">A TECHNO-CULTURAL CONFLUENCE</p><h2>Old roots.<br><span>New frequencies.</span></h2><p>A meeting of minds. A celebration of roots.<br>One festival to make something extraordinary.</p><div class="hero-actions"><a href="/events.php" class="button button-orange">Explore the experiences <?= arrow_icon() ?></a><button class="film-button" data-film><span class="play-circle">▶</span> Feel the energy</button></div></div>
 <div class="hero-side"><span class="hero-orbit" aria-hidden="true"><?= weave_mark() ?></span><span class="hero-side-caption">MANY WORLDS.<br>ONE CONNECTION.</span><div class="hero-date"><span class="status-dot"></span> 2026 EDITION<span>Dates dropping soon</span></div></div></div>
 <div class="hero-bottom"><a href="#about"><span class="scroll-cue">↓</span> SCROLL INTO THE EXPERIENCE</a><span>ROOTED IN ASSAM. WIRED FOR TOMORROW.</span><button class="motion-toggle" aria-pressed="false">Pause motion <span>Ⅱ</span></button></div>
</section>
`;
home=hero+home.slice(home.indexOf('<div class="ticker"'));
const intro=`<section class="intro section-pad" id="about">
 <div class="intro-content"><p class="eyebrow"><span class="section-number">01</span> THE ANAZORI SPIRIT</p><h2 data-reveal>Some connections<br>change <span class="serif-word">everything.</span></h2><div class="intro-bottom" data-reveal><p>Between a beat and a breakthrough. Between where we come from and what comes next. Anazori brings culture and technology together at the Centre for Computer Science and Applications, Dibrugarh University.</p></div><a href="/teams.php" class="text-link">Meet the people behind the connection <?= arrow_icon() ?></a></div>
 <div class="connection-art" id="connection-sculpture" role="img" aria-label="An interwoven metallic sculpture, representing culture and technology connected"><div class="sculpture-grid" aria-hidden="true"></div><span class="sculpture-corner corner-tl" aria-hidden="true"></span><span class="sculpture-corner corner-br" aria-hidden="true"></span><div class="sculpture-fallback" aria-hidden="true"><img src="/assets/2026/graphics/connection.svg" alt="" width="600" height="600"></div><canvas id="connection-canvas" aria-hidden="true"></canvas><span class="sculpture-label">CULTURE × TECHNOLOGY</span><span class="sculpture-foot">THE THREAD THAT CONNECTS US <span>↗</span></span></div>
</section>
`;
home=home.slice(0,home.indexOf('<section class="intro '))+intro+home.slice(home.indexOf('<section class="experiences '));
writeFileSync('index.php',home);
mkdirSync('assets/2026/graphics',{recursive:true});
// Original vector art: projected torus curves form a shared visual language.
for(const [name,accent] of [['connection','#d7ef8a'],['code','#d7ef8a'],['game','#c1b1ed'],['ball','#98c7cf'],['workshop','#dbd0a7'],['paper','#c1b1ed'],['art','#d4c2ac']]) {
 let paths='';
 const project=(x,y,z)=>{const a=.68,b=-.5;const yy=y*Math.cos(a)-z*Math.sin(a),zz=y*Math.sin(a)+z*Math.cos(a);return [300+(x*Math.cos(b)+zz*Math.sin(b))*103,290+yy*103];};
 for(let i=0;i<44;i++) {let d='';for(let j=0;j<=100;j++){const u=j/100*Math.PI*2,v=i/44*Math.PI*2;const r=1.55+.57*Math.cos(v);const [x,y]=project(r*Math.cos(u),r*Math.sin(u),.57*Math.sin(v));d+=(j?'L':'M')+x.toFixed(2)+','+y.toFixed(2);}paths+=`<path d="${d}" fill="none" stroke="${accent}" stroke-opacity="${.28+i/100}" stroke-width="1.1"/>`;}
 let symbol=name==='game'?'<path d="M250 260v60m-30-30h60"/><circle cx="352" cy="275" r="5"/><circle cx="372" cy="295" r="5"/>':name==='code'?'<path d="m265 258-30 30 30 30m70-60 30 30-30 30m-25-67-20 74"/>':name==='workshop'?'<path d="M270 322l65-65m-60 0h60v60"/>':name==='paper'?'<path d="M268 243h44l24 25v65h-68zm44 0v25h24m-51 19h34m-34 18h34"/>':name==='ball'?'<path d="m300 255 32 24-12 37h-40l-12-37z"/>':name==='art'?'<path d="m300 245 10 30 30-15-15 30 30 10-30 10 15 30-30-15-10 30-10-30-30 15 15-30-30-10 30-10-15-30 30 15z"/>':'';
 const svg=`<svg xmlns="http://www.w3.org/2000/svg" width="600" height="600" viewBox="0 0 600 600"><defs><radialGradient id="g"><stop stop-color="${accent}" stop-opacity=".11"/><stop offset="1" stop-color="${accent}" stop-opacity="0"/></radialGradient></defs><circle cx="300" cy="290" r="290" fill="url(#g)"/>${paths}<g stroke="${accent}" stroke-width="5" stroke-linecap="round" stroke-linejoin="round" fill="none">${symbol}</g></svg>`;
 writeFileSync(`assets/2026/graphics/${name}.svg`,svg);
}
console.log('Created cinematic homepage and original vector graphics.');
