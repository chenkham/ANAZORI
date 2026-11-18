<?php $activePage='home';require_once __DIR__.'/includes/festival.php';$pageTitle=setting('site_name').' '.festival_version().' · '.setting('year').' — '.setting('tagline');require __DIR__.'/includes/header.php'; ?>
<section class="hero section-pad" aria-labelledby="hero-title">
 <?php readfile(__DIR__.'/includes/hero-signature-effects.svg'); ?>
 <div class="hero-wordmark"><h1 id="hero-title" class="flash-wordmark"><span class="hero-title-text hero-title-art"><span class="hero-wordmark-glow" aria-hidden="true"><?= anazori_wordmark() ?></span><?= anazori_wordmark() ?></span></h1></div>
 <div class="hero-grid"><div class="hero-copy"><h2 class="hero-signature"><span class="hero-signature-line"><?= e(setting('hero_line1')) ?></span><br><span class="hero-signature-line"><?= e(setting('hero_line2')) ?></span></h2><p><?= cms_escape_lines(setting('hero_description')) ?></p></div></div>
</section>
<?php require __DIR__.'/includes/pixel-workshop.php'; ?>
<?php if(setting('show_countdown')==='1'): $start=cms_date(setting('starts_at'));$end=cms_date(setting('ends_at')); ?>
<section class="festival-clock section-pad" id="festival-clock" aria-labelledby="clock-heading" data-start="<?= $start?e($start->format(DateTimeInterface::ATOM)):'' ?>" data-end="<?= $end?e($end->format(DateTimeInterface::ATOM)):'' ?>">
 <div class="clock-card" data-festival-scene><span class="festival-snow" aria-hidden="true"><?= festival_performance('festival-snow') ?></span><h2 id="clock-heading"><?= $start?e(setting('countdown_title')):'The next chapter awaits.' ?></h2><div class="clock-digits" role="timer" aria-label="Festival countdown" aria-live="off" <?= $start?'':'hidden' ?>><?php foreach(['days'=>'Days','hours'=>'Hours','minutes'=>'Minutes','seconds'=>'Seconds'] as $unit=>$label): ?><div class="clock-unit"><span data-count="<?= $unit ?>">00</span><small><?= $label ?></small></div><?php endforeach; ?></div><p id="countdown-message" class="clock-caption"><?= $start?'Your next unforgettable chapter is getting closer.':e(setting('date_note')) ?></p><span class="clock-orbit" aria-hidden="true"></span></div>
 <div class="duration-card"><div class="duration-portal" aria-hidden="true"><i></i><i></i><i></i><span>16</span></div><?php if($start): ?><span class="duration-month"><?= e($start->format('F Y')) ?></span><div class="duration-range"><strong><?= $start->format('d') ?></strong><span>—</span><strong><?= $end?$end->format('d'):'?' ?></strong></div><p class="duration-dates"><?= e($start->format('d M Y').' · '.$start->format('g:i a').' IST') ?><?php if($end): ?><br><?= e('to '.$end->format('d M Y').' · '.$end->format('g:i a').' IST') ?><?php endif; ?></p><?php if($end): ?><div class="duration-footer"><span>FESTIVAL DURATION</span><strong><?= ceil(($end->getTimestamp()-$start->getTimestamp())/86400) ?> DAYS</strong></div><?php endif;else: ?><div class="duration-await">Dates dropping<br>soon.</div><?php endif; ?></div>
</section>
<?php endif; ?>
<?php if(setting('show_intro')==='1'): ?>
<section class="intro section-pad" id="about"><div class="intro-content"><h2 data-reveal><?= e(setting('intro_line1')) ?><br><span class="serif-word"><?= e(setting('intro_line2')) ?></span></h2><div class="intro-bottom" data-reveal><p><?= cms_escape_lines(setting('intro_description')) ?></p></div><a href="/teams.php" class="text-link">Meet the people behind the connection <?= arrow_icon() ?></a></div>
 <?php require __DIR__.'/includes/intro-video-view.php'; ?>
</section>
<?php endif; ?>
<?php if(setting('show_events')==='1'): ?>
<?php require __DIR__.'/includes/programme-stage.php'; ?>
<?php endif; ?>
<?php if(setting('show_culture')==='1'): ?>
<section class="culture-tech section-pad" id="culture-tech" data-frequency="50" aria-labelledby="culture-heading tech-heading" data-festival-scene>
 <div class="culture-half"><h2 id="culture-heading"><?= e(setting('culture_title')) ?></h2><p><?= cms_escape_lines(setting('culture_copy')) ?></p><span lang="as" class="assamese-word">এনাজৰী</span></div>
 <div class="frequency-deck"><div class="record-stage" aria-hidden="true"><div class="record-orbit"></div><div class="frequency-record"></div><div class="record-label"><span>ANAZORI</span><b>×</b><span><?= e(festival_version()) ?></span></div><svg class="frequency-wave" viewBox="0 0 480 180"><path d="M0 90h35q12-58 24 0t24 0t24 0t24 0t24 0h20q12-85 24 0t24 0t24 0t24 0t24 0h20q12-48 24 0t24 0t24 0t24 0h38"/></svg><div class="record-needle"></div><?= festival_performance('coco-guitar','record-musician') ?></div>
 <div class="frequency-control"><label for="frequency-mix">Find your frequency</label><input id="frequency-mix" type="range" min="0" max="100" value="50" aria-describedby="frequency-status"><div class="frequency-labels"><span>Culture</span><output id="frequency-status" for="frequency-mix" role="status" aria-live="polite">In harmony</output><span>Tech</span></div></div></div>
 <div class="tech-half"><h2 id="tech-heading"><?= e(setting('tech_title')) ?></h2><p><?= cms_escape_lines(setting('tech_copy')) ?></p><span class="tech-outline" aria-hidden="true">{ tomorrow }</span></div>
</section>
<?php endif; ?>
<?php if(setting('show_memories')==='1'): ?>
<section class="memories section-pad"><div class="section-heading"><div><h2><?= e(setting('memory_line1')) ?><br><span><?= e(setting('memory_line2')) ?></span></h2></div><p data-reveal><?= cms_escape_lines(setting('memory_copy')) ?></p></div><div class="memory-grid" data-reveal><a class="memory-main" href="/gallery.php"><img src="<?= e(setting('memory_image1')) ?>"<?= az_image_attributes84(setting('memory_image1'),'(max-width:700px) calc(100vw - 44px), 55vw') ?> width="1400" height="933" loading="lazy" alt="A moment from the Anazori festival"><span>The moments we keep. <?= arrow_icon() ?></span></a><div class="memory-side"><img src="<?= e(setting('memory_image2')) ?>"<?= az_image_attributes84(setting('memory_image2'),'(max-width:700px) calc(100vw - 44px), 35vw') ?> width="1000" height="667" loading="lazy" alt="The Anazori community"><a href="/gallery.php"><h3>A thousand stories.<br>One shared spirit.</h3><span class="text-link">Step into the memories <?= arrow_icon() ?></span></a></div></div></section>
<?php endif; ?>
<?php if(setting('show_sponsors')==='1'): $partners=cms_records('sponsor'); ?>
<section class="partners section-pad" id="partners"><div class="section-heading"><div><h2><?= e(setting('partners_line1')) ?><br><span><?= e(setting('partners_line2')) ?></span></h2></div></div>
 <?php require __DIR__.'/includes/sponsor-stage.php'; ?>
 <div class="sponsor-bento">
  <article class="bento-invitation"><div class="connect-copy"><h3><?= e(setting('sponsor_heading')) ?></h3><p><?= cms_escape_lines(setting('sponsor_copy')) ?></p><a class="button" href="mailto:<?= e(setting('sponsor_email')) ?>?subject=Anazori%20sponsorship"><?= e(setting('sponsor_cta')) ?> <?= arrow_icon() ?></a></div></article>
  <article class="bento-signal" data-festival-scene><div class="signal-companion" aria-hidden="true"><?= festival_performance('stitch-light') ?></div><h3>Amplify<br>the next wave.</h3><p>Put your brand where culture and ideas come alive.</p></article>
  <article class="bento-ticket"><div class="bento-ticket-art" aria-hidden="true"><span>ANAZORI</span><b><?= e(festival_version()) ?></b><div class="ticket-barcode"></div></div><h3>A place in the story.</h3><p>On campus. On stage. In the memories.</p></article>
  <div class="bento-contact"><span>Let’s make it happen.</span><a class="text-link" href="mailto:<?= e(setting('sponsor_email')) ?>?subject=Anazori%20partnership">Start a conversation <?= arrow_icon() ?></a></div>
 </div>
 <?php require __DIR__.'/includes/collaborations.php'; ?>
 <?php require __DIR__.'/includes/share-station.php'; ?>
</section>
<?php endif; ?>
<?php if(setting('show_visit')==='1'): ?>
<section class="visit section-pad" id="visit" data-festival-scene><div class="visit-heading"><h2><?= e(setting('visit_line1')) ?><br><span class="serif-word"><?= e(setting('visit_line2')) ?></span></h2><p><?= e(setting('venue')) ?><br><?= cms_escape_lines(setting('address')) ?></p><a class="button button-dark" href="<?= e(setting('map_url')) ?>" target="_blank" rel="noopener noreferrer">Find your way <?= arrow_icon() ?></a><?php require __DIR__.'/includes/visit-contacts.php'; ?><button class="leaf-discovery" type="button" data-discovery="leaf" aria-label="Find the hidden festival leaf"><svg viewBox="0 0 80 80" aria-hidden="true"><path d="M62 12C21 6 8 28 22 49S63 62 62 12Z" fill="#a7d4af"/><path d="m18 69 36-46m-20 29-9-14m17 3 14 1" fill="none" stroke="#42685a" stroke-width="3"/></svg></button><div class="visit-guide" aria-hidden="true"><?= festival_performance('totoro-visit') ?><span class="guide-path"></span></div><div class="visit-meta"><span><?= e(setting('year')) ?> EDITION</span><span><?= setting('starts_at')?e(cms_date_label(setting('starts_at'))):e(setting('date_note')) ?></span></div></div><div class="faq"><span class="faq-helper"><?= festival_performance('baymax-help','','interaction') ?></span><?php foreach(cms_records('faq') as $question): ?><details><summary><?= e($question['title']) ?><span>+</span></summary><p><?= cms_escape_lines($question['fields']['answer']) ?></p></details><?php endforeach; ?></div></section>
<?php endif; ?>
<?php require __DIR__.'/includes/footer.php'; ?>
