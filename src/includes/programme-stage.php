<?php $programmeEvents=$festival['events']; $firstEvent=array_key_first($programmeEvents); ?>
<section class="programme-section section-pad" id="experiences" aria-labelledby="programme-heading" data-festival-scene>
 <div class="programme-heading"><h2 id="programme-heading"><?= e(setting('stage_heading','Find your')) ?><br><em><?= e(setting('stage_accent','moment.')) ?></em></h2><div class="programme-heading-links"><a class="programme-all" href="/events.php">Explore the programme <?= arrow_icon() ?></a><?php if(setting('brochure_pdf')): ?><a class="programme-all" href="<?= e(setting('brochure_pdf')) ?>" download>Download brochure <span aria-hidden="true">↓</span></a><?php endif; ?></div></div>
 <?php if($programmeEvents): ?>
 <div class="programme-layout" data-programme>
  <div class="programme-index" aria-label="Festival experiences">
   <?php $programmeNumber=0; foreach($programmeEvents as $slug=>$event): ?>
   <a class="programme-link<?= $slug===$firstEvent?' is-selected':'' ?>" href="/event.php?name=<?= e(rawurlencode($slug)) ?>" data-programme-select="<?= e($slug) ?>"><span class="programme-number" aria-hidden="true"><?= str_pad((string)++$programmeNumber,2,'0',STR_PAD_LEFT) ?></span><span class="programme-link-copy"><h3><?= e($event['title']) ?></h3><span><?= e(cms_phase_label($event)) ?></span></span><span class="programme-arrow" aria-hidden="true">›</span></a>
   <?php endforeach; ?>
  </div>
  <div class="programme-theatre programme-photo-theatre" aria-label="Event artwork">
   <div class="theatre-scenery" aria-hidden="true"><span class="theatre-sun"></span><span class="theatre-line"></span><span class="theatre-ground"></span><span class="theatre-pulse"></span></div>
   <?php $programmeNumber=0;foreach($programmeEvents as $slug=>$event):$cast=festival_scene_character($slug,$event);$photo=$event['image']??'';if(!$photo&&($event['art']??'')==='dance')$photo='/assets/2026/stage.webp'; ?>
   <div class="programme-pane" id="programme-<?= e($slug) ?>" data-programme-pane="<?= e($slug) ?>" data-category="<?= e($event['category']??'tech') ?>" <?= $slug===$firstEvent?'':'hidden' ?>>
    <span class="theatre-numeral" aria-hidden="true"><?= str_pad((string)++$programmeNumber,2,'0',STR_PAD_LEFT) ?></span>
    <div class="theatre-art programme-photo-scene">
     <div class="programme-photo-frame<?= $photo?'':' is-awaiting-photo' ?>"><?php if($photo): ?><img class="programme-event-photo" src="<?= e($photo) ?>"<?= az_image_attributes84($photo,'(max-width:700px) 80vw, 50vw') ?> alt="<?= e($event['title'].' — Anazori') ?>" width="1200" height="800" loading="lazy" decoding="async"><?php else: ?><span class="programme-photo-placeholder" aria-hidden="true"><?= e($event['title']) ?></span><?php endif; ?></div>
     <div class="programme-companion" aria-hidden="true"><?= festival_programme_companion($slug,$event,$slug!==$firstEvent) ?></div>
    </div>
    <div class="theatre-caption"><h3 class="programme-mobile-title"><?= e($event['title']) ?></h3><p><?= e($event['short']??'Discover your next Anazori experience.') ?></p><a href="/event.php?name=<?= e(rawurlencode($slug)) ?>">Explore <?= e($event['title']) ?> <?= arrow_icon() ?></a></div>
   </div>
   <?php endforeach; ?>
   <div class="programme-swipe-controls" aria-label="Browse festival events" hidden>
    <span class="programme-position" role="status" aria-live="polite" aria-atomic="true"><span data-programme-count>01 / <?= str_pad((string)count($programmeEvents),2,'0',STR_PAD_LEFT) ?></span><span class="sr-only" data-programme-name><?= e($programmeEvents[$firstEvent]['title']) ?></span></span>
    <input class="programme-scrubber" data-programme-scrub type="range" min="1" max="<?= count($programmeEvents) ?>" step="1" value="1" aria-label="Choose event" aria-valuetext="1 of <?= count($programmeEvents) ?>: <?= e($programmeEvents[$firstEvent]['title']) ?>">
    <button class="programme-next" type="button" data-programme-step="1" aria-label="Next event"><svg width="24" height="24" viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M5 12h14m-5-5 5 5-5 5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg></button>
   </div>
   <?php if(setting('show_characters','1')==='1'): ?><button class="crew-discovery" type="button" data-discovery="cable" aria-label="Wake the stage crew" aria-describedby="crew-hint"><?= festival_character('minion') ?><span id="crew-hint">A little help?</span></button><?php endif; ?>
   <span class="crew-cable" aria-hidden="true"></span>
  </div>
 </div>
 <?php else: ?><p class="programme-empty">The next programme is taking shape. Check back soon.</p><?php endif; ?>
</section>
