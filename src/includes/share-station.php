<?php
$keepsakePreview=['name'=>'Your name','festival'=>setting('site_name'),'logo'=>setting('logo'),'edition'=>festival_version(),'year'=>setting('year'),'date'=>setting('starts_at')?cms_date(setting('starts_at'))?->format('d M Y'):setting('date_note'),'notice'=>'Keepsake only · Not valid for event entry'];
?>
<section class="festival-share-station keepsake-studio" id="motion-studio" aria-labelledby="keepsake-heading" data-festival-scene data-keepsake-studio="<?= e(json_encode($keepsakePreview,JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT)) ?>">
 <div class="keepsake-heading"><div><h3 id="keepsake-heading">Your Anazori ticket.</h3><p>A keepsake to share. Not valid for event entry.</p></div>
  <form class="keepsake-actions" data-keepsake-form>
   <label for="keepsake-name">Enter your name</label>
   <div class="keepsake-name-row"><input id="keepsake-name" name="keepsake_name" type="text" placeholder="Your name" autocomplete="name" maxlength="60" required data-keepsake-name><button type="submit" class="button keepsake-download" data-video-save disabled>Download MP4 <span aria-hidden="true">↓</span></button></div>
  </form>
 </div>
 <div class="keepsake-stage"><canvas width="1280" height="720" role="img" aria-label="Preview of your personal Anazori keepsake. Not valid for event entry.">Your Anazori keepsake. Enter your name to personalise your video. Not valid for event entry.</canvas><video class="keepsake-result" playsinline muted loop preload="metadata" aria-label="Your Anazori keepsake video. Not valid for event entry." hidden></video><button class="keepsake-play" type="button" data-preview-pause aria-label="Pause ticket preview">Ⅱ</button></div>
 <div class="keepsake-feedback"><p class="share-feedback" role="status" aria-live="polite"></p><progress max="100" value="0" aria-label="Video export progress" hidden></progress><a class="keepsake-save-again" data-ready-download download hidden>Save MP4 ↓</a></div>
 <noscript><p>Enable JavaScript to preview and download your animated keepsake.</p></noscript>
</section>
