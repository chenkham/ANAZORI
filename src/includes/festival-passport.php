<?php
$passportEvents=array_map(fn($slug,$event)=>['id'=>$slug,'title'=>$event['title']],array_keys($festival['events']),array_values($festival['events']));
$passportGoals=['events'=>$passportEvents?35:0,'story'=>setting('show_intro')==='1'?10:0,'memory'=>cms_records('gallery')?15:0,'people'=>10,'visit'=>setting('show_visit')==='1'?10:0];
$passportCharacters=setting('show_characters','1')==='1';
$passportGoals['rune:cable']=$passportCharacters&&setting('show_events')==='1'&&$passportEvents?5:0;
$passportGoals['rune:guardian']=$passportCharacters?5:0;
$passportGoals['rune:leaf']=setting('show_visit')==='1'?5:0;
?>
<section class="passport-invitation section-pad" aria-label="Optional festival discoveries">
 <?php if(($activePage??'')==='home' && $passportCharacters): ?><span class="passport-guide" aria-hidden="true"><?= festival_vector_character('link') ?></span><?php else: ?><span class="passport-seal" aria-hidden="true">16</span><?php endif; ?><div><p>A little more to discover.</p><span>Collect moments along the way.</span></div><button type="button" data-passport-open>Open festival passport <?= arrow_icon() ?></button>
</section>
<dialog class="passport-dialog" id="festival-passport" aria-labelledby="passport-title" data-passport-events="<?= e(json_encode($passportEvents,JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_AMP|JSON_HEX_QUOT)) ?>" data-passport-goals="<?= e(json_encode($passportGoals)) ?>" data-passport-season="<?= e(setting('year').'-'.festival_version()) ?>">
 <button class="dialog-close" aria-label="Close festival passport">✕</button>
 <span class="passport-seal" aria-hidden="true">16</span><h2 id="passport-title">Your festival<br><em>passport.</em></h2>
 <p class="passport-intro">A few discoveries. A little curiosity. Your own Anazori story.</p>
 <div class="passport-start"><p>Save discoveries on this browser. This optional keepsake is separate from your entry tickets.</p><button class="button" type="button" data-passport-start>Start exploring</button></div>
 <div class="passport-active" hidden>
  <?php if(($activePage??'')==='home' && $passportCharacters): ?><div class="passport-journey" data-festival-scene><span class="passport-track" aria-hidden="true"></span><?= festival_performance('mario-discovery','passport-runner','interaction') ?><span class="passport-gem" aria-hidden="true"></span></div><?php endif; ?>
  <div class="passport-progress-copy"><span data-passport-level>Just arrived</span><strong><span data-passport-score>0</span> / 100</strong></div><progress max="100" value="0" aria-label="Festival discovery progress"></progress>
  <p class="passport-message" role="status" aria-live="polite"></p>
  <ul class="passport-checklist"><li data-passport-task="events"><a href="/#experiences">Explore the events</a><span data-passport-event-count>0 explored</span></li><li data-passport-task="story"><a href="/#about">Find the festival story</a><span>10</span></li><li data-passport-task="memory"><a href="/gallery.php">Open a memory</a><span>15</span></li><li data-passport-task="people"><a href="/teams.php">Meet the people</a><span>10</span></li><li data-passport-task="visit"><a href="/#visit">Plan your visit</a><span>10</span></li></ul>
  <details class="passport-secrets"><summary>Little secrets <span data-passport-runes>0 / 3</span></summary><p>Follow the clues around the festival.</p><div><a data-rune-link="cable" href="/#experiences">The stage crew</a><a data-rune-link="guardian" href="/gallery.php">The gallery guardian</a><a data-rune-link="leaf" href="/#visit">The hidden leaf</a></div></details>
  <div class="passport-actions"><button type="button" class="button" data-passport-download>Download my postcard</button><button type="button" class="passport-reset" data-passport-reset>Clear my discoveries</button></div><?php if(($activePage??'')==='home' && $passportCharacters): ?><div class="passport-prize" data-passport-reward hidden><?= festival_vector_character('kirby') ?><span>Your keepsake is ready.</span></div><?php endif; ?><p class="passport-note">A keepsake, not an entry pass. Progress stays on this browser.</p>
 </div>
</dialog>
