<?php
// The map is a view of the live programme; adding an event in Studio adds it here.
$atlasLabels = ['tech'=>'Tech', 'culture'=>'Culture', 'gaming'=>'Gaming', 'sports'=>'Sports'];
$atlasGroups = array_fill_keys(array_keys($atlasLabels), []);
foreach ($festival['events'] as $atlasSlug=>$atlasEvent) {
    $atlasCategory = trim((string)($atlasEvent['category'] ?? '')) ?: 'other';
    if (!isset($atlasLabels[$atlasCategory])) {
        $atlasLabels[$atlasCategory] = ucwords(str_replace(['-', '_'], ' ', $atlasCategory));
        $atlasGroups[$atlasCategory] = [];
    }
    $atlasGroups[$atlasCategory][$atlasSlug] = $atlasEvent;
}
?>
<section class="world-atlas section-pad" id="experiences" aria-labelledby="atlas-heading" data-world-atlas>
 <div class="atlas-heading"><h2 id="atlas-heading">Find your event. <br><span>Get your ticket.</span></h2><a class="atlas-all" href="/events.php">Explore the programme</a></div>
 <div class="atlas-explorer">
  <div class="atlas-map">
  <div class="atlas-stage" role="group" aria-label="Interactive festival constellation">
   <svg class="atlas-chart" viewBox="0 0 700 550" fill="none" aria-hidden="true">
    <defs><radialGradient id="atlas-nebula"><stop stop-color="#83f4ed" stop-opacity=".13"/><stop offset="1" stop-color="#83f4ed" stop-opacity="0"/></radialGradient><linearGradient id="atlas-orbit-light"><stop stop-color="#83f4ed" stop-opacity=".65"/><stop offset=".48" stop-color="#bca1ff" stop-opacity=".15"/><stop offset="1" stop-color="#ff9e8c" stop-opacity=".55"/></linearGradient></defs>
    <circle cx="350" cy="275" r="238" fill="url(#atlas-nebula)" stroke="none"/>
    <g class="atlas-orbits"><ellipse cx="350" cy="275" rx="290" ry="164" transform="rotate(-24 350 275)"/><ellipse cx="350" cy="275" rx="290" ry="164" transform="rotate(24 350 275)"/><circle cx="350" cy="275" r="221"/><circle cx="350" cy="275" r="145" stroke-dasharray="2 12"/></g>
    <g class="atlas-routes"><path data-atlas-route="tech" d="M350 275Q215 275 154 137"/><path data-atlas-route="culture" d="M350 275Q481 260 548 153"/><path data-atlas-route="gaming" d="M350 275Q479 280 543 402"/><path data-atlas-route="sports" d="M350 275Q219 290 160 413"/></g>
    <g class="atlas-stars"><circle cx="96" cy="279" r="2"/><circle cx="265" cy="76" r="2.5"/><circle cx="410" cy="72" r="2"/><circle cx="610" cy="290" r="3"/><circle cx="389" cy="476" r="2"/><circle cx="79" cy="388" r="1.5"/><circle cx="604" cy="99" r="1.5"/><circle cx="241" cy="459" r="2"/><path d="M88 85v10m-5-5h10M608 438v10m-5-5h10M463 325v8m-4-4h8"/></g>
    <path class="atlas-chart-trim" d="M35 62V34h36m558 0h36v28M35 488v28h36m558 0h36v-28M350 24v12m0 478v12M24 275h12m628 0h12"/>
   </svg>
   <div class="atlas-core" aria-hidden="true"><div class="atlas-core-ring"></div><div class="atlas-core-inner"><span class="atlas-core-name">Tech</span><span class="atlas-core-count"></span></div></div>
   <?php $atlasNodeIndex=0;foreach(array_slice($atlasLabels,0,4,true) as $atlasCategory=>$atlasLabel): ?>
   <button type="button" class="atlas-node atlas-node-<?= ++$atlasNodeIndex ?>" data-atlas-select="<?= e($atlasCategory) ?>" aria-pressed="false" aria-controls="atlas-events" aria-label="Explore <?= e($atlasLabel) ?>: <?= count($atlasGroups[$atlasCategory]) ?> <?= count($atlasGroups[$atlasCategory])===1?'event':'events' ?>" hidden><span class="atlas-node-orb" aria-hidden="true"><span class="atlas-node-count"><?= count($atlasGroups[$atlasCategory]) ?></span></span><span class="atlas-node-label"><?= e($atlasLabel) ?></span></button>
   <?php endforeach; ?>
  </div>
  <?php if(count($atlasLabels)>4): ?>
  <div class="atlas-extra-nodes" role="group" aria-label="More event categories">
   <?php foreach(array_slice($atlasLabels,4,null,true) as $atlasCategory=>$atlasLabel): ?>
   <button type="button" class="atlas-node atlas-node-extra" data-atlas-select="<?= e($atlasCategory) ?>" aria-pressed="false" aria-controls="atlas-events" aria-label="Explore <?= e($atlasLabel) ?>: <?= count($atlasGroups[$atlasCategory]) ?> <?= count($atlasGroups[$atlasCategory])===1?'event':'events' ?>" hidden><span class="atlas-node-orb" aria-hidden="true"><span class="atlas-node-count"><?= count($atlasGroups[$atlasCategory]) ?></span></span><span class="atlas-node-label"><?= e($atlasLabel) ?></span></button>
   <?php endforeach; ?>
  </div>
  <?php endif; ?>
  </div>
  <div class="atlas-events" id="atlas-events">
   <?php foreach($atlasLabels as $atlasCategory=>$atlasLabel): ?>
   <div class="atlas-world" data-atlas-world="<?= e($atlasCategory) ?>" data-atlas-label="<?= e($atlasLabel) ?>" data-atlas-count="<?= count($atlasGroups[$atlasCategory]) ?>">
    <h3><?= e($atlasLabel) ?> experiences<span>.</span></h3>
    <?php foreach($atlasGroups[$atlasCategory] as $atlasSlug=>$atlasEvent): ?>
    <a class="atlas-event" href="/event.php?name=<?= e(rawurlencode($atlasSlug)) ?>"><span class="atlas-event-copy"><strong><?= e($atlasEvent['title']) ?></strong><?php if(!empty($atlasEvent['short'])): ?><span><?= e($atlasEvent['short']) ?></span><?php endif; ?><span class="atlas-event-phase"><?= e(cms_phase_label($atlasEvent)) ?></span></span></a>
    <?php endforeach; ?>
    <?php if(!$atlasGroups[$atlasCategory]): ?><p class="atlas-empty">The <?= e(strtolower($atlasLabel)) ?> programme will be announced here.</p><?php endif; ?>
   </div>
   <?php endforeach; ?>
  </div>
 </div>
 <p class="atlas-status" role="status" aria-live="polite" aria-atomic="true"></p>
</section>
