<?php
// Original GrafxKid sprite frames; the entire scene stays in the hero divider.
$pixelCrew = [
 'gum' => ['idle'=>['gum-bot-idle',4,.8], 'walk'=>['gum-bot-walk',6,.6]],
 'geralt' => ['idle'=>['geralt-idle',2,1], 'pickup'=>['geralt-pickup',1,1], 'carry'=>['geralt-carry',3,.45], 'run'=>['geralt-run',3,.36], 'victory'=>['geralt-victory',1,1]],
 'j5' => ['idle'=>['j5-idle',5,1], 'run'=>['j5-run',3,.3], 'jump'=>['j5-jump',1,1], 'laugh'=>['j5-laugh',2,.5]],
];
?>
<div class="ticker energy-conduit<?= setting('show_characters','1')==='1'?' pixel-workshop':'' ?>" aria-hidden="true"<?= setting('show_characters','1')==='1'?' data-festival-scene':'' ?>>
 <?php if(setting('show_characters','1')==='1'): ?>
 <div class="pixel-workshop-stage">
  <div class="pixel-sky"><i></i><i></i><i></i><i></i><i></i></div>
  <span class="pixel-ground"></span>
  <span class="pixel-platform pixel-platform--left"></span>
  <span class="pixel-platform pixel-platform--right"></span>
  <span class="pixel-supply"><i class="pixel-cube pixel-source-cube"></i></span>
  <span class="pixel-socket"><i></i><i></i><i></i><b class="pixel-cube pixel-docked-cube"></b></span>
  <span class="pixel-signal pixel-signal--one"></span><span class="pixel-signal pixel-signal--two"></span><span class="pixel-signal pixel-signal--three"></span>
  <?php foreach($pixelCrew as $robot=>$poses): ?>
  <div class="pixel-route pixel-route--<?= $robot ?>"><div class="pixel-hop"><div class="pixel-body">
   <?php foreach($poses as $pose=>[$sheet,$frames,$duration]): ?>
   <span class="pixel-pose pixel-pose--<?= $pose ?>" style="--sprite-art:url('/assets/2026/pixel-character/<?= $sheet ?>.png');--frames:<?= $frames ?>;--frame-time:<?= $duration ?>s;--pose-window:pixel-<?= $robot ?>-<?= $pose ?>"></span>
   <?php endforeach; ?>
   <?php if($robot==='geralt'): ?><i class="pixel-cube pixel-carried-cube"></i><?php endif; ?>
  </div></div></div>
  <?php endforeach; ?>
 </div>
 <?php else: ?><span class="conduit-rail"></span><?php endif; ?>
</div>
