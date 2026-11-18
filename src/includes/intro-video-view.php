<?php $introVideo=intro_video_config(); ?>
<div class="connection-art video-stage <?= $introVideo['has_video']?'has-video':'is-blank' ?>" id="connection-sculpture" role="region" aria-label="Festival video presentation">
 <span class="arcane-frame" aria-hidden="true"><i></i><i></i><i></i><i></i></span>
 <?php if($introVideo['has_video']): ?>
 <div class="intro-video-wrapper">
  <?php if($introVideo['is_embed']): ?><iframe class="intro-video-iframe" src="<?= e($introVideo['embed_url']) ?>" title="Anazori festival video" loading="lazy" allow="autoplay; encrypted-media; picture-in-picture; fullscreen" allowfullscreen referrerpolicy="strict-origin-when-cross-origin"></iframe>
  <?php else: ?><video id="intro-video" class="intro-video-player" playsinline <?= $introVideo['controls']?'controls':'' ?> <?= $introVideo['loop']?'loop':'' ?> <?= $introVideo['autoplay']?'muted data-autoplay="1"':'' ?> preload="none" <?= $introVideo['poster']?'poster="'.e($introVideo['poster']).'"':'' ?>><source src="<?= e($introVideo['src']) ?>" type="video/mp4">Your browser does not support this video. <a href="<?= e($introVideo['src']) ?>">Open the festival film</a>.</video><?php endif; ?>
 </div>
 <?php else: ?>
 <div class="intro-video-blank"><div class="film-placeholder-art" aria-hidden="true"><span class="film-placeholder-play"><svg viewBox="0 0 24 24"><path d="M8 4v16l12-8Z"/></svg></span></div><span class="film-placeholder-label">Official film coming soon</span></div>
 <?php endif; ?>
</div>
