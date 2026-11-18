<?php // The original folded poster, with live partner logos held by the festival mascot. ?>
<div class="sponsor-installation sponsor-poster-wall" data-festival-scene><div class="locker-seams" aria-hidden="true"><i></i><i></i><i></i></div><div class="sponsor-paper">
 <span class="paper-tape tape-top" aria-hidden="true"></span><span class="paper-tape tape-bottom" aria-hidden="true"></span>
 <div class="poster-masthead"><img src="<?= e(setting('logo')) ?>" width="48" height="48" alt=""><span>ANAZORI <?= e(festival_version()) ?><br>Culture × Technology</span><span>CCSA<br>DIBRUGARH UNIVERSITY</span></div>
 <h3><?= $partners?'Meet our<br>partners.':'Your brand.<br>Our next chapter.' ?></h3>
 <?php if($partners): ?>
 <div class="placard-rig sponsor-logo-holder">
  <div class="partner-placard"><div class="placard-partners"><?php foreach($partners as $partner):$f=$partner['fields'];$tag=$f['link']?'a':'div'; ?>
   <<?= $tag ?> class="placard-partner" <?= $tag==='a'?'href="'.e($f['link']).'" target="_blank" rel="noopener"':'' ?>><span class="placard-tier"><?= e($f['tier']?:'Festival partner') ?></span><span class="placard-logo"><?php if($f['image']): ?><img src="<?= e($f['image']) ?>"<?= az_image_attributes84($f['image'],'(max-width:700px) 40vw, 300px') ?> alt="<?= e($partner['title']) ?>" width="300" height="140" loading="lazy" decoding="async"><?php else: ?><strong><?= e($partner['title']) ?></strong><?php endif; ?></span><span class="placard-name"><?= e($partner['title']) ?><span aria-hidden="true">↗</span></span></<?= $tag ?>>
   <?php endforeach; ?></div></div>
  <img class="placard-mascot" src="/assets/2026/creative/placard-mascot.png"<?= az_image_attributes84('/assets/2026/creative/placard-mascot.png','230px') ?> width="1280" height="1280" alt="A cheerful green festival mascot holding the partner logos on a sign" loading="lazy" decoding="async">
 </div>
 <?php else: ?><p class="poster-invitation-copy">A place for brands that believe in fresh ideas, culture and the next generation.</p><a class="poster-partner-link" href="mailto:<?= e(setting('sponsor_email')) ?>">Be part of Anazori <span aria-hidden="true">+</span></a><?php endif; ?>
 <p class="poster-colophon">OLD ROOTS. NEW FREQUENCIES.</p>
</div></div>
