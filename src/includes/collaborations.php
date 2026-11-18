<?php $collaborators=cms_records('collaboration'); ?>
<?php if(setting('show_collaborations')==='1'): ?>
<section class="collaboration-section" id="collaborations" aria-labelledby="collaboration-heading">
 <div class="collaboration-heading"><div><span class="eyebrow"><?= e(setting('collaboration_label')) ?></span><h3 id="collaboration-heading"><?= e(setting('collaboration_heading')) ?></h3></div><p><?= cms_escape_lines(setting('collaboration_copy')) ?></p></div>
 <div class="collaboration-grid">
 <?php foreach($collaborators as $partner):$fields=$partner['fields']; ?>
 <article class="collaboration-card"><span class="collaboration-kind"><?= e($fields['tier']) ?></span><?php if($fields['image']): ?><img src="<?= e($fields['image']) ?>"<?= az_image_attributes84($fields['image'],'200px') ?> alt="<?= e($partner['title']) ?>" loading="lazy"><?php endif; ?><h4><?= e($partner['title']) ?></h4><?php if($fields['description']): ?><p><?= cms_escape_lines($fields['description']) ?></p><?php endif;if($fields['link']): ?><a class="text-link" href="<?= e($fields['link']) ?>" target="_blank" rel="noopener noreferrer">Visit <?= e($partner['title']) ?> <?= arrow_icon() ?></a><?php endif; ?></article>
 <?php endforeach; ?>
 </div>
 <?php if(!$collaborators): ?><a class="collaboration-invitation" href="mailto:<?= e(setting('sponsor_email')) ?>?subject=Anazori%20collaboration"><span>Make something together.</span><span>Partner with Anazori <?= arrow_icon() ?></span></a><?php endif; ?>
</section>
<?php endif; ?>
