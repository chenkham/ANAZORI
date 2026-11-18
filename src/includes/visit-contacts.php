<?php if(setting('contact_person1')||setting('contact_person2')): ?>
<div class="visit-contacts" aria-label="Contact the organising team">
 <?php foreach([1,2] as $number):$name=setting('contact_person'.$number);if(!$name)continue;$email=setting('contact_email'.$number);$phone=setting('contact_phone'.$number); ?>
 <div class="visit-contact"><strong><?= e($name) ?></strong><?php if($phone): ?><a href="tel:<?= e(preg_replace('/[^0-9+]/','',$phone)) ?>"><?= e($phone) ?></a><?php endif;if($email): ?><a href="mailto:<?= e($email) ?>"><?= e($email) ?></a><?php endif; ?></div>
 <?php endforeach; ?>
</div>
<?php endif; ?>
