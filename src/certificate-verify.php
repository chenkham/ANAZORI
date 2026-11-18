<?php
require_once __DIR__.'/includes/commerce.php';
set_security_headers();
header('Cache-Control: public, max-age=300');
header('X-Robots-Tag: noindex, nofollow');
$token=is_string($_GET['token']??null)?$_GET['token']:'';
$certificate=az_certificate_lookup_token($token);
$valid=$certificate&&$certificate['status']==='ISSUED';
$staffCertificate=$certificate&&az_certificate_is_staff_certificate($certificate);
$staffPerson=$staffCertificate?(az_certificate_staff_people()[az_certificate_staff_key_for_name((string)$certificate['recipient_name'])]??null):null;
$award=$certificate?az_certificate_award((int)$certificate['event_id'],$certificate['team_name']):['status'=>'','label'=>''];
$activePage='certificate-verify';$pageTitle='Certificate verification · Anazori';
require __DIR__.'/includes/header.php';
?>
<section class="section-pad certificate-verification">
 <article class="certificate-verification-card <?= $valid?'certificate-valid':'certificate-invalid' ?>">
  <p class="eyebrow">ANAZORI · CERTIFICATE CHECK</p>
  <h1><?= $valid?'Certificate verified':($certificate?'Certificate revoked':'Certificate not found') ?></h1>
  <?php if($certificate): ?>
   <p class="certificate-verification-status"><?= $valid?'This certificate is valid.':'This certificate is no longer valid.' ?></p>
   <dl><?php if($valid): ?><div><dt>Recipient</dt><dd><?= e($certificate['recipient_name']) ?></dd></div><?php if($staffCertificate): ?><div><dt>Certificate type</dt><dd>Teacher Coordinator</dd></div><?php elseif($certificate['team_name']): ?><div><dt>Team</dt><dd><?= e($certificate['team_name']) ?></dd></div><?php endif; ?><div><dt>Status</dt><dd><?= $staffCertificate?'Teacher Coordinator certificate':e($award['status'].($award['status']==='Winner'?' · '.$award['label']:'')) ?></dd></div><div><dt>Event</dt><dd><?= e($certificate['event_title']) ?></dd></div><div><dt>Certificate ID</dt><dd><?= e($certificate['certificate_id']) ?></dd></div><div><dt>Issued</dt><dd><?= e((new DateTimeImmutable($certificate['issued_at']))->setTimezone(new DateTimeZone('Asia/Kolkata'))->format('d M Y')) ?></dd></div><?php else: ?><div><dt>Certificate ID</dt><dd><?= e($certificate['certificate_id']) ?></dd></div><?php endif; ?></dl>
   <?php if($valid&&$staffPerson): ?><section class="certificate-staff-profiles"><h2>Official profiles</h2><div class="certificate-profile-links"><a href="<?= e($staffPerson['ccsdu_profile']) ?>" target="_blank" rel="noopener noreferrer">CCSA faculty profile ↗</a><a href="<?= e($staffPerson['university_profile']) ?>" target="_blank" rel="noopener noreferrer">Dibrugarh University profile ↗</a></div></section><?php endif; ?>
  <?php else: ?><p class="certificate-verification-status">This QR code does not match a certificate issued by Anazori.</p><?php endif; ?>
  <a class="text-link" href="/">Return to Anazori ›</a>
 </article>
</section>
<?php require __DIR__.'/includes/footer.php'; ?>
