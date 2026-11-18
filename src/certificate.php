<?php
require_once __DIR__.'/includes/commerce.php';
set_security_headers();
header('Cache-Control: private, no-store');
$participant=az_require_participant();
$id=is_string($_GET['id']??null)?trim($_GET['id']):'';
$certificate=az_certificate_lookup_for_participant($id,$participant);
if(!$certificate){http_response_code(404);exit('Certificate unavailable.');}
if(($_GET['download']??'')==='pdf')az_certificate_download($certificate);
$token=az_decrypt($certificate['token_enc']);
$qr=az_certificate_qr($token);
$award=az_certificate_award((int)$certificate['event_id'],$certificate['team_name']);
$activePage='certificate';$pageTitle='Your certificate · Anazori';
require __DIR__.'/includes/header.php';
?>
<section class="section-pad certificate-page">
 <div class="certificate-page-heading"><div><p class="eyebrow">GAME OF CODES · <?= e($award['status']) ?></p><h1>Your certificate</h1><p><?= e($certificate['recipient_name']) ?><?= $certificate['team_name']?' · '.e($certificate['team_name']):'' ?> · <?= e($award['label']) ?></p></div><div class="certificate-page-actions"><a class="button button-orange" href="/certificate.php?id=<?= rawurlencode($certificate['certificate_id']) ?>&amp;download=pdf">Download PDF ↓</a><a class="text-link certificate-back-link" href="/dashboard.php">Back to My festival</a></div></div>
 <p class="certificate-note">The QR code opens Anazori’s verification page. It shows the recipient, team, and certificate status.</p>
 <div class="certificate-preview"><?= az_certificate_markup($certificate,$award,$qr) ?></div>
</section>
<?php require __DIR__.'/includes/footer.php'; ?>
