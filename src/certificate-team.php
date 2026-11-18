<?php
require_once __DIR__.'/includes/commerce.php';
set_security_headers();
header('Cache-Control: private, no-store');
$participant=az_require_participant();
$orderId=filter_input(INPUT_GET,'order_id',FILTER_VALIDATE_INT)?:0;
$certificates=$orderId>0?az_certificate_team_rows_for_participant($orderId,$participant):[];
if(!$certificates){http_response_code(404);exit('Team certificates unavailable.');}
$teamName=(string)$certificates[0]['team_name'];
if(($_GET['download']??'')==='pdf')az_certificate_stream_team_pdf($certificates,$teamName);
$activePage='certificate';
$pageTitle='Team certificates · Anazori';
require __DIR__.'/includes/header.php';
?>
<section class="section-pad certificate-page">
 <div class="certificate-page-heading"><div><p class="eyebrow">TEAM CERTIFICATES · <?= count($certificates) ?> MEMBER<?= count($certificates)===1?'':'S' ?></p><h1><?= e($teamName) ?></h1><p>Each team member has a separate certificate and verification QR.</p></div><div class="certificate-page-actions"><a class="button button-orange" href="/certificate-team.php?order_id=<?= $orderId ?>&amp;download=pdf">Download all as one PDF ↓</a><a class="text-link certificate-back-link" href="/dashboard.php">Back to My festival</a></div></div>
 <p class="certificate-note">The PDF contains one page per issued team member certificate. The QR on each page verifies that member’s name, team, and award status.</p>
 <?php foreach($certificates as $certificate): $award=az_certificate_award((int)$certificate['event_id'],$certificate['team_name']); $qr=az_certificate_qr(az_decrypt($certificate['token_enc'])); ?>
  <article class="team-certificate-preview"><h2><?= e($certificate['recipient_name']) ?> · <?= e($award['label']) ?></h2><div class="certificate-preview"><?= az_certificate_markup($certificate,$award,$qr) ?></div></article>
 <?php endforeach; ?>
</section>
<?php require __DIR__.'/includes/footer.php'; ?>
