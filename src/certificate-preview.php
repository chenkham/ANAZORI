<?php
require_once __DIR__.'/includes/commerce.php';
set_security_headers();
header('Cache-Control: private, no-store');
$staff=cms_require_user();
$certificateRowId=filter_input(INPUT_GET,'certificate_row_id',FILTER_VALIDATE_INT)?:0;
$eventId=filter_input(INPUT_GET,'event_id',FILTER_VALIDATE_INT)?:0;
$orderId=filter_input(INPUT_GET,'order_id',FILTER_VALIDATE_INT)?:0;
$teamSet=($_GET['team_certificates']??'')==='1';
$issued=$certificateRowId>0;
if($teamSet){
    if($eventId<1||$orderId<1){http_response_code(404);exit('Certificate preview unavailable.');}
} elseif($issued){
    $query=cms_db()->prepare("SELECT c.*,e.title event_title,e.slug event_slug,o.snapshot order_snapshot,o.answers order_answers FROM az_certificates c JOIN cms_content e ON e.id=c.event_id AND e.type='event' LEFT JOIN az_orders o ON o.id=c.order_id WHERE c.id=?");
    $query->execute([$certificateRowId]);
    $certificate=$query->fetch();
    if(!$certificate){http_response_code(404);exit('Certificate preview unavailable.');}
    $certificate=az_certificate_apply_registered_team_name($certificate);
    $eventId=(int)$certificate['event_id'];
} elseif($eventId<1||$orderId<1){http_response_code(404);exit('Certificate preview unavailable.');}
try {
    $staff=az_certificate_require_manage($staff,$eventId);
    if(!$issued){$order=st_require_order($staff,$orderId);}
} catch(Throwable) {
    http_response_code(404);
    exit('Certificate preview unavailable.');
}

if($teamSet){
    if((int)$order['event_id']!==$eventId||$order['state']!=='PAID'||$order['environment']!=='live'){http_response_code(404);exit('Certificate preview unavailable.');}
    $teamName=az_certificate_order_team_name($order);
    if($teamName===''){http_response_code(404);exit('Certificate preview unavailable.');}
    $ticket=cms_db()->prepare("SELECT id FROM az_tickets WHERE order_id=? AND status IN ('VALID','USED') LIMIT 1");
    $ticket->execute([$orderId]);
    if(!$ticket->fetchColumn()){http_response_code(404);exit('Certificate preview unavailable.');}
    $query=cms_db()->prepare("SELECT c.*,e.title event_title,e.slug event_slug,o.snapshot order_snapshot,o.answers order_answers FROM az_certificates c
        JOIN cms_content e ON e.id=c.event_id AND e.type='event'
        JOIN az_orders o ON o.id=c.order_id AND o.state='PAID' AND o.environment='live'
        WHERE c.event_id=? AND c.status='ISSUED' AND EXISTS (SELECT 1 FROM az_tickets t WHERE t.order_id=o.id AND t.status IN ('VALID','USED'))
        ORDER BY c.recipient_name,c.id");
    $query->execute([$eventId]);
    $teamKey=az_certificate_team_key($teamName);
    $teamCertificates=array_values(array_filter(array_map('az_certificate_apply_registered_team_name',$query->fetchAll()),static fn($certificate)=>az_certificate_team_key((string)$certificate['team_name'])===$teamKey));
    if($teamCertificates&&($_GET['download']??'')==='pdf')az_certificate_stream_team_pdf($teamCertificates,(string)$teamCertificates[0]['team_name']);
} elseif($issued){
    $award=az_certificate_award($eventId,(string)$certificate['team_name']);
    $qr=az_certificate_qr(az_decrypt($certificate['token_enc']));
    if(($_GET['download']??'')==='pdf')az_certificate_stream_pdf($certificate,$award,$qr);
} else {
    if((int)$order['event_id']!==$eventId||$order['state']!=='PAID'||$order['environment']!=='live'){
        http_response_code(404);exit('Certificate preview unavailable.');
    }
    $ticket=cms_db()->prepare("SELECT id FROM az_tickets WHERE order_id=? AND status IN ('VALID','USED') LIMIT 1");
    $ticket->execute([$orderId]);
    if(!$ticket->fetchColumn()){http_response_code(404);exit('Certificate preview unavailable.');}
    $account=cms_db()->prepare('SELECT id,email,name,active FROM az_participants WHERE id=?');
    $account->execute([(int)$order['participant_id']]);
    $account=$account->fetch();
    if(!$account||!(int)$account['active']){http_response_code(404);exit('Certificate preview unavailable.');}
    $event=cms_record($eventId);
    if(!$event||$event['type']!=='event'){http_response_code(404);exit('Certificate preview unavailable.');}
    $snapshot=json_decode((string)$order['snapshot'],true)?:[];
    $team=az_certificate_order_team_name($order);
    $certificate=[
        'certificate_id'=>'PREVIEW ONLY · NOT ISSUED',
        'event_id'=>$eventId,
        'event_title'=>$event['title'],
        'event_slug'=>$event['slug'],
        'recipient_email'=>(string)$account['email'],
        'recipient_name'=>(string)$account['name']!==''?(string)$account['name']:(string)($snapshot['name']??''),
        'team_name'=>$team,
    ];
    $award=az_certificate_award($eventId,$team);
    if(($_GET['download']??'')==='pdf')az_certificate_download_preview($certificate,$award);
    $qr=az_certificate_qr('',true);
}
$staffCertificatePreview = !$teamSet && $issued && az_certificate_is_staff_certificate($certificate);
$pageTitle='Certificate preview · Anazori';
$activePage='certificate';
require __DIR__.'/includes/header.php';
?>
<?php if($teamSet): ?>
<section class="section-pad certificate-page">
 <div class="certificate-page-heading"><div><p class="eyebrow">ISSUED TEAM CERTIFICATES · <?= count($teamCertificates) ?> MEMBER<?= count($teamCertificates)===1?'':'S' ?></p><h1><?= e($teamName) ?></h1><p>Each page shows one member’s certificate, award place, and verification QR.</p></div><div class="certificate-page-actions"><?php if($teamCertificates): ?><a class="button button-orange" href="/certificate-preview.php?event_id=<?= $eventId ?>&amp;order_id=<?= $orderId ?>&amp;team_certificates=1&amp;download=pdf">Download all as one PDF ↓</a><?php endif; ?><a class="text-link certificate-back-link" href="/admin.php?section=certificates&amp;event_id=<?= $eventId ?>">Back to results &amp; certificates</a></div></div>
 <?php if(!$teamCertificates): ?><p class="certificate-note">No teammate certificates have been issued for this registration yet. Use “Issue certificates for team members” below this registration first.</p><?php else: ?>
  <p class="certificate-note">This is the issued certificate set. Saving podium results updates the displayed award place for every member of the matching team.</p>
  <?php foreach($teamCertificates as $teamCertificate): $teamAward=az_certificate_award($eventId,$teamCertificate['team_name']); $teamQr=az_certificate_qr(az_decrypt($teamCertificate['token_enc'])); ?>
   <article class="team-certificate-preview"><h2><?= e($teamCertificate['recipient_name']) ?> · <?= e($teamAward['label']) ?></h2><div class="certificate-preview"><?= az_certificate_markup($teamCertificate,$teamAward,$teamQr) ?></div></article>
  <?php endforeach; ?>
 <?php endif; ?>
</section>
<?php else: ?>
<section class="section-pad certificate-page">
 <div class="certificate-page-heading"><div><p class="eyebrow"><?= $issued?'ISSUED CERTIFICATE':'STAFF PREVIEW' ?> · <?= $staffCertificatePreview?'TEACHER COORDINATOR':e($award['status']) ?></p><h1><?= $staffCertificatePreview?'Teacher Coordinator certificate':($issued?'Issued certificate':'Certificate preview') ?></h1><p><?= e($certificate['recipient_name']) ?><?= $certificate['team_name']?' · '.e($certificate['team_name']):($staffCertificatePreview?' · Teacher Coordinator':' · '.e($award['label'])) ?></p></div><div class="certificate-page-actions"><a class="button button-orange" href="/certificate-preview.php?<?= $issued?'certificate_row_id='.(int)$certificateRowId:'event_id='.$eventId.'&amp;order_id='.$orderId ?>&amp;download=pdf"><?= $issued?'Download issued PDF':'Preview PDF' ?> ↓</a><a class="text-link certificate-back-link" href="/admin.php?section=certificates&amp;event_id=<?= $eventId ?>">Back to results &amp; certificates</a></div></div>
 <?php if($issued): ?><p class="certificate-note" style="padding:14px 18px;border:1px solid #bf83ed;border-radius:12px;background:#24152f;color:#f4e8ff"><strong>This is the issued certificate.</strong> Its QR code opens the public verification page. Viewing or downloading it does not change its status.</p>
 <?php else: ?><p class="certificate-note" style="padding:14px 18px;border:1px solid #bf83ed;border-radius:12px;background:#24152f;color:#f4e8ff"><strong>Preview only.</strong> This page has not issued or saved a certificate. Its QR code contains preview text and cannot verify as a real certificate. Issuing it from the Organizing Studio creates the participant’s dashboard certificate and valid verification QR.</p><?php endif; ?>
 <div class="certificate-preview"><?= az_certificate_markup($certificate,$award,$qr) ?></div>
</section>
<?php endif; ?>
<?php require __DIR__.'/includes/footer.php'; ?>
