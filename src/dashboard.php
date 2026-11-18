<?php
require_once __DIR__.'/includes/commerce.php';
$u=az_require_participant();
header('Cache-Control: no-store');
if($_SERVER['REQUEST_METHOD']==='POST'){
    az_csrf();
    if(($_POST['action']??'')==='logout'){
        az_auth_event('logout',($_SESSION['participant_method']??'')==='google'?'google':'email_password',$u);az_remember_revoke102((int)$u['id']);az_participant_clear102();
        session_regenerate_id(true);header('Location: /account.php',true,303);exit;
    }
}
$page=max(1,min(100000,(int)($_GET['p']??1)));
$query=cms_db()->prepare('SELECT * FROM az_orders WHERE participant_id=? ORDER BY id DESC LIMIT 21 OFFSET '.(($page-1)*20));
$query->execute([$u['id']]);$orders=$query->fetchAll();
$query=cms_db()->prepare("SELECT c.*,e.title event_title,team_order.participant_id team_order_owner_id,team_order.snapshot order_snapshot,team_order.answers order_answers FROM az_certificates c JOIN cms_content e ON e.id=c.event_id AND e.type='event'
 LEFT JOIN az_orders team_order ON team_order.id=c.order_id
 WHERE c.status='ISSUED' AND (c.participant_id=? OR (c.team_name<>'' AND EXISTS (
   SELECT 1 FROM az_orders team_order WHERE team_order.id=c.order_id AND team_order.participant_id=?
 ))) ORDER BY c.issued_at DESC,c.id DESC");
$query->execute([(int)$u['id'],(int)$u['id']]);$certificates=array_map('az_certificate_apply_registered_team_name',$query->fetchAll());
$teamCertificateGroups=[];foreach($certificates as $certificate)if($certificate['team_name']!==''&&(int)$certificate['team_order_owner_id']===(int)$u['id']){$key=(int)$certificate['order_id'];$teamCertificateGroups[$key]['team_name']=$certificate['team_name'];$teamCertificateGroups[$key]['event_title']=$certificate['event_title'];$teamCertificateGroups[$key]['certificates'][]=$certificate;}
$query=cms_db()->prepare("SELECT c.title,c.slug,d.event_id,d.game_id,d.updated_at FROM az_checkout_drafts d JOIN cms_content c ON c.id=d.event_id WHERE d.participant_id=? AND d.context_id<=0 AND c.status='PUBLISHED' ORDER BY d.updated_at DESC LIMIT 100");
$query->execute([$u['id']]);$savedDrafts=array_values(array_filter($query->fetchAll(),fn($draft)=>!az_existing_event_order((int)$u['id'],(int)$draft['event_id'],$draft['game_id'])));
$activePage='account';$pageTitle='My festival · Anazori';require __DIR__.'/includes/header.php';
?>
<section class="participant-dashboard section-pad clean-dashboard">
 <div class="dashboard-heading"><div><h1>Hey, <?= e(explode(' ',$u['name'])[0]) ?>.</h1><p>Your registrations and entry passes.</p></div><a class="text-link" href="/profile.php">Edit profile ›</a><form method="post"><?= csrf_field() ?><input type="hidden" name="action" value="logout"><button class="text-link" type="submit">Sign out ›</button></form></div>
 <?php if(!$u['email_verified']): ?><p class="account-notice">Verify your email to register. <a href="/verify-email.php">Verify email ›</a></p><?php endif; ?>
 <?php if($certificates): ?><section class="saved-registration-list"><h2>Your certificates</h2><p class="account-help">Your event certificates are verified by the QR code printed on each one.</p>
 <?php foreach($teamCertificateGroups as $orderId=>$group): ?><article class="registration-row"><div class="registration-heading"><div><h3><?= e($group['event_title']) ?> · <?= e($group['team_name']) ?></h3><p><?= count($group['certificates']) ?> issued member certificate<?= count($group['certificates'])===1?'':'s' ?> · download together as one PDF</p></div><div><a class="button button-purple" href="/certificate-team.php?order_id=<?= (int)$orderId ?>">View team certificates ›</a><br><a class="text-link" href="/certificate-team.php?order_id=<?= (int)$orderId ?>&amp;download=pdf">Download all PDF ↓</a></div></div></article><?php endforeach; ?>
 <?php foreach($certificates as $certificate): $award=az_certificate_award((int)$certificate['event_id'],$certificate['team_name']); ?><article class="registration-row"><div class="registration-heading"><div><h3><?= e($certificate['event_title']) ?> · <?= e($award['label']) ?></h3><p><?= e($certificate['recipient_name']) ?><?= $certificate['team_name']?' · '.e($certificate['team_name']):'' ?> · <?= e($award['status']) ?></p></div><a class="button button-purple" href="/certificate.php?id=<?= rawurlencode($certificate['certificate_id']) ?>">View certificate ›</a></div></article><?php endforeach; ?></section><?php endif; ?>
 <?php if($savedDrafts): ?><section class="saved-registration-list"><h2>Continue registration</h2><p class="account-help">Your details and completed uploads are saved to your account. These forms have not been submitted yet.</p><?php foreach($savedDrafts as $draft): ?><article class="registration-row"><div class="registration-heading"><div><h3><?= e($draft['title'].($draft['game_id']?' · '.ucwords(str_replace('-',' ',$draft['game_id'])):'')) ?></h3><p class="account-help">Progress saved <?= e(az_record_date_label($draft['updated_at'])) ?></p></div><a class="button button-purple" href="/checkout.php?event=<?= e($draft['slug']) ?>&amp;game=<?= e($draft['game_id']) ?>">Continue ›</a></div></article><?php endforeach; ?></section><?php endif; ?>
 <?php if(!$orders&&!$savedDrafts): ?><p class="dashboard-empty">Your next story starts here.</p><?php endif; ?>
 <div class="registration-list">
 <?php foreach(array_slice($orders,0,20) as $order):
    $snapshot=json_decode($order['snapshot'],true)?:[];$payment=az_manual_payment((int)$order['id']);
    $formResponse=$order['provider']==='form'?az_form_response((int)$order['id']):null;$formSettings=$formResponse?json_decode($formResponse['settings_json'],true):[];
    $query=cms_db()->prepare('SELECT t.*,b.reason FROM az_tickets t LEFT JOIN az_ticket_blocks b ON b.ticket_id=t.id WHERE t.order_id=? ORDER BY t.id');$query->execute([$order['id']]);$tickets=$query->fetchAll();
 ?>
  <article class="registration-row">
   <div class="registration-heading"><div><h2><?= e($snapshot['title']??$order['event_slug']) ?></h2><p><?= e((!empty($snapshot['game'])?$snapshot['game'].' · ':'').$snapshot['type']??'Registration') ?> · <?= (int)$order['quantity'] ?> pass<?= $order['quantity']>1?'es':'' ?></p></div><span class="payment-badge state-<?= e(strtolower($order['state'])) ?>"><?= e(az_payment_state_label($order['state'])) ?></span></div>
   <?php if($order['state']==='PENDING_REVIEW'): ?><p class="account-help">Your screenshot is with the event coordinator. Your ticket will appear after they confirm the payment.</p><?php endif; ?>
   <?php if($formResponse): ?>
    <?php if($order['state']==='FORM_PENDING'): ?><p class="account-help"><?= e($formSettings['confirmation']??'Your response is awaiting coordinator approval.') ?></p><?php endif; ?>
    <?php if($formResponse['review_note']): ?><p class="native-review-note"><?= nl2br(e($formResponse['review_note'])) ?></p><?php endif; ?>
    <?php if($order['state']==='FORM_CORRECTION'||($order['state']==='FORM_PENDING'&&!empty($formSettings['allow_edit']))): ?><a class="text-link" href="/checkout.php?event=<?= e($order['event_slug']) ?>&order=<?= e($order['public_id']) ?>"><?= $order['state']==='FORM_CORRECTION'?'Correct and resubmit response':'Edit submitted response' ?> ›</a><?php endif; ?>
    <?php if(!empty($formSettings['show_score'])&&$formResponse['max_score']): ?><p class="account-help">Quiz score: <?= (int)$formResponse['score'] ?> / <?= (int)$formResponse['max_score'] ?></p><?php endif; ?>
   <?php endif; ?>
   <?php if($order['state']==='PERFORMER_PENDING'): ?><p class="account-help">Your free performer application is saved. Your ticket will appear here once the Cultural Night coordinators confirm your performance.</p><?php elseif($order['state']==='PERFORMER_DECLINED'): ?><p class="account-help">Your performance was not selected. Contact the Cultural Night coordinators for details.</p><?php endif; ?>
   <?php if($order['state']==='PAID_REVIEW'): ?><p class="account-notice">Your payment is confirmed. The coordinator is resolving ticket availability. Contact <?= e(setting('email')) ?> with reference <?= e($order['public_id']) ?>.</p><?php endif; ?>
   <?php if($payment&&in_array($order['state'],['AWAITING_PROOF','REJECTED'],true)): ?>
    <?php if($payment['review_note']): ?><p class="account-notice"><?= e($payment['review_note']) ?></p><?php endif; ?>
    <a class="text-link" href="/payment-proof.php?order=<?= e($order['public_id']) ?>"><?= $order['state']==='REJECTED'?'Correct payment screenshot':'Payment details & upload screenshot' ?> ›</a>
   <?php endif; ?>
   <?php foreach($tickets as $ticket): ?><div class="ticket-row"><a href="/ticket.php?id=<?= e($ticket['ticket_id']) ?>" data-ticket-reveal><span><strong><?= e($ticket['ticket_id']) ?></strong><small><?= e($ticket['status']) ?> · View QR & download</small></span></a><?php if($ticket['status']==='BLOCKED'): ?><p class="account-notice">Entry is suspended: <?= e($ticket['reason']??'Contact the event coordinator.') ?></p><?php endif; ?></div><?php endforeach; ?>
   <details class="registration-details"><summary>Registration details</summary><dl class="payment-details"><div><dt>Reference</dt><dd><?= e($order['public_id']) ?></dd></div><div><dt>Amount</dt><dd><?= $order['amount']?e(az_money((int)$order['amount'])):'Free registration' ?></dd></div><div><dt>Venue</dt><dd><?= e($snapshot['venue']??'To be announced') ?></dd></div><div><dt>Event date</dt><dd><?= !empty($snapshot['starts_at'])?e(cms_date_label($snapshot['starts_at'])):'Dates coming soon' ?></dd></div><?php foreach(json_decode($order['answers'],true)?:[] as $label=>$answer): ?><div><dt><?= e($label) ?></dt><dd><?= e((string)$answer) ?></dd></div><?php endforeach; ?></dl>
    <?php if($formResponse):foreach(az_registration_files((int)$order['id']) as $file): ?><p><a class="text-link" href="/registration-file.php?id=<?= (int)$file['id'] ?>" target="_blank" rel="noopener"><?= e($file['label'].' — '.$file['original_name']) ?> ↗</a></p><?php endforeach;endif; ?>
    <?php if($payment&&$payment['proof_id']): ?><p><a class="text-link" href="/payment-proof-file.php?id=<?= (int)$payment['proof_id'] ?>" target="_blank" rel="noopener">Submitted screenshot ›</a> · <?= e($payment['reference']) ?></p><?php endif; ?>
    <?php $query=cms_db()->prepare('SELECT COALESCE(SUM(amount),0) FROM az_refunds WHERE order_id=?');$query->execute([$order['id']]);$refund=(int)$query->fetchColumn();if($refund): ?><p>Refund recorded: <?= e(az_money($refund)) ?></p><?php endif; ?>
   </details>
  </article>
 <?php endforeach; ?>
 </div>
 <nav class="registration-pagination" aria-label="Registration pages"><?php if($page>1): ?><a class="text-link" href="/dashboard.php?p=<?= $page-1 ?>">Previous</a><?php endif;if(count($orders)>20): ?><a class="text-link" href="/dashboard.php?p=<?= $page+1 ?>">Next</a><?php endif; ?></nav>
 <a class="text-link" href="/events.php">Explore events ›</a>
</section>
<?php require __DIR__.'/includes/footer.php'; ?>
