<?php
require_once __DIR__.'/includes/commerce.php';
$participant=az_require_participant(true);set_security_headers();header('Cache-Control: no-store');
$public=is_string($_GET['order']??null)?$_GET['order']:'';$order=az_order_public($public);
if(!$order||(int)$order['participant_id']!==(int)$participant['id']||$order['provider']!=='manual'){http_response_code(404);exit('Registration unavailable.');}
$payment=az_manual_payment((int)$order['id']);$method=json_decode($payment['method_snapshot'],true);$snapshot=json_decode($order['snapshot'],true);
$flash=$_SESSION['payment_proof_flash']??null;unset($_SESSION['payment_proof_flash']);
$activePage='account';$pageTitle='Payment screenshot · Anazori';require __DIR__.'/includes/header.php';
?>
<section class="payment-proof-shell section-pad">
 <a class="text-link" href="/dashboard.php">← My registrations</a>
 <h1><?= e($snapshot['title']) ?></h1>
 <p><?= e((!empty($snapshot['game'])?$snapshot['game'].' · ':'').$snapshot['type']) ?> · <?= (int)$order['quantity'] ?> pass<?= (int)$order['quantity']===1?'':'es' ?> · <strong><?= e(az_money((int)$order['amount'])) ?></strong></p>
 <p class="payment-badge"><?= e(az_payment_state_label($order['state'])) ?></p>
 <?php if($flash): ?><p class="account-notice <?= $flash['error']?'error':'' ?>" role="status"><?= e($flash['message']) ?></p><?php endif; ?>
 <?php if($order['state']==='REJECTED'): ?><p class="account-notice">Coordinator note: <?= e($payment['review_note']) ?></p><?php endif; ?>
 <div class="payment-proof-layout">
  <div>
   <h2>Payment details</h2>
   <?php az_payment_destination($method,(int)$order['amount'],$public); ?>
   <p class="account-help">Pay the exact total to the account above. Your screenshot and transaction reference will be checked against the received payment before tickets are released.</p>
   <?php if($order['state']==='AWAITING_PROOF'): ?><p class="account-help"><?= (int)$order['expires_at']>time()?'Your places are held until '.e((new DateTimeImmutable('@'.$order['expires_at']))->setTimezone(new DateTimeZone('Asia/Kolkata'))->format('j M, g:i a')).' IST.':'The place reservation has expired. Contact the coordinator before paying; ticket availability will be checked during review.' ?></p><?php endif; ?>
  </div>
  <div>
  <?php if(in_array($order['state'],['AWAITING_PROOF','REJECTED'],true)): ?>
   <h2>Attach your screenshot</h2>
   <form class="account-form payment-proof-form" method="post" action="/api/payment-proof.php" enctype="multipart/form-data">
    <?= csrf_field() ?><input type="hidden" name="order" value="<?= e($public) ?>"><input type="hidden" name="revision" value="<?= (int)$payment['revision'] ?>">
    <label for="payment-reference">Transaction reference / UTR<input id="payment-reference" name="reference" value="<?= e($payment['reference']??'') ?>" required minlength="6" maxlength="100"></label>
    <label for="payment-date">Payment date<input id="payment-date" name="paid_on" type="date" value="<?= e($payment['paid_on']?:(new DateTimeImmutable('today',new DateTimeZone('Asia/Kolkata')))->format('Y-m-d')) ?>" max="<?= e((new DateTimeImmutable('now',new DateTimeZone('Asia/Kolkata')))->format('Y-m-d')) ?>" required></label>
    <label for="payment-screenshot">Payment screenshot<input id="payment-screenshot" name="proof" type="file" accept="image/jpeg,image/png,image/webp" required><small>JPG, PNG or WebP, up to 5 MB. Visible only to you and authorised event staff.</small></label>
    <button class="button button-orange" type="submit">Submit for review ›</button>
   </form>
  <?php else: ?>
   <h2><?= $order['state']==='PAID'?'Your tickets are ready':'Registration saved' ?></h2>
   <p><?= $order['state']==='PENDING_REVIEW'?'Your payment is awaiting coordinator review. You do not need to pay again.':e(az_payment_state_label($order['state'])) ?></p>
   <a class="text-link" href="/dashboard.php">View my registrations ›</a>
  <?php endif; ?>
  <?php if($payment['proof_id']): ?><details class="payment-proof-history"><summary>Submitted screenshot and reference</summary><p><?= e($payment['reference']) ?> · <?= e($payment['paid_on']) ?></p><a href="/payment-proof-file.php?id=<?= (int)$payment['proof_id'] ?>" target="_blank" rel="noopener">Open screenshot ›</a></details><?php endif; ?>
  </div>
 </div>
</section>
<?php require __DIR__.'/includes/footer.php'; ?>
