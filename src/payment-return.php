<?php
require_once __DIR__.'/includes/commerce.php';$u=az_require_participant();header('Cache-Control: no-store');
$order=az_order_public(is_string($_GET['order']??null)?$_GET['order']:'');
if(!$order||(int)$order['participant_id']!==(int)$u['id']){http_response_code(404);require __DIR__.'/includes/header.php';echo '<section class="section account-section"><div class="account-card"><h1>Registration unavailable.</h1><a class="button" href="/dashboard.php">My festival</a></div></section>';require __DIR__.'/includes/footer.php';exit;}
$pageTitle='Payment confirmation · Anazori V16.0';require __DIR__.'/includes/header.php';
?>
<section class="section account-section"><div class="account-card"><h1>Confirming your registration.</h1><p>Checking your payment with PhonePe. Your pass will appear in My festival once payment is confirmed.</p><form id="payment-return" data-order="<?= e($order['public_id']) ?>"><?= csrf_field() ?><p id="checkout-message" class="notice" role="status" aria-live="polite">Verifying payment…</p></form><a class="button button-orange" href="/dashboard.php">My festival ›</a></div></section>
<script type="module" src="/assets/2026/checkout.js?v=2026.18"></script>
<?php require __DIR__.'/includes/footer.php'; ?>
