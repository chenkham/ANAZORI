<?php
declare(strict_types=1);

function az_payment_destination(array $method,int $amount,string $reference=''): void {
    echo '<dl class="payment-destination payment-details"><div><dt>Method</dt><dd>'.e($method['label']).'</dd></div><div><dt>Account holder</dt><dd>'.e($method['recipient']).'</dd></div>';
    if($method['kind']==='upi')echo '<div><dt>UPI ID</dt><dd><code>'.e($method['upi']).'</code></dd></div>';
    if($method['kind']==='bank')foreach(['bank'=>'Bank','account'=>'Account number','ifsc'=>'IFSC'] as $key=>$label)echo '<div><dt>'.$label.'</dt><dd>'.e($method[$key]).'</dd></div>';
    echo '</dl>';
    if($method['instructions'])echo '<p>'.nl2br(e($method['instructions'])).'</p>';
    if($method['qr'])echo '<img class="payment-qr-image payment-qr" src="'.e($method['qr']).'" width="220" height="220" alt="Payment QR for '.e($method['recipient']).'">';
    if($method['kind']==='upi'){
        $uri='upi://pay?'.http_build_query(['pa'=>$method['upi'],'pn'=>$method['recipient'],'am'=>number_format($amount/100,2,'.',''),'cu'=>'INR','tn'=>$reference]);
        echo '<a class="text-link" href="'.e($uri).'">Open a UPI app ›</a>';
    }
}

function az_manual_review_fields(array $order,array $payment): void {
    $prefix='review-'.$order['id'];
    echo '<input type="hidden" name="revision" value="'.(int)$payment['revision'].'">';
    echo '<label class="field" for="'.$prefix.'-amount"><span>Amount received (₹)</span><input id="'.$prefix.'-amount" name="received_amount" type="number" step="0.01" min="0.01" value="'.number_format($order['amount']/100,2,'.','').'"></label>';
    echo '<label class="check-field"><input type="checkbox" name="bank_confirmed" value="yes"><span>I checked this reference and amount in the receiving account.</span></label>';
    echo '<label class="field" for="'.$prefix.'-note"><span>Review note (required when requesting correction)</span><textarea id="'.$prefix.'-note" name="note" maxlength="1000" rows="2"></textarea></label>';
    echo '<div class="form-actions"><button class="primary-button" name="decision" value="approve" type="submit">Confirm payment &amp; release ticket</button>';
    if($order['state']==='PENDING_REVIEW')echo '<button class="quiet-button" name="decision" value="reject" type="submit">Request correction</button>';
    echo '</div>';
}
