<?php
require_once __DIR__.'/includes/commerce.php';
$slug=is_string($_GET['event']??null)?$_GET['event']:'';$event=az_event($slug);
if($event&&az_participation_mode($event)!=='registration'){header('Location: /event.php?name='.rawurlencode($slug).'#contribute',true,303);exit;}
// External registrations and game selection are public; existing response edits stay in Studio’s native workflow.
$editing=is_string($_GET['order']??null)&&$_GET['order']!=='';
if($event&&!$editing&&az_has_external_registration97($event['fields'])){
    $requested=is_string($_GET['game']??null)?$_GET['game']:'';
    $nativeGame=$requested!==''&&in_array($requested,array_column(az_event_games($event['fields']),'id'),true)&&az_external_registration_url97($event['fields'],$requested)==='';
    if(!$nativeGame){header('Location: /register.php?event='.rawurlencode($event['slug']).($requested!==''?'&game='.rawurlencode($requested):''),true,302);exit;}
}
$participant=az_require_participant(true);set_security_headers();header('Cache-Control: no-store');
$editOrder=null;$editResponse=null;$formValues=[];$formUploads=[];$existingOrder=null;$draft=null;$draftState=[];$gameId='';$teamName='';$typeId='';
$fields=$event['fields']??[];$games=$event?az_event_games($fields):[];
if(is_string($_GET['order']??null)&&$_GET['order']!==''){
    $editOrder=az_order_public($_GET['order']);$editResponse=$editOrder?az_form_response((int)$editOrder['id']):null;
    if(!$editOrder||!$editResponse||(int)$editOrder['participant_id']!==(int)$participant['id']||!$event||(int)$editOrder['event_id']!==(int)$event['id']){http_response_code(404);exit('Response unavailable.');}
    $editSettings=json_decode($editResponse['settings_json'],true);
    if(!in_array($editOrder['state'],['FORM_PENDING','FORM_CORRECTION'],true)||($editOrder['state']!=='FORM_CORRECTION'&&empty($editSettings['allow_edit']))){http_response_code(403);exit('This response is locked.');}
    $fields['registration_form']=$editResponse['schema_json'];$fields['registration_settings']=$editResponse['settings_json'];
    $formValues=json_decode($editResponse['raw_answers'],true)?:[];$formUploads=az_registration_files((int)$editOrder['id']);
    $snapshot=json_decode($editOrder['snapshot'],true)?:[];$gameId=$snapshot['game_id']??'';$teamName=$snapshot['team_name']??'';$typeId=$editOrder['ticket_type'];
}else if($event){
    $requested=is_string($_GET['game']??null)?$_GET['game']:az_latest_draft_game81((int)$participant['id'],(int)$event['id']);
    if(in_array($requested,array_column($games,'id'),true))$gameId=$requested;
    $fields=az_game_fields81($fields,$gameId);
    $existingOrder=az_existing_event_order((int)$participant['id'],(int)$event['id'],$gameId);
}
if($event&&!$existingOrder&&(!$games||$gameId!=='')){
    $context=az_draft_context81($gameId,(int)($editOrder['id']??0));
    if(!$editOrder&&!empty($fields['form_workflow'])&&cms_event_phase($fields)==='open'&&array_filter(az_ticket_qrs85($fields),fn($field)=>!empty($field['payment_dynamic'])))az_payment_reference108($participant,$event,$fields,$gameId);
    $draft=az_checkout_draft((int)$participant['id'],(int)$event['id'],$context);
    if($draft&&hash_equals($draft['schema_hash'],az_draft_schema_hash($fields))){$formValues=json_decode($draft['answers_json'],true)?:[];$draftState=json_decode($draft['state_json']??'{}',true)?:[];$teamName=$draft['team_name']??$teamName;if(!$editOrder)$typeId=$draft['type_id'];}
    $draftFiles=az_checkout_draft_files((int)$participant['id'],(int)$event['id'],$context);
    if($draftFiles){$replaced=array_column($draftFiles,'field_id');$formUploads=[...array_filter($formUploads,fn($file)=>!in_array($file['field_id'],$replaced,true)),...$draftFiles];}
}
$options=$event?az_ticket_options81($fields,$gameId):[];
if(!$editOrder){$selected=az_registration_entry($fields,$gameId,$typeId);if(!$selected&&count($options)===1)$selected=$options[0];$typeId=$selected['id']??'';}
$checkoutError=$_SESSION['checkout_error']??null;unset($_SESSION['checkout_error']);
$activePage='account';$pageTitle='Register · Anazori';require __DIR__.'/includes/header.php';
?>
<section class="checkout-shell section-pad">
 <a class="text-link" href="/event.php?name=<?= e($slug) ?>">← Event details</a>
 <?php if($checkoutError): ?><p class="account-notice" role="alert"><?= e($checkoutError) ?></p><?php endif; ?>
 <?php if(!$event): ?><h1>Event unavailable.</h1><a class="text-link" href="/events.php">Explore events ›</a>
 <?php else: ?>
 <div class="checkout-grid checkout-layout"><div><h1><?= e($event['title']) ?></h1><p><?= e($fields['short']) ?></p><p><?= e($fields['venue']?:setting('venue')) ?><br><?= $fields['starts_at']?e(cms_date_label($fields['starts_at'])):'Dates coming soon' ?></p>
 <?php if($fields['rules_pdf']): ?><a class="text-link" href="<?= e($fields['rules_pdf']) ?>" target="_blank" rel="noopener">Read event rules ›</a><?php endif; ?>
 <p class="account-help"><?= $slug==='joystick'?'One registration per game from your account.':'One registration per event from your account.' ?> Each registration receives one ticket after the coordinator approves your response.</p>
 </div><div>
 <?php if($games&&!$editOrder): ?><form class="account-form game-picker81" method="get" action="/checkout.php" data-game-navigation><input type="hidden" name="event" value="<?= e($slug) ?>"><label for="checkout-game">Choose your game<select id="checkout-game" name="game" required><option value="">Choose a game</option><?php foreach($games as $game): ?><option value="<?= e($game['id']) ?>" <?= $gameId===$game['id']?'selected':'' ?>><?= e($game['label']) ?></option><?php endforeach; ?></select></label><button class="button button-dark" type="submit">Open game form ›</button><p class="account-help">Each game has its own form and saved progress.</p></form><?php endif; ?>
 <?php if($games&&$gameId===''&&!$editOrder): ?><p class="account-notice">Choose MLBB, BGMI or Free Fire to open its registration form.</p>
 <?php elseif($existingOrder): ?><p class="account-notice"><?= e(az_duplicate_registration_message($existingOrder)) ?></p><a class="button button-orange" href="/dashboard.php">View my registration & ticket ›</a>
 <?php elseif(!$editOrder&&(cms_event_phase($fields)!=='open'||!az_form_settings($fields)['accepting'])): ?><h2>Registration is closed.</h2><p><?= cms_escape_lines($fields['registration_closed_message']) ?></p>
 <?php elseif(!$options&&!$editOrder): ?><h2>Ticket categories are coming soon.</h2><p>The event team will publish the available tickets here.</p>
 <?php else:
 $nativeForm=!empty($fields['form_workflow']);$methods=$nativeForm?[]:az_payment_methods($fields);
 $nonce=bin2hex(random_bytes(24));$_SESSION['checkout_nonces']=array_slice($_SESSION['checkout_nonces']??[],-20,null,true);$_SESSION['checkout_nonces'][$nonce]=true;
 $qrLinks=az_ticket_qrs85($fields);$entryMap=[];foreach($options as $option)$entryMap[$option['id']]=['price'=>(int)$option['price'],'label'=>$option['label'],'qr_ready'=>!$qrLinks||(int)$option['price']===0||isset($qrLinks[$option['id']])];
 if($editOrder)$entryMap[$typeId]=['price'=>(int)$editOrder['amount'],'label'=>$snapshot['type'],'qr_ready'=>true];
 $paymentReference=$editOrder?$editOrder['public_id']:((json_decode($draft['state_json']??'{}',true)?:[])['payment_reference']??'');
 foreach($entryMap as $id=>&$entry){$payment=$editOrder?($snapshot['ticket_payment']??[]):($qrLinks[$id]??[]);if(!empty($payment['payment_dynamic'])&&$entry['price']>0){$entry['qr_url']=az_payment_qr_url108($slug,$id,$gameId,$editOrder['public_id']??'');$entry['upi_url']=az_payment_uri108($payment['payment_upi'],$payment['payment_name']??'Anazori',(int)$entry['price'],$paymentReference);}}unset($entry);
 ?>
 <form id="checkout-form" class="account-form checkout-form" method="post" enctype="multipart/form-data" action="/api/checkout.php"
 data-payment-reference108="<?= e($paymentReference) ?>" data-submit-label="<?= e($fields['registration_button']) ?>" data-participant="<?= (int)$participant['id'] ?>" data-event-id="<?= (int)$event['id'] ?>" data-game="<?= e($gameId) ?>" data-draft-revision="<?= (int)($draft['revision']??0) ?>" data-draft-updated="<?= e($draft['updated_at']??'') ?>" data-schema-hash="<?= e(az_draft_schema_hash($fields)) ?>" data-entry-map="<?= e(json_encode($entryMap)) ?>">
 <?= csrf_field() ?><input type="hidden" name="event" value="<?= e($slug) ?>"><input type="hidden" name="nonce" value="<?= e($nonce) ?>"><input type="hidden" name="response_format" value="redirect"><input type="hidden" name="quantity" value="1"><input type="hidden" name="game" value="<?= e($gameId) ?>">
 <p class="account-notice" data-draft-error role="alert" hidden></p>
 <?php if($editOrder): ?><input type="hidden" name="edit_order" value="<?= (int)$editOrder['id'] ?>"><input type="hidden" name="form_revision" value="<?= (int)$editResponse['revision'] ?>"><?php if(($snapshot['registration_kind']??'')==='team'): ?><input type="hidden" name="team_name" value="<?= e($teamName) ?>"><?php endif; ?><?php endif; ?>
 <fieldset class="registration-fields" data-category-form><legend><?= e($fields['registration_title']) ?></legend><?php if($fields['registration_intro']): ?><p class="account-help"><?= cms_escape_lines($fields['registration_intro']) ?></p><?php endif; ?><p class="account-help"><?= e($participant['name'].' · '.$participant['email']) ?></p><?php az_registration_form($fields,'registration',$formValues,$formUploads,fn()=>az_checkout_ticket_picker85($options,$typeId,$editOrder,$snapshot??[])); ?></fieldset>
 <?php if($methods): ?><fieldset id="payment-method-options"><legend>Payment account</legend><?php foreach($methods as $method): ?><label class="ticket-option"><input type="radio" name="payment_method" value="<?= e($method['id']) ?>" <?= ($draftState['payment_method']??'')===$method['id']?'checked':'' ?>><span><?= e($method['label']) ?></span></label><?php endforeach; ?></fieldset><?php endif; ?>
 <label class="account-consent"><input type="checkbox" name="consent" value="yes" required <?= !empty($draftState['consent'])?'checked':'' ?>><span>I agree to the <a href="/terms.php" target="_blank" rel="noopener">event rules and terms</a> and the <a href="/privacy.php" target="_blank" rel="noopener">privacy policy</a>.</span></label>
 <div class="checkout-total"><span>One ticket · <span data-category-label><?= e($editOrder?$snapshot['type']:($selected['label']??'Choose a category')) ?></span></span><strong id="checkout-total" data-fixed-amount="<?= $editOrder?(int)$editOrder['amount']:'' ?>"><?= $editOrder?e(az_money((int)$editOrder['amount'])):($selected?e(az_money((int)$selected['price'])):'Choose a ticket') ?></strong></div>
 <button class="button button-orange" type="submit"><?= e($fields['registration_button']) ?> ›</button><p id="checkout-message" class="account-notice" role="status" hidden></p>
 </form><?php endif; ?></div></div><?php endif; ?>
</section><script type="module" src="<?= e($publicAssetUrl('checkout.js')) ?>"></script>
<?php require __DIR__.'/includes/footer.php'; ?>
