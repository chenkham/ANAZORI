<?php
require_once __DIR__.'/includes/festival.php';$slug=is_string($_GET['name']??null)?$_GET['name']:'';
if($slug==='game-of-codes'){header('Location: /event.php?name=goc',true,301);exit;}
if($slug==='futsal'){header('Location: /event.php?name=treasure-hunt',true,301);exit;}
if($slug==='prativa'){header('Location: /event.php?name=youth-parliament',true,301);exit;}
$event=$festival['events'][$slug]??null;$activePage='events';
if(!$event){http_response_code(404);$pageTitle='Experience not found';require __DIR__.'/includes/header.php'; ?><section class="page-intro section-pad"><h1>Let's find<br>your way back.</h1><p>This experience is not currently published.</p><a class="button button-orange" href="/events.php">Explore the experiences <?= arrow_icon() ?></a></section><?php require __DIR__.'/includes/footer.php';exit;}
require_once __DIR__.'/includes/commerce.php';$participation=az_participation_mode($event);$contribution=$participation==='contribution';$ceremony=false;$performers=false;$hasTickets=(bool)az_prices($event);$onSale=array_values(array_filter(az_prices($event),fn($t)=>$t['active']));$amounts=array_column($onSale,'price');$priceLabel=$amounts?(min($amounts)===max($amounts)?az_money((int)min($amounts)):'From '.az_money((int)min($amounts))):'Details coming soon';$phase=cms_event_phase($event);$isRegistration=$phase==='open';$canSubmit=$contribution?$isRegistration:($phase==='interest'&&$event['interest_open']==='1');
$registrationGames=$slug==='joystick'&&$participation==='registration'?az_event_games($event):[];$showGamePicker=$isRegistration&&(bool)$registrationGames;
$eventDocuments=az_event_documents103($event);
$pageTitle=$event['title'].' — '.setting('site_name');$pageDescription=$event['short'];require __DIR__.'/includes/header.php';
?>
<section class="event-detail section-pad"><a class="back-link" href="/events.php">← All experiences</a><div class="detail-grid"><div class="detail-copy">
 <h1><?= e($event['title']) ?><span>.</span></h1><p class="detail-tagline"><?= e($event['short']) ?></p><p class="detail-description"><?= cms_escape_lines($event['description']) ?></p>
 <div class="detail-facts"><div><span class="eyebrow">WHEN</span><strong><?= $event['starts_at']?e(cms_date_label($event['starts_at'])):'To be announced' ?><?php if($event['ends_at']): ?><br>to <?= e(cms_date_label($event['ends_at'])) ?><?php endif; ?></strong></div><div><span class="eyebrow">WHERE</span><strong><?= e($event['venue']?:setting('venue')) ?></strong></div>
 <?php if(!$ceremony): ?><div><span class="eyebrow"><?= $performers?'PERFORMING':'ENTRY DETAILS' ?></span><strong><?= $contribution?'Contributions & performances':e($hasTickets?$priceLabel:($event['fees']?:'Coming soon')) ?></strong></div><div><span class="eyebrow">STATUS</span><strong><span class="status-dot"></span> <?= e(cms_phase_label($event)) ?></strong></div><?php endif; ?></div>
 <div class="detail-actions"><?php if($contribution): ?><a class="button button-dark" href="#event-preview">Preview <?= arrow_icon() ?></a><?php if($canSubmit): ?><button class="button button-orange" data-interest>Contribute <?= arrow_icon() ?></button><?php else: ?><span class="registration-closed"><?= e(cms_phase_label($event)) ?></span><?php endif; ?><?php elseif($isRegistration&&($hasTickets||az_has_external_registration97($event)||$showGamePicker)): ?><a class="button button-orange" href="/register.php?event=<?= e($slug) ?>"<?= $showGamePicker?' data-game-registration105 aria-haspopup="dialog" aria-controls="joystick-registration-dialog"':'' ?>>Register now <?= arrow_icon() ?></a><?php elseif($canSubmit): ?><button class="button button-orange" data-interest>I'm interested <?= arrow_icon() ?></button><?php else: ?><span class="registration-closed"><?= e(cms_phase_label($event)) ?></span><?php endif; ?><?php if(!$contribution): ?><button class="share-button" data-share>Share experience <?= arrow_icon() ?></button><?php endif; ?></div>
 <p class="small-note"><?= $contribution?'Share your contribution or performance idea with the coordinators.':($isRegistration?(az_has_external_registration97($event)?($slug==='joystick'?'Choose a game to open its registration form.':'Registration is collected through the event coordinator’s Google Form.'):($slug==='joystick'?'One registration and one ticket per game per account.':'One registration and one ticket per event per account.')):($phase==='interest'?'Share your interest with the event team. No sign-up or sign-in needed.':cms_escape_lines($event['registration_closed_message']))) ?></p>
 <?php if($eventDocuments): ?><a class="document-shortcut103" href="#event-documents">View event PDFs <span aria-hidden="true">↓</span></a><?php endif; ?>
 </div><div class="detail-art event-art art-<?= e($event['art']) ?> color-<?= e($event['color']) ?>"><?= event_art($event) ?><?php if($slug==='joystick'): ?><span class="gaming-guest" aria-hidden="true"><?= festival_character('charizard') ?></span><?php endif; ?></div></div></section>
<section class="detail-next section-pad" id="event-preview">
 <div><h2>Everything<br>you need to know.</h2>
 <?php if($eventDocuments): ?>
  <div class="event-documents103" id="event-documents" aria-label="Event PDFs">
   <p class="eyebrow">EVENT DOCUMENTS</p>
   <?php foreach($eventDocuments as $document): ?>
   <a class="rules-download" href="<?= e($document['path'].'?view=inline') ?>" target="_blank" rel="noopener noreferrer" aria-label="<?= e($document['label'].' (PDF, opens in a new tab)') ?>">
    <span class="document-type103" aria-hidden="true">PDF</span>
    <span class="document-copy103"><span class="document-label103"><?= e($document['label']) ?></span><span class="document-note103">Read in your browser · Opens in a new tab</span></span>
    <span class="document-action103" aria-hidden="true">Open PDF ↗</span>
   </a>
   <?php endforeach; ?>
  </div>
 <?php endif; ?>
 </div>
 <div class="detail-steps"><?php $n=0;foreach(['format'=>'Event format','eligibility'=>'Who can take part','rules'=>'Rules & instructions','prizes'=>'Prizes & recognition','contact'=>'Your event coordinators'] as $key=>$label): if(!$event[$key])continue; ?><article><span>0<?= ++$n ?></span><div><h3><?= e($label) ?></h3><p><?= cms_escape_lines($event[$key]) ?></p></div></article><?php endforeach;if(!$n): ?><article><span>01</span><div><h3>Curiosity first. Details next.</h3><p>Confirmed rules, eligibility, prizes, and coordinator details will be published here by the organising team.</p></div></article><?php endif; ?></div>
</section>
<?php if($showGamePicker): ?>
<dialog id="joystick-registration-dialog" class="joystick-registration105" aria-labelledby="joystick-registration-title" aria-describedby="joystick-registration-intro">
 <button class="dialog-close" type="button" aria-label="Close game selection">✕</button>
 <h2 id="joystick-registration-title">Choose your game.</h2>
 <p id="joystick-registration-intro" class="dialog-intro">Select a game to open its registration form.</p>
 <div class="registration-game-grid97">
 <?php foreach($registrationGames as $index=>$choice): $external=az_external_registration_url97($event,$choice['id'])!==''; ?>
  <a class="registration-game-card97" data-registration-game105 href="/register.php?event=<?= e(rawurlencode($slug)) ?>&amp;game=<?= e(rawurlencode($choice['id'])) ?>" aria-label="Register for <?= e($choice['label']) ?>">
   <span class="eyebrow">GAME <?= str_pad((string)($index+1),2,'0',STR_PAD_LEFT) ?></span>
   <strong><?= e($choice['label']) ?></strong><span><?= $external?'Open Google Form':'Open registration' ?> <?= arrow_icon() ?></span>
  </a>
 <?php endforeach; ?>
 </div>
</dialog>
<?php endif; ?>
<?php if($canSubmit)require __DIR__.'/includes/event-interest-form.php'; ?>
<?php require __DIR__.'/includes/footer.php'; ?>
