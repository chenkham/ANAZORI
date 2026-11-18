<?php
declare(strict_types=1);
require_once __DIR__.'/includes/commerce.php';
set_security_headers();header('Cache-Control: no-store');
$slug=is_string($_GET['event']??null)?$_GET['event']:'';
if($slug===''){header('Location: /events.php',true,302);exit;}
$event=az_event($slug);$error='';$games=[];
if(!$event){http_response_code(404);$error='This event is not available.';}
elseif(az_participation_mode($event)!=='registration'){header('Location: /event.php?name='.rawurlencode($event['slug']),true,302);exit;}
else{
    $slug=$event['slug'];$fields=$event['fields'];$games=az_event_games($fields);
    $game=is_string($_GET['game']??null)?$_GET['game']:'';
    if(cms_event_phase($fields)!=='open'){http_response_code(403);$error=$fields['registration_closed_message']?:'Registration is currently closed.';}
    elseif(az_event_games($fields,false)&&!$games){http_response_code(403);$error='No game is currently accepting registrations. Please check back later.';}
    elseif(!$games||$game!==''){
        try{
            az_selected_game($fields,$game);
            $destination=az_external_registration_url97($fields,$game);
            if($destination==='')$destination='/checkout.php?event='.rawurlencode($slug).($game!==''?'&game='.rawurlencode($game):'');
            header('Location: '.$destination,true,302);exit;
        }catch(InvalidArgumentException|RuntimeException){http_response_code(400);$error='Choose an available game for this event.';}
    }
}
$activePage='events';$pageTitle=($event?$event['title'].' registration':'Registration').' — Anazori';
require __DIR__.'/includes/header.php';
?>
<section class="checkout-shell section-pad external-registration97">
 <a class="back-link" href="<?= $event?'/event.php?name='.e(rawurlencode($event['slug'])):'/events.php' ?>">← <?= $event?'Event details':'Explore events' ?></a>
 <h1><?= e($event['title']??'Event unavailable') ?></h1>
 <?php if($error): ?><p class="account-notice" role="alert"><?= e($error) ?></p>
 <?php else: ?>
 <h2>Choose your game.</h2><p>Select the game you want to register for.</p>
 <div class="registration-game-grid97">
 <?php foreach($games as $index=>$choice): $external=az_external_registration_url97($fields,$choice['id'])!==''; ?>
  <a class="registration-game-card97" href="/register.php?event=<?= e(rawurlencode($slug)) ?>&amp;game=<?= e(rawurlencode($choice['id'])) ?>" aria-label="Register for <?= e($choice['label']) ?>">
   <span class="eyebrow">GAME <?= str_pad((string)($index+1),2,'0',STR_PAD_LEFT) ?></span>
   <strong><?= e($choice['label']) ?></strong><span><?= $external?'Open Google Form':'Open registration' ?> <?= arrow_icon() ?></span>
  </a>
 <?php endforeach; ?>
 </div>
 <?php endif; ?>
</section>
<?php require __DIR__.'/includes/footer.php'; ?>
