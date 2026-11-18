<?php
declare(strict_types=1);
require_once __DIR__.'/commerce.php';
function az_launch_payment_ready90(array $fields): bool {
 $games=az_event_games($fields);$contexts=$games?array_column($games,'id'):[''];
 foreach($contexts as $game){
  if(az_external_registration_url97($fields,$game)!=='')continue;
  $context=az_game_fields81($fields,$game);
  $paid=array_filter(az_ticket_options81($context,$game),fn($ticket)=>(int)$ticket['price']>0);
  if(!$paid)continue;
  if(!empty($context['form_workflow'])){
   $links=az_ticket_qrs85($context);
   foreach($paid as $ticket)if(empty($links[$ticket['id']]['media'])&&empty($links[$ticket['id']]['payment_dynamic']))return false;
  }elseif(!az_payment_methods($context))return false;
 }
 return true;
}
function az_launch_checks(): array {
 $driver=cms_db()->getAttribute(PDO::ATTR_DRIVER_NAME);
 $mailHeartbeat=(int)cms_db()->query("SELECT value FROM cms_settings WHERE setting_key='mail_worker_heartbeat89'")->fetchColumn();
 $checks=[
  ['PHP runtime',version_compare(PHP_VERSION,'8.2.0','>='),'PHP '.PHP_VERSION.'; hosting requires PHP 8.2 or newer.'],
  ['Database',true,strtoupper($driver).' connected. Accounts, registrations and sign-in history share this database.'],
  ['Required PHP extensions',!array_filter(['curl','mbstring','fileinfo','openssl','pdo','dom'],fn($extension)=>!extension_loaded($extension)),'cURL, mbstring, Fileinfo, OpenSSL, PDO and DOM are needed.'],
  ['Event editor input limit',(int)ini_get('max_input_vars')>=3000,'max_input_vars = '.ini_get('max_input_vars').'. Set at least 3000 in hosting PHP configuration.'],
  ['Private application key',is_readable(az_application_key_path90())||getenv('ANAZORI_APP_KEY')!==false,'Preserve the application key with the database; it protects stored integration secrets.'],
  ['Google credentials',az_google_ready(),'Configuration present does not confirm Google Console approval. Test sign-in on the current origin.'],
  ['OTP email',az_mail_ready(),'PHP mail() is available. Confirm sender authorisation, domain authentication and one live OTP on the host.'],
  ['Email mode',az_mail_notifications_enabled89(),'Submission receipts, approved tickets and reminders use the notification sender pair. New notices get an automatic delivery attempt; run the email cron every minute for reminders, retries and alerts.'],
 ];
 if(az_mail_notifications_enabled89())$checks[]=['Email cron job',$mailHeartbeat>time()-600,'Run includes/mail-worker95.php every minute for enabled notifications.'];
 $checks=array_merge($checks,az_storage_checks90());
 foreach(cms_records('event',true) as $event){
  $fields=$event['fields'];$phase=cms_event_phase($fields);$detail=cms_phase_label($fields);
  $ok=$phase!=='open'||az_launch_payment_ready90($fields);
  if(!$ok)$detail.=' · link a payment QR to every paid ticket category in each registration form before accepting payments.';
  if(az_event_games($fields,false)&&!az_event_games($fields)&&$phase==='open'){$ok=false;$detail.=' · enable at least one game.';}
  $checks[]=[$event['title'],$ok,$detail];
 }
 return $checks;
}
function az_launch_readiness_panel(): void { ?>
 <section class="panel"><div class="panel-heading"><h2>Launch checks</h2><span class="badge">CURRENT SERVER</span></div><p class="help">Complete Google sign-in and email verification in your normal browser before public registration opens.</p><div class="table-wrap"><table><thead><tr><th>Check</th><th>Status</th><th>Details</th></tr></thead><tbody><?php foreach(az_launch_checks() as [$label,$ok,$detail]): ?><tr><td><?= e($label) ?></td><td><?= $ok?'Configured':'Needs attention' ?></td><td><?= e($detail) ?></td></tr><?php endforeach; ?></tbody></table></div></section>
 <?php }
