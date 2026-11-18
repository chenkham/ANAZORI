<?php
require_once __DIR__.'/includes/cms.php';
require_once __DIR__.'/includes/account-layout.php';
require_once __DIR__.'/includes/participant-auth99.php';
$u=az_require_participant(false,false);
set_security_headers();
header('Cache-Control: no-store');
if($u['email_verified']){header('Location: '.az_safe_next($_SESSION['participant_next']??'/dashboard.php'));exit;}
$flash=$_SESSION['verify_flash99']??[];
unset($_SESSION['verify_flash99']);
$error=$flash['error']??'';
$notice=$flash['notice']??'';
$pending=az_pending_verification99($u);
$challenge=$pending['id']??'';
if($_SERVER['REQUEST_METHOD']==='POST'){
    try{
        az_csrf();
        $action=$_POST['action']??'verify';
        if($action==='send'||$action==='resend'){
            // A repeated first-send request keeps the code already in the inbox.
            if($action==='send'&&$pending){
                $notice='A code has already been sent. Enter it below; it remains valid for 10 minutes from sending.';
            }else{
                $_SESSION['verify_challenge']=az_otp_start('VERIFY','participant',(int)$u['id'],$u['email']);
                $notice='A verification code has been sent. Enter it below within 10 minutes.';
            }
        }elseif($action==='verify'){
            if(!$pending)throw new RuntimeException('Your verification code expired or is unavailable. Send a new code below.');
            az_otp_consume($challenge,cms_text('code',6),'VERIFY',function($db,$r)use($u){
                if($r['user_kind']!=='participant'||(int)$r['user_id']!==(int)$u['id']||!hash_equals($r['email_hash'],hash('sha256',strtolower($u['email']))))throw new RuntimeException('Invalid code.');
                $db->prepare('UPDATE az_participants SET email_verified=1 WHERE id=?')->execute([$u['id']]);
                az_notify_welcome89(array_replace($u,['email_verified'=>1]));
                az_auth_event('email_verified','email_otp',$u);
            });
            unset($_SESSION['verify_challenge'],$_SESSION['verify_flash99']);
            header('Location: '.az_safe_next($_SESSION['participant_next']??'/dashboard.php'),true,303);
            exit;
        }else{
            throw new RuntimeException('Choose verification or request a code.');
        }
    }catch(Throwable $e){
        $error=$e instanceof PDOException?'Verification is temporarily unavailable. Please try again.':$e->getMessage();
    }
    // Returning from Gmail or refreshing now opens a GET, never resends the POST.
    $_SESSION['verify_flash99']=['error'=>$error,'notice'=>$notice];
    header('Location: /verify-email.php',true,303);
    exit;
}
az_account_start('Verify your email',$u['email']);
az_account_error($error);
if($notice)echo '<p role="status" class="account-notice">'.e($notice).'</p>';
?>
<?php if($pending): ?>
<form method="post" action="/verify-email.php" class="account-form" data-verification-expires="<?= (int)$pending['expires_at'] ?>">
 <?= csrf_field() ?><input type="hidden" name="action" value="verify">
 <label for="verify-code">6-digit code<input id="verify-code" name="code" inputmode="numeric" autocomplete="one-time-code" required pattern="[0-9]{6}" minlength="6" maxlength="6" autofocus></label>
 <p class="account-help">Your code is valid for 10 minutes after sending. You can close the browser and return through My festival → Verify email to enter the same unexpired code.</p>
 <button class="button button-orange" type="submit">Verify email ›</button>
</form>
<?php else: ?><p class="account-help">Your account is already created. Send a verification code below to verify it; you do not need to create another account.</p><?php endif; ?>
<form method="post" action="/verify-email.php"><?= csrf_field() ?><input type="hidden" name="action" value="<?= $pending?'resend':'send' ?>"><button class="text-link" type="submit"><?= $pending?'Send a new code':'Send verification code' ?> ›</button></form>
<p class="account-help">Codes expire in 10 minutes. Wait one minute before requesting another. Sending a new code replaces the previous code.</p>
<a class="text-link" href="/dashboard.php">Back to my account</a>
<?php az_account_end(); ?>
