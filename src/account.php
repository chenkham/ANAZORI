<?php
require_once __DIR__.'/includes/cms.php';require_once __DIR__.'/includes/account-layout.php';require_once __DIR__.'/includes/participant-auth99.php';cms_db();set_security_headers();header('Cache-Control: no-store');
$mode=($_GET['mode']??'')==='signup'?'signup':'login';$error='';$next=az_safe_next(is_string($_GET['next']??null)?$_GET['next']:($_SESSION['participant_next']??'/dashboard.php'));$_SESSION['participant_next']=$next;
if(az_participant()){header('Location: '.$next);exit;}
if($_SERVER['REQUEST_METHOD']==='POST')try{
 az_csrf();$email=strtolower(cms_text('email',254));if(!filter_var($email,FILTER_VALIDATE_EMAIL))throw new RuntimeException('Enter a valid email address.');$password=$_POST['password']??'';if(!is_string($password)||strlen($password)>200)throw new RuntimeException('Check your password.');az_auth_limit('participant.'.$mode,$email);
 $db=cms_db();
 if($mode==='signup'){
  $u=az_password_signup99($db,$email,cms_text('name',100),$password);az_participant_login($u,'email_password','signup');header('Location: /verify-email.php',true,303);exit;
 }
 $s=$db->prepare('SELECT * FROM az_participants WHERE LOWER(email)=? LIMIT 1');$s->execute([$email]);$u=$s->fetch();
 $dummy='$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2uheWG/igi.';
 if(!password_verify($password,$u['password_hash']??$dummy)||!$u||!$u['active'])throw new RuntimeException('The email or password is incorrect, or this account is unavailable.');az_participant_login($u);header('Location: '.$next,true,303);exit;
}catch(Throwable $e){if($mode==='login'&&isset($email)&&filter_var($email,FILTER_VALIDATE_EMAIL))az_auth_event('login_failed','email_password',null,'participant',false,$email);$error=$e instanceof PDOException?'We could not complete sign-in. Please try again.':$e->getMessage();}
az_account_start($mode==='signup'?'Create your account':'Welcome back');az_account_error($error);
?>
<?php if($mode==='signup'&&!az_mail_delivery_available()): ?><p class="account-notice" role="status">Email signup will open when verification email is connected. You can continue with Google below.</p><?php endif; ?>
<form method="post" class="account-form"><?= csrf_field() ?><?php if($mode==='signup'): ?><label for="account-name">Full name<input id="account-name" name="name" autocomplete="name" required minlength="2" maxlength="100"></label><?php endif; ?><label for="account-email">Email<input id="account-email" name="email" type="email" autocomplete="email" required maxlength="254"></label><label for="account-password">Password<input id="account-password" type="password" name="password" required minlength="<?= $mode==='signup'?12:1 ?>" maxlength="200" autocomplete="<?= $mode==='signup'?'new-password':'current-password' ?>"><?php if($mode==='signup'): ?><small>Use at least 12 characters.</small><?php endif; ?></label><button class="button button-orange" type="submit" <?= $mode==='signup'&&!az_mail_delivery_available()?'disabled':'' ?>><?= $mode==='signup'?'Create account':'Sign in' ?> ›</button></form>
<?php if(az_google_ready()): ?><a class="google-button" href="/oauth.php?target=participant&amp;mode=<?= e($mode) ?>"> <svg viewBox="0 0 24 24" width="22" height="22" aria-hidden="true"><path fill="#4285F4" d="M22 12.2c0-.7-.1-1.4-.2-2.1H12v4h5.6a4.8 4.8 0 0 1-2.1 3.2v2.6h3.4c2-1.8 3.1-4.4 3.1-7.7Z"/><path fill="#34A853" d="M12 22c2.8 0 5.2-.9 6.9-2.5l-3.4-2.6c-.9.6-2.1.9-3.5.9a6 6 0 0 1-5.6-4.1H2.9v2.7A10 10 0 0 0 12 22Z"/><path fill="#FBBC05" d="M6.4 13.7a6.1 6.1 0 0 1 0-3.4V7.6H2.9a10 10 0 0 0 0 8.8l3.5-2.7Z"/><path fill="#EA4335" d="M12 6.2c1.5 0 2.8.5 3.8 1.5l3-3A10 10 0 0 0 2.9 7.6l3.5 2.7A6 6 0 0 1 12 6.2Z"/></svg>Continue with Google</a><?php else: ?><?php endif; ?>
<p class="account-help">You stay signed in on this browser for up to 30 days, until you sign out. Already created an account? Sign in and open Verify email to use a code that is still valid.</p>
<div class="account-links"><a href="/account.php?mode=<?= $mode==='signup'?'login':'signup' ?>&next=<?= rawurlencode($next) ?>"><?= $mode==='signup'?'Already have an account? Sign in':'New here? Create an account' ?></a><a href="/forgot-password.php">Forgot password?</a></div>
<?php az_account_end(); ?>
