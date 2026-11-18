<?php
require_once __DIR__.'/includes/cms.php';require_once __DIR__.'/includes/account-layout.php';
$participant=az_require_participant(false,false);set_security_headers();header('Cache-Control: no-store');
$setup=empty($participant['profile_completed']);$error='';
if($_SERVER['REQUEST_METHOD']==='POST')try{
 az_csrf();az_limit('profile.update',(string)$participant['id'],15,300);
 $participant=az_update_participant_profile($participant,$_POST);
 $next=$setup?az_safe_next($_SESSION['profile_next']??$_SESSION['participant_next']??'/dashboard.php'):'/profile.php?saved=1';
 unset($_SESSION['profile_next']);if($next==='/profile.php')$next='/dashboard.php';
 header('Location: '.$next,true,303);exit;
}catch(Throwable $failure){$error=$failure instanceof PDOException?'Your profile could not be saved. Please try again.':$failure->getMessage();}
$name=is_string($_POST['name']??null)?$_POST['name']:($setup?'':$participant['name']);
$phone=is_string($_POST['phone']??null)?$_POST['phone']:$participant['phone'];
az_account_start($setup?'What should we call you?':'Your profile',$setup?'Enter your full name to finish signing in.':'Update your name and phone number.');az_account_error($error);
?>
<?php if(!$setup&&isset($_GET['saved'])&&!$error): ?><p class="account-notice" role="status">Profile saved.</p><?php endif; ?>
<form method="post" class="account-form"><?= csrf_field() ?>
 <label for="profile-name">Full name<input id="profile-name" name="name" value="<?= e($name) ?>" required minlength="2" maxlength="100" autocomplete="name"></label>
 <label for="profile-phone">Phone number <small>(optional)</small><input id="profile-phone" name="phone" type="tel" value="<?= e($phone) ?>" maxlength="25" autocomplete="tel" inputmode="tel"></label>
 <button class="button button-orange" type="submit"><?= $setup?'Continue':'Save profile' ?> ›</button>
</form>
<?php if(!$setup): ?><a class="text-link" href="/dashboard.php">Back to My festival ›</a><?php endif; ?>
<?php az_account_end(); ?>
