<?php
require_once __DIR__.'/includes/cms.php';require_once __DIR__.'/includes/google-auth.php';cms_db();set_security_headers();header('Cache-Control: no-store');
try{
 if(($_GET['target']??'')==='staff')throw new RuntimeException('Organisers sign in with their team email or username and password.');
 if(!az_google_ready())throw new RuntimeException('Google sign-in is not connected yet.');$c=az_config();$redirect=az_origin().'/oauth.php';
 if(!isset($_GET['code'])&&!isset($_GET['error'])){
  $state=bin2hex(random_bytes(32));$verifier=rtrim(strtr(base64_encode(random_bytes(48)),'+/','-_'),'=');$_SESSION['google_oauth']=['state'=>$state,'verifier'=>$verifier,'created'=>time(),'target'=>'participant','mode'=>($_GET['mode']??'')==='signup'?'signup':'login'];
  $params=['client_id'=>$c['google_client_id'],'redirect_uri'=>$redirect,'response_type'=>'code','scope'=>'openid email','state'=>$state,'code_challenge'=>rtrim(strtr(base64_encode(hash('sha256',$verifier,true)),'+/','-_'),'='),'code_challenge_method'=>'S256','prompt'=>'select_account'];header('Location: https://accounts.google.com/o/oauth2/v2/auth?'.http_build_query($params));exit;
 }
 $o=$_SESSION['google_oauth']??null;unset($_SESSION['google_oauth']);if(!$o||time()-$o['created']>600||!is_string($_GET['state']??null)||!hash_equals($o['state'],$_GET['state'])||isset($_GET['error']))throw new RuntimeException('Google sign-in was cancelled or expired. Please try again.');
 if(($o['target']??'')==='staff')throw new RuntimeException('Organisers sign in with their team email or username and password.');
 $token=az_http('https://oauth2.googleapis.com/token','FORM',['code'=>cms_oauth_code(),'client_id'=>$c['google_client_id'],'client_secret'=>$c['google_client_secret'],'redirect_uri'=>$redirect,'grant_type'=>'authorization_code','code_verifier'=>$o['verifier']],null,['Content-Type: application/x-www-form-urlencoded']);
 $g=az_http('https://openidconnect.googleapis.com/v1/userinfo','GET',null,null,['Authorization: Bearer '.($token['access_token']??'')]);$identity=az_google_identity($g);$email=$identity['email'];az_auth_limit('google.signin',$email,20,900);$db=cms_db();
 $participant=az_google_participant($db,$identity,$o['mode']??'login');az_participant_login($participant,'google');$_SESSION['participant_next']='/dashboard.php';header('Location: '.az_participant_destination($participant,'/dashboard.php'),true,303);exit;
}catch(Throwable $e){az_auth_event('oauth_failed','google',$identity??null,($_SESSION['google_oauth']['target']??$o['target']??'participant')==='staff'?'staff':'participant',false);http_response_code(400);require_once __DIR__.'/includes/account-layout.php';az_account_start('Sign-in could not finish');az_account_error($e instanceof PDOException?'Please try again.':$e->getMessage());echo '<a class="text-link" href="/account.php">Back to sign in ›</a><a class="text-link" href="/account.php?mode=signup">Create an account ›</a>';az_account_end();}
function cms_oauth_code(): string {$code=$_GET['code']??'';if(!is_string($code)||strlen($code)>4096)throw new RuntimeException('Invalid Google response.');return $code;}
