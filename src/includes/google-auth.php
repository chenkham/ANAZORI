<?php
declare(strict_types=1);

/** Only the server's Google userinfo response may supply this identity. */
function az_google_identity(array $profile): array {
    $email=strtolower($profile['email']??'');$subject=$profile['sub']??null;
    if(($profile['email_verified']??false)!==true||!filter_var($email,FILTER_VALIDATE_EMAIL)||!is_string($subject)||$subject===''||strlen($subject)>255)throw new RuntimeException('A verified Google email is required.');
    return ['email'=>$email,'sub'=>$subject];
}

/** Link verified accounts once, keeping disabled accounts and conflicting identities unavailable. */
function az_google_participant(PDO $db,array $identity,string $mode='login'): array {
    if(!in_array($mode,['login','signup'],true))throw new InvalidArgumentException('Choose sign in or create an account.');
    $db->beginTransaction();
    try{
        az_lock($db);
        $query=$db->prepare('SELECT * FROM az_participants WHERE google_sub=? OR LOWER(email)=?');$query->execute([$identity['sub'],$identity['email']]);$matches=$query->fetchAll();
        if(count($matches)>1)throw new RuntimeException('This Google account is linked to another participant. Contact the organisers.');
        $user=$matches[0]??null;
        if($user){
            if($mode==='signup')throw new RuntimeException('An account already exists with this email. Please sign in.');
            if(strtolower($user['email'])!==$identity['email'])throw new RuntimeException('This email does not match the registered account. Contact the organisers.');
            if(!$user['active']||($user['google_sub']&&$user['google_sub']!==$identity['sub']))throw new RuntimeException('This account is unavailable.');
            $identityChanged=empty($user['google_sub'])||!$user['email_verified'];
            $db->prepare('UPDATE az_participants SET google_sub=?,email_verified=1,password_hash=?,session_version=session_version+? WHERE id=?')->execute([$identity['sub'],$user['email_verified']?$user['password_hash']:null,$identityChanged?1:0,$user['id']]);
            if($identityChanged)$db->prepare('DELETE FROM az_remember_tokens102 WHERE participant_id=?')->execute([$user['id']]);$id=$user['id'];
        }else{
            $db->prepare("INSERT INTO az_participants(email,name,google_sub,email_verified,created_at) VALUES(?,'',?,1,?)")->execute([$identity['email'],$identity['sub'],gmdate('c')]);$id=$db->lastInsertId();az_auth_event('signup','google',['id'=>$id,'name'=>'','email'=>$identity['email']]);
        }
        $query=$db->prepare('SELECT * FROM az_participants WHERE id=?');$query->execute([$id]);az_notify_welcome89($query->fetch());
        $db->commit();
    }catch(Throwable $error){if($db->inTransaction())$db->rollBack();throw $error;}
    $query=$db->prepare('SELECT * FROM az_participants WHERE id=?');$query->execute([$id]);return $query->fetch();
}
