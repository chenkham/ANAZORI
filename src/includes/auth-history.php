<?php
declare(strict_types=1);

function az_install_auth_history(PDO $db): void {
    $sqlite=$db->getAttribute(PDO::ATTR_DRIVER_NAME)==='sqlite';
    $id=$sqlite?'INTEGER PRIMARY KEY AUTOINCREMENT':'BIGINT AUTO_INCREMENT PRIMARY KEY';
    $db->exec("CREATE TABLE IF NOT EXISTS az_auth_events (id $id,user_kind VARCHAR(20) NOT NULL,user_id INT,user_name VARCHAR(150) NOT NULL,email VARCHAR(254) NOT NULL,event VARCHAR(40) NOT NULL,method VARCHAR(30) NOT NULL,success INT NOT NULL,occurred_at VARCHAR(40) NOT NULL)");
    if($db->query("SELECT value FROM cms_settings WHERE setting_key='auth_history_schema'")->fetchColumn())return;
    foreach(['az_auth_events_user'=>'az_auth_events (user_kind,user_id,id)','az_auth_events_email'=>'az_auth_events (email,id)'] as $name=>$definition){
        try{$db->exec('CREATE INDEX '.($sqlite?'IF NOT EXISTS ':'').$name.' ON '.$definition);}catch(PDOException $error){if((int)($error->errorInfo[1]??0)!==1061)throw $error;}
    }
    cms_put_setting('auth_history_schema','1');
}

/** Identity and outcome only: never store passwords, OTP values or OAuth tokens. */
function az_auth_event(string $event,string $method,?array $user=null,string $kind='participant',bool $success=true,string $email=''): void {
    if(!in_array($event,['signup','profile_updated','login','login_failed','email_verified','otp_sent','otp_failed','password_reset','logout','oauth_failed'],true)||!in_array($method,['google','email_password','email_otp','remember_cookie'],true)||!in_array($kind,['participant','staff'],true))throw new InvalidArgumentException('Invalid sign-in activity.');
    if(!empty($user['id'])&&(!isset($user['email'])||(!isset($user['name'])&&!isset($user['display_name'])))){
        $identity=cms_db()->prepare($kind==='staff'?'SELECT id,email,display_name,username FROM users WHERE id=?':'SELECT id,email,name FROM az_participants WHERE id=?');$identity->execute([$user['id']]);$user=array_replace($identity->fetch()?:[],$user);
    }
    $query=cms_db()->prepare('INSERT INTO az_auth_events(user_kind,user_id,user_name,email,event,method,success,occurred_at) VALUES(?,?,?,?,?,?,?,?)');
    $query->execute([$kind,$user['id']??null,mb_substr($user['name']??$user['display_name']??$user['username']??'',0,150),mb_substr(strtolower($user['email']??$email),0,254),$event,$method,$success?1:0,gmdate('c')]);
}

function st_auth_history(array $staff): void {
    if(!cms_can($staff,'logins'))throw new RuntimeException('No access to sign-in history.');
    $page=max(1,min(100000,(int)($_GET['p']??1)));$search=is_string($_GET['q']??null)?mb_substr(trim($_GET['q']),0,100):'';
    $method=is_string($_GET['method']??null)?$_GET['method']:'';
    $where=[];$params=[];
    if($search!==''){$where[]='(email LIKE ? OR user_name LIKE ?)';$params=['%'.$search.'%','%'.$search.'%'];}
    if(in_array($method,['google','email_password','email_otp','remember_cookie'],true)){$where[]='method=?';$params[]=$method;}
    $query=cms_db()->prepare('SELECT * FROM az_auth_events'.($where?' WHERE '.implode(' AND ',$where):'').' ORDER BY id DESC LIMIT 51 OFFSET '.(($page-1)*50));$query->execute($params);$rows=$query->fetchAll();
    ?>
    <p class="page-help">Google sign-ins, account creation, password sign-ins and email verification. Records begin when this update is installed.</p>
    <form method="get" class="list-toolbar"><input type="hidden" name="section" value="logins"><label class="sr-only" for="auth-search">Name or email</label><input id="auth-search" name="q" value="<?= e($search) ?>" placeholder="Name or email"><label class="sr-only" for="auth-method">Sign-in method</label><select id="auth-method" name="method"><option value="">All methods</option><?php foreach(['google'=>'Google','email_password'=>'Email and password','email_otp'=>'Email verification','remember_cookie'=>'Remembered browser'] as $key=>$label): ?><option value="<?= $key ?>" <?= $method===$key?'selected':'' ?>><?= $label ?></option><?php endforeach; ?></select><button class="quiet-button">Filter</button></form>
    <div class="table-wrap" tabindex="0" role="region" aria-label="Sign-in history"><table><thead><tr><th>Account</th><th>Activity</th><th>Method</th><th>Result</th><th>Time (UTC)</th></tr></thead><tbody><?php foreach(array_slice($rows,0,50) as $row): ?><tr><td><strong><?= e($row['user_name']?:'Account not identified') ?></strong><br><?= e($row['email']) ?><br><small><?= e($row['user_kind']) ?></small></td><td><?= e(ucwords(str_replace('_',' ',$row['event']))) ?></td><td><?= e(str_replace('_',' ',$row['method'])) ?></td><td><?= $row['success']?'Successful':'Unsuccessful' ?></td><td><?= e($row['occurred_at']) ?></td></tr><?php endforeach; ?></tbody></table><?php if(!$rows): ?><p class="empty-message">No sign-in activity recorded yet.</p><?php endif; ?></div>
    <nav class="form-actions" aria-label="Sign-in history pages"><?php if($page>1): ?><a class="quiet-button" href="/admin.php?<?= e(http_build_query(['section'=>'logins','p'=>$page-1,'q'=>$search,'method'=>$method])) ?>">Previous</a><?php endif;if(count($rows)>50): ?><a class="quiet-button" href="/admin.php?<?= e(http_build_query(['section'=>'logins','p'=>$page+1,'q'=>$search,'method'=>$method])) ?>">Next</a><?php endif; ?></nav>
    <?php
}
