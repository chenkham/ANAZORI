<?php
declare(strict_types=1);

/** Apply the supplied brochure once, preserving IDs, forms, payments and later Studio edits. */
function az_apply_brochure63(PDO $db): void {
    if($db->query("SELECT value FROM cms_settings WHERE setting_key='brochure_release_63'")->fetchColumn())return;
    $brochure=require __DIR__.'/../config/brochure-v16.php';
    $db->beginTransaction();
    try {
        az_lock($db);
        if($db->query("SELECT value FROM cms_settings WHERE setting_key='brochure_release_63'")->fetchColumn()){$db->commit();return;}
        $now=gmdate('c');
        $site=json_decode($db->query("SELECT value FROM cms_settings WHERE setting_key='site'")->fetchColumn()?:'{}',true)?:[];
        // Prativa has been replaced by Youth Parliament, as confirmed by the organiser.
        foreach(['cms_content','events'] as $table){
            $type=$table==='cms_content'?" AND type='event'":'';
            $old=$db->query("SELECT id FROM $table WHERE slug='prativa'$type")->fetchColumn();
            $new=$db->query("SELECT id FROM $table WHERE slug='youth-parliament'$type")->fetchColumn();
            if($old&&!$new)$db->prepare("UPDATE $table SET slug='youth-parliament' WHERE id=?")->execute([$old]);
        }
        $defaults=[];foreach(cms_content_schema()['event']['fields'] as $key=>$definition)$defaults[$key]=$definition[2]??'';
        $order=0;
        foreach($brochure['events'] as $slug=>$confirmed){
            $query=$db->prepare("SELECT * FROM cms_content WHERE type='event' AND slug=?");$query->execute([$slug]);$old=$query->fetch();
            $saved=$old?(json_decode($old['data'],true)?:[]):$defaults;
            $title=$confirmed['title'];unset($confirmed['title'],$confirmed['page'],$confirmed['game_categories']);
            $fields=array_replace($saved,$confirmed);
            if($slug==='joystick'){
                $games=json_decode($saved['game_categories']??'[]',true)?:[];
                foreach(json_decode($brochure['events'][$slug]['game_categories'],true) as $game){
                    $found=false;foreach($games as $existing)if(($existing['id']??'')===$game['id']||mb_strtolower($existing['label']??'')===mb_strtolower($game['label'])){$found=true;break;}
                    if(!$found)$games[]=$game;
                }
                $fields['game_categories']=json_encode($games,JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR);
            }
            if(($fields['rules_pdf']??'')==='/ANAZORI_V15.0_Brochure.pdf')$fields['rules_pdf']=$brochure['pdf'];
            unset($fields['title']);
            $json=json_encode($fields,JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR);++$order;
            if($old)$db->prepare('UPDATE cms_content SET title=?,data=?,sort_order=?,revision=revision+1,updated_at=? WHERE id=?')->execute([$title,$json,$order,$now,$old['id']]);
            else $db->prepare("INSERT INTO cms_content(type,slug,title,data,status,sort_order,created_by,updated_at) VALUES('event',?,?,?,'PUBLISHED',?,0,?)")->execute([$slug,$title,$json,$order,$now]);
            $legacy=$db->prepare('SELECT id FROM events WHERE slug=?');$legacy->execute([$slug]);$id=$legacy->fetchColumn();
            if($id)$db->prepare('UPDATE events SET title=?,tag_line=?,description=? WHERE id=?')->execute([$title,$fields['short']??'',$fields['description']??'',$id]);
            else $db->prepare("INSERT INTO events(slug,title,tag_line,description,location,status) VALUES(?,?,?,?,?,'ACTIVE')")->execute([$slug,$title,$fields['short']??'',$fields['description']??'',$site['venue']??'Dibrugarh University']);
        }
        $nameKey=static function(string $name): string {
            $name=preg_replace('/^(?:Prof|Dr|Mrs|Mr|Ms)\.?\s+/iu','',trim($name))??$name;
            return mb_strtolower(preg_replace('/[^\p{L}\p{N}]/u','',$name)??$name);
        };
        $people=$db->query("SELECT * FROM cms_content WHERE type='person'")->fetchAll();$used=[];
        foreach($brochure['people'] as $order=>$person){
            $keys=array_map($nameKey,array_merge([$person['title']],$person['aliases']??[]));$old=null;
            foreach($people as $candidate)if(in_array($nameKey($candidate['title']),$keys,true)){$old=$candidate;break;}
            $fields=$old?(json_decode($old['data'],true)?:[]):['image'=>'','description'=>'','link'=>''];
            foreach(['group','role'] as $key)$fields[$key]=$person[$key];$fields['edition']='V16.0 / 2026';
            if(empty($fields['image'])&&!empty($person['image']))$fields['image']=$person['image'];
            $json=json_encode($fields,JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR);
            if($old){$used[]=(int)$old['id'];$db->prepare("UPDATE cms_content SET title=?,data=?,status='PUBLISHED',sort_order=?,revision=revision+1,updated_at=? WHERE id=?")->execute([$person['title'],$json,$order,$now,$old['id']]);}
            else{$db->prepare("INSERT INTO cms_content(type,slug,title,data,status,sort_order,created_by,updated_at) VALUES('person',?,?,?,'PUBLISHED',?,0,?)")->execute(['v16-'.$nameKey($person['title']),$person['title'],$json,$order,$now]);$used[]=(int)$db->lastInsertId();}
        }
        foreach($people as $old){
            $fields=json_decode($old['data'],true)?:[];
            if(!in_array((int)$old['id'],$used,true)&&($fields['edition']??'')==='Previous edition'&&$old['status']==='PUBLISHED')$db->prepare("UPDATE cms_content SET status='ARCHIVED',revision=revision+1,updated_at=? WHERE id=?")->execute([$now,$old['id']]);
        }
        $site=array_replace($site,$brochure['site'],['brochure_pdf'=>$brochure['pdf']]);
        cms_put_setting('site',json_encode($site,JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR));
        $revision=(int)$db->query("SELECT value FROM cms_settings WHERE setting_key='settings_revision'")->fetchColumn();cms_put_setting('settings_revision',(string)($revision+1));
        $media=$db->prepare('SELECT id FROM cms_media WHERE path=?');$media->execute([$brochure['pdf']]);
        if(!$media->fetchColumn())$db->prepare('INSERT INTO cms_media(path,title,mime,size_bytes,uploaded_by,created_at) VALUES(?,?,?,?,0,?)')->execute([$brochure['pdf'],'Anazori V16.0 - Official brochure','application/pdf',filesize(__DIR__.'/..'.$brochure['pdf']),$now]);
        $db->prepare('INSERT INTO cms_audit(user_id,username,action,detail,created_at) VALUES(0,?,?,?,?)')->execute(['Brochure update','brochure.publish','Public V16.0 programme, committee and contacts updated from the supplied brochure. Prativa replaced by Youth Parliament; existing operational records retained.',$now]);
        az_schema_marker($db,'brochure_release_63');$db->commit();
    } catch(Throwable $error){if($db->inTransaction())$db->rollBack();throw $error;}
}
