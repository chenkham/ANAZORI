<?php
declare(strict_types=1);

/** A category changes the fee, never the number of tickets issued. */
function az_ticket_options81(array $fields,string $game=''): array {
    return array_values(array_filter(az_prices($fields),fn($row)=>!empty($row['active'])&&(empty($row['game'])||$row['game']===$game)));
}
function az_game_fields81(array $fields,string $game,string $phase='registration'): array {
    if($game==='')return $fields;
    $known=null;foreach(az_event_games($fields,false) as $item)if($item['id']===$game)$known=$item;
    if(!$known)throw new InvalidArgumentException('Choose an available game.');
    $forms=json_decode($fields['game_forms']??'{}',true)?:[];
    foreach(['form','settings','title','intro','button','form_draft'] as $suffix){
        $key=$phase.'_'.$suffix;
        if(array_key_exists($key,$forms[$game]??[]))$fields[$key]=$forms[$game][$key];
        elseif($suffix==='form_draft')unset($fields[$key]);
    }
    $schema=json_decode($fields[$phase.'_form']??'null',true);
    if(is_array($schema)){$schema=array_values(array_filter($schema,fn($row)=>empty($row['game'])||$row['game']===$game));foreach($schema as &$row)$row['game']='';unset($row);$fields[$phase.'_form']=json_encode($schema,JSON_THROW_ON_ERROR);}
    $fields['_form_game']=$game;$fields['_form_game_label']=$known['label'];
    return $fields;
}
function az_draft_context81(string $game,int $order=0): int {
    return $order?:($game===''?0:-(1+(int)hexdec(substr(hash('sha256',$game),0,7))));
}
function az_latest_draft_game81(int $participant,int $event): string {
    $q=cms_db()->prepare('SELECT game_id FROM az_checkout_drafts WHERE participant_id=? AND event_id=? AND context_id<=0 ORDER BY updated_at DESC LIMIT 1');$q->execute([$participant,$event]);return (string)($q->fetchColumn()?:'');
}
function az_install_options81(PDO $db): void {
    if($db->query("SELECT value FROM cms_settings WHERE setting_key='event_options81'")->fetchColumn()){az_install_game_forms81($db);return;}
    $columns=$db->getAttribute(PDO::ATTR_DRIVER_NAME)==='sqlite'?$db->query('PRAGMA table_info(az_checkout_drafts)')->fetchAll():$db->query('SHOW COLUMNS FROM az_checkout_drafts')->fetchAll();
    if(!in_array('type_id',array_column($columns,$db->getAttribute(PDO::ATTR_DRIVER_NAME)==='sqlite'?'name':'Field'),true))$db->exec("ALTER TABLE az_checkout_drafts ADD COLUMN type_id VARCHAR(60) NOT NULL DEFAULT ''");
    $db->beginTransaction();
    try{
        az_lock($db);
        if($db->query("SELECT value FROM cms_settings WHERE setting_key='event_options81'")->fetchColumn()){$db->commit();return;}
        foreach($db->query("SELECT id,slug,data FROM cms_content WHERE type='event'")->fetchAll() as $event){
            $fields=json_decode($event['data'],true)?:[];$changed=false;
            if($event['slug']==='joystick'){
                $games=az_event_games($fields,false);
                foreach(['mobile-legends'=>'MLBB','bgmi'=>'BGMI','free-fire'=>'Free Fire'] as $id=>$label){
                    $found=false;
                    foreach($games as &$game){$name=mb_strtolower($game['label']);if($game['id']===$id||($label==='MLBB'&&(str_contains($name,'mobile legends')||str_contains($name,'mlbb')))||mb_strtolower($label)===$name){$game['active']=true;$found=true;}}unset($game);
                    if(!$found)$games[]=['id'=>$id,'label'=>$label,'active'=>true];
                }
                $fields['game_categories']=json_encode($games,JSON_THROW_ON_ERROR);$changed=true;
            }
            $prices=json_decode($fields['ticket_types']??'[]',true)?:[];
            foreach($prices as &$price)if(in_array($price['label'],['Individual ticket','Team ticket'],true)){$price['label']='Event ticket';$changed=true;}unset($price);
            if($prices)$fields['ticket_types']=json_encode($prices,JSON_THROW_ON_ERROR);
            if($changed)$db->prepare('UPDATE cms_content SET data=?,revision=revision+1 WHERE id=?')->execute([json_encode($fields,JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR),$event['id']]);
        }
        // Move previous game drafts together with their private file ownership.
        foreach($db->query("SELECT participant_id,event_id,game_id FROM az_checkout_drafts WHERE context_id=0 AND game_id<>''")->fetchAll() as $row){
            $context=az_draft_context81($row['game_id']);
            foreach(['az_checkout_drafts','az_draft_files'] as $table)$db->prepare("UPDATE $table SET context_id=? WHERE participant_id=? AND event_id=? AND context_id=0")->execute([$context,$row['participant_id'],$row['event_id']]);
        }
        az_schema_marker($db,'event_options81');$db->commit();az_install_game_forms81($db);
    }catch(Throwable $error){if($db->inTransaction())$db->rollBack();throw $error;}
}
function st_ticket_category81(string $index,array $row,array $games): void {
    $base='ticket['.$index.']';
    echo '<details class="setup-row"'.(!$row?' open':'').'><summary>'.e($row['label']??'New ticket category').'</summary><div class="disclosure-content form-grid"><input type="hidden" name="'.e($base).'[id]" value="'.e($row['id']??'').'">';
    foreach(['label'=>['Category name','text',$row['label']??'',80],'price'=>['Price (₹) for this ticket','number',number_format(($row['price']??0)/100,2,'.',''),20],'capacity'=>['Category capacity (0 = unlimited)','number',$row['capacity']??0,7],'people'=>['People covered by one ticket','number',$row['people']??1,4]] as $key=>[$label,$type,$value,$max]){
        echo '<label class="field"><span>'.e($label).'</span><input name="'.e($base.'['.$key.']').'" type="'.$type.'" value="'.e((string)$value).'" maxlength="'.$max.'"'.($type==='number'?' min="'.($key==='people'?'1':'0').'" step="'.($key==='price'?'0.01':'1').'"':' data-setup-label').'></label>';
    }
    echo '<label class="field wide"><span>When should someone choose this ticket?</span><textarea name="'.e($base).'[description]" maxlength="500" rows="2" placeholder="For example: Two presenters entering together, or ages 12–16.">'.e($row['description']??'').'</textarea></label>';
    if($games){echo '<label class="field"><span>Available for game</span><select name="'.e($base).'[game]"><option value="">All games</option>';foreach($games as $game)echo '<option value="'.e($game['id']).'"'.(($row['game']??'')===$game['id']?' selected':'').'>'.e($game['label']).'</option>';echo '</select></label>';}
    else echo '<input type="hidden" name="'.e($base).'[game]" value="">';
    echo '<label class="check-field"><input type="checkbox" name="'.e($base).'[active]" value="1"'.(($row['active']??true)?' checked':'').'>Available for registration</label>';
    st_setup_row_actions();echo '</div></details>';
}
function st_game_form_links81(int $event,array $fields,bool $autosave=false): void {
    foreach(az_event_games($fields,false) as $game){
        echo '<div class="game-form-links81"><strong>'.e($game['label']).'</strong><div class="form-actions">';
        foreach(['registration'=>'Registration form','interest'=>'Interest form'] as $phase=>$label)echo '<a class="'.($phase==='registration'?'primary':'quiet').'-button"'.($autosave?' data-open-form-setup':'').' href="/form-setup.php?event_id='.$event.'&amp;phase='.$phase.'&amp;game='.e($game['id']).'">'.$label.' ↗</a>';
        echo '</div></div>';
    }
}

/** Give each game its own starting document without replacing existing customised forms. */
function az_install_game_forms81(PDO $db): void {
    if($db->query("SELECT value FROM cms_settings WHERE setting_key='game_forms81'")->fetchColumn())return;
    $db->beginTransaction();
    try{
        az_lock($db);
        if($db->query("SELECT value FROM cms_settings WHERE setting_key='game_forms81'")->fetchColumn()){$db->commit();return;}
        foreach($db->query("SELECT id,data FROM cms_content WHERE type='event' AND slug='joystick'")->fetchAll() as $event){
            $fields=json_decode($event['data'],true);$forms=json_decode($fields['game_forms']??'{}',true)?:[];
            foreach(az_event_games($fields,false) as $game)foreach(['registration','interest'] as $phase){
                $resolved=az_game_fields81($fields,$game['id'],$phase);
                foreach(['form','settings','title','intro','button'] as $suffix){$key=$phase.'_'.$suffix;if(!array_key_exists($key,$forms[$game['id']]??[])){
                    $forms[$game['id']][$key]=$resolved[$key]??($suffix==='form'?json_encode(az_registration_fields($resolved,$phase)):($suffix==='settings'?json_encode(az_form_settings($resolved,$phase)):''));
                    if($suffix==='title')$forms[$game['id']][$key].=' · '.$game['label'];
                }}
            }
            $fields['game_forms']=json_encode($forms,JSON_THROW_ON_ERROR);
            $db->prepare('UPDATE cms_content SET data=?,revision=revision+1 WHERE id=?')->execute([json_encode($fields,JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR),$event['id']]);
            $drafts=$db->prepare('SELECT participant_id,game_id,context_id FROM az_checkout_drafts WHERE event_id=? AND context_id<=0');$drafts->execute([$event['id']]);
            foreach($drafts as $draft)if(in_array($draft['game_id'],array_column(az_event_games($fields,false),'id'),true))$db->prepare('UPDATE az_checkout_drafts SET schema_hash=? WHERE event_id=? AND participant_id=? AND context_id=?')->execute([az_draft_schema_hash(az_game_fields81($fields,$draft['game_id'])),$event['id'],$draft['participant_id'],$draft['context_id']]);
        }
        az_schema_marker($db,'game_forms81');$db->commit();
    }catch(Throwable $error){if($db->inTransaction())$db->rollBack();throw $error;}
}

/** Called under the event-save lock, so a concurrent registration cannot lose its category. */
function az_validate_ticket_history81(PDO $db,int $event,string $previous,string $next): void {
    $ids=array_column(json_decode($next,true)?:[],'id');$used=$db->prepare('SELECT 1 FROM az_orders WHERE event_id=? AND ticket_type=? LIMIT 1');
    foreach(json_decode($previous,true)?:[] as $type)if(!in_array($type['id'],$ids,true)){
        $used->execute([$event,$type['id']]);if($used->fetchColumn())throw new RuntimeException('This ticket category already has registrations. Turn off Available for registration instead of removing it.');
    }
}
