<?php
declare(strict_types=1);
require_once __DIR__.'/external-registration97.php';

/** Game identities remain stable when names and registration choices change. */
function az_event_games(array $fields, bool $activeOnly=true): array {
    $games=json_decode($fields['game_categories']??'[]',true)?:[];
    return array_values(array_filter($games,fn($game)=>!$activeOnly||!empty($game['active'])));
}

function az_validate_games(mixed $rows): string {
    if(!is_array($rows)||count($rows)>20)throw new InvalidArgumentException('Use up to 20 games for an event.');
    $games=[];$ids=[];
    foreach($rows as $row){
        if(!is_array($row))throw new InvalidArgumentException('Check the game choices.');
        $label=az_setup_text($row,'label',80);if($label==='')continue;
        $id=az_setup_text($row,'id',60)?:'game-'.bin2hex(random_bytes(6));
        if(!preg_match('/^[a-z0-9-]{3,60}$/D',$id)||isset($ids[$id]))throw new InvalidArgumentException('Reload the game editor before saving.');
        $url=az_google_form_url97($row['registration_url']??'',$label.' Google Form link');
        $ids[$id]=true;$game=['id'=>$id,'label'=>$label,'active'=>isset($row['active'])];
        if($url!=='')$game['registration_url']=$url;
        $games[]=$game;
    }
    return json_encode($games,JSON_THROW_ON_ERROR|JSON_UNESCAPED_UNICODE);
}

function az_selected_game(array $fields,string $id): ?array {
    $games=az_event_games($fields);
    if(!$games){if(az_event_games($fields,false))throw new RuntimeException('No game is currently accepting registrations.');if($id!=='')throw new InvalidArgumentException('This event does not have game choices.');return null;}
    foreach($games as $game)if($game['id']===$id)return $game;
    throw new InvalidArgumentException('Choose an available game for this event.');
}

function st_game_category_row(string $index,array $game): void {
    $name='games['.$index.']';
    echo '<details class="setup-row"'.(!$game?' open':'').'><summary>'.e($game['label']??'New game').'</summary><div class="disclosure-content form-grid">';
    echo '<input type="hidden" name="'.e($name).'[id]" value="'.e($game['id']??'').'">';
    echo '<label class="field"><span>Game name</span><input name="'.e($name).'[label]" value="'.e($game['label']??'').'" maxlength="80" data-setup-label></label>';
    echo '<label class="field wide"><span>Google Form link (optional)</span><input type="url" name="'.e($name).'[registration_url]" value="'.e($game['registration_url']??'').'" maxlength="2048" placeholder="https://forms.gle/..."><small>Use the published responder link. Blank uses the event’s default Google Form, if provided, or its Anazori registration form.</small></label>';
    echo '<label class="check-field"><input type="checkbox" name="'.e($name).'[active]" value="1"'.(($game['active']??true)?' checked':'').'>Accept registrations for this game</label>';
    st_setup_row_actions();echo '</div></details>';
}
