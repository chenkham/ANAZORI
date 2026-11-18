<?php
function cms_seed(PDO $db): void {
 $db->beginTransaction();
 try {
  $insert=$db->prepare('INSERT INTO cms_content(type,slug,title,data,status,sort_order,created_by,updated_at) VALUES(?,?,?,?,?,?,0,?)');
  $paths=[];
  $add=function(string $type,string $slug,string $title,array $fields,int $order)use($insert,&$paths){$insert->execute([$type,$slug,$title,json_encode($fields,JSON_UNESCAPED_UNICODE),'PUBLISHED',$order,gmdate('c')]);foreach(['image','rules_pdf'] as $key)if(!empty($fields[$key]))$paths[]=$fields[$key];};
  $festival=require __DIR__.'/../config/festival.php';$i=0;
  foreach($festival['events'] as $slug=>$event){$defaults=[];foreach(cms_content_schema()['event']['fields'] as $k=>$d)$defaults[$k]=$d[2]??'';$event['featured']=$i<3?'1':'0';$add('event',$slug,$event['title'],array_replace($defaults,$event),++$i);}
  $photos=[['/assets/2026/stage.webp','Finding our rhythm','stage'],['/assets/2026/community.webp','The people make the festival','community'],['/assets/2026/culture.webp','A moment worth celebrating','celebrations'],['/assets/2026/together.webp','Ideas worth sharing','celebrations']];
  foreach(['6212','6213','6224','6326','6327','6218','6219','6220','6221','6238','6328','6258','6231','6243'] as $n=>$frame)$photos[]=['/assets/2026/archive-'.$frame.'.webp','Anazori 2024 · Archive frame '.($n+5),'archive'];
  foreach($photos as $n=>$p)$add('gallery','memory-'.($n+1),$p[1],['image'=>$p[0],'alt'=>$p[1],'category'=>$p[2],'year'=>'2024','description'=>''],$n);
  $people=require __DIR__.'/../config/cms-people.php';
  foreach($people as $n=>$p){$image=in_array($p['id'],[20,7,8,3,4,6],true)?'':$p['avatar'];$add('person','person-'.$p['id'],$p['name'],['group'=>$p['role'],'role'=>$p['status'],'image'=>$image,'description'=>'','link'=>$p['link']==='#'?'':$p['link'],'edition'=>'Previous edition'],$n);}
  $questions=[['What is Anazori?','Anazori is the festival of CCSA, Dibrugarh University, bringing technical exploration and cultural expression into one shared experience.'],['When is the next Anazori?','The dates are being finalised. Confirmed dates and schedules will appear here and on our official social channels.'],['How do I take part?','Explore the experiences and register your interest. Entry details and event rules will be published on each event page.'],['Can students from other colleges join?','Eligibility is published for each event. Check the event page for participation rules before planning your entry.'],['Want to collaborate or volunteer?','Use the contact links below to connect with the organising team. We would love to hear from you.']];
  foreach($questions as $n=>$q)$add('faq','question-'.($n+1),$q[0],['answer'=>$q[1]],$n);
  $defaults=cms_defaults();foreach(cms_setting_schema() as $fields)foreach($fields as $key=>$d)if(in_array($d[1],['image','video','audio','pdf'],true)&&$defaults[$key])$paths[]=$defaults[$key];
  $paths=array_unique(array_merge($paths,['/anazori.mp4','/into_musictrim.mp3','/into_music.mp3','/ANAZORI_V15.0_Brochure.pdf']));
  $media=$db->prepare('INSERT INTO cms_media(path,title,mime,size_bytes,uploaded_by,created_at) VALUES(?,?,?,?,0,?)');
  $mime=['jpg'=>'image/jpeg','jpeg'=>'image/jpeg','png'=>'image/png','webp'=>'image/webp','mp4'=>'video/mp4','mp3'=>'audio/mpeg','pdf'=>'application/pdf'];
  foreach($paths as $path){$file=__DIR__.'/..'.$path;$ext=strtolower(pathinfo($file,PATHINFO_EXTENSION));if(isset($mime[$ext]))$media->execute([$path,basename($path),$mime[$ext],is_file($file)?filesize($file):0,gmdate('c')]);}
  cms_put_setting('site',json_encode($defaults,JSON_UNESCAPED_UNICODE));cms_put_setting('settings_revision','1');cms_put_setting('seeded','1');$db->commit();
 }catch(Throwable $e){if($db->inTransaction())$db->rollBack();throw $e;}
}
