<?php
declare(strict_types=1);
require_once __DIR__.'/legal-defaults79.php';
require_once __DIR__.'/event-documents103.php';
// Field definitions are shared by the editor and server-side validation.
function cms_content_schema(): array {
 return [
  'event'=>['label'=>'Events','singular'=>'event','fields'=>[
   'short'=>['Short description','textarea'], 'description'=>['Full description','textarea'],
   'category'=>['Category','text','tech'], 'format'=>['Format / discipline','text'],
   'image'=>['Event photo / cover','image'], 'art'=>['Fallback illustration','select','code',['code'=>'Code','dance'=>'Stage','game'=>'Gaming','ball'=>'Sport','treasure'=>'Treasure Hunt','workshop'=>'Workshop','paper'=>'Research','art'=>'Art','ceremony'=>'Inauguration','parliament'=>'Youth Parliament','performance'=>'Cultural Night']],
   'color'=>['Accent colour','select','mint',['mint'=>'Cyan','lilac'=>'Violet','orange'=>'Coral','blue'=>'Blue','yellow'=>'Gold','pink'=>'Pink']],
   'label'=>['Artwork caption','text'], 'starts_at'=>['Starts at (India time)','datetime-local'], 'ends_at'=>['Ends at (India time)','datetime-local'],
   'reminder_window'=>['Ticket reminder timing','select','24h',['24h'=>'24 hours before the event','12h'=>'12 hours before the event']],
   'venue'=>['Venue','text','Dibrugarh University'], 'fees'=>['Entry fees / details','text','Coming soon'], 'prizes'=>['Prizes','textarea'],
   'eligibility'=>['Eligibility','textarea'], 'rules'=>['Rules and instructions','textarea'], 'rules_pdf'=>['Rules PDF','pdf'], 'event_documents'=>['Event PDFs','textarea',''],
   'contact'=>['Coordinator contact','textarea'], 'registration_url'=>['Google Form link (optional)','url'],
   'registration_mode'=>['Registration phase','select','interest',['interest'=>'Before registration — collect interest','open'=>'Registration open','closed'=>'Registration closed','completed'=>'Event completed','scheduled'=>'Automatic — use registration dates below','none'=>'No registration — programme item']],
   'game_categories'=>['Games and competitions','textarea','[]'],
   'registration_fee'=>['Registration fee (INR)','price','0'],
   'registration_kind'=>['Ticket covers','select','individual',['individual'=>'One individual','team'=>'One team']],
   'registration_opens'=>['Registration opens (India time)','datetime-local'], 'registration_closes'=>['Registration closes (India time)','datetime-local'],
   'registration_questions'=>['Extra registration questions — one required question per line','textarea'],
   'registration_note'=>['Registration instructions','textarea','Submit your details to the organising team. Your entry is subject to their confirmation.'],
   'interest_title'=>['Interest form heading','text','Count me in.'],'interest_intro'=>['Interest form introduction','textarea','Share your details with the organising team.'],'interest_button'=>['Interest submit button','text','Register my interest'],
   'registration_title'=>['Registration form heading','text','Make it official.'],'registration_intro'=>['Registration form description','textarea',''],'registration_button'=>['Registration submit button','text','Submit registration'],'registration_closed_message'=>['Closed registration message','textarea','Registration is currently closed. Contact the organising team for updates.'],
   'interest_open'=>['Allow interest submissions','checkbox','1'], 'featured'=>['Feature on the homepage','checkbox','1'], 'status_label'=>['Public status label','text','Programme preview']]],
  'gallery'=>['label'=>'Gallery','singular'=>'photo','fields'=>[
   'image'=>['Photo','image'], 'alt'=>['Image description for accessibility','text'], 'description'=>['Story / caption','textarea'], 'category'=>['Album / category','text','community'], 'year'=>['Edition label','text','2026']]],
  'person'=>['label'=>'Our people','singular'=>'person','fields'=>[
   'group'=>['Group (e.g. Management leads, Volunteers)','text','Volunteers'], 'role'=>['Role / designation','text'], 'image'=>['Portrait','image'],
   'description'=>['Biography','textarea'], 'link'=>['Profile link','url'], 'edition'=>['Edition label','text','2026']]],
  'sponsor'=>['label'=>'Sponsors','singular'=>'sponsor','fields'=>[
   'image'=>['Sponsor logo','image'], 'tier'=>['Partnership type','text','Community partner'], 'description'=>['Description','textarea'], 'link'=>['Website','url']]],
  'collaboration'=>['label'=>'Collaborations & partnerships','singular'=>'collaboration','fields'=>['image'=>['Partner logo','image'],'tier'=>['Partnership type','text','Community collaboration'],'description'=>['Description','textarea'],'link'=>['Website','url']]],
  'faq'=>['label'=>'Questions & answers','singular'=>'question','fields'=>['answer'=>['Answer','textarea']]],
 ];
}
function cms_setting_schema(): array {
 $schema=[
  'Identity & navigation'=>[
   'site_name'=>['Festival name','text','ANAZORI'],'year'=>['Festival year','text','2026'],'version'=>['Edition version','text','V16.0'],'tagline'=>['Tagline','text','Culture × Tech'],
   'logo'=>['Official logo','image','/assets/logo.png'],'meta_description'=>['Search description','textarea','Culture meets technology at Anazori, the festival of CCSA, Dibrugarh University.'],
   'nav_home'=>['Home navigation label','text','Home'],'nav_events'=>['Events navigation label','text','Explore events'],'nav_gallery'=>['Gallery navigation label','text','The memories'],'nav_people'=>['People navigation label','text','Our people'],
   'header_cta'=>['Header button','text','Find your thing']],
  'Festival dates'=>[
   'starts_at'=>['Festival starts (India time)','datetime-local',''],'ends_at'=>['Festival ends (India time)','datetime-local',''],
   'countdown_title'=>['Countdown heading','text','The next chapter starts in.'],'date_note'=>['Unannounced dates message','text','Dates dropping soon'],
   'show_countdown'=>['Show countdown & duration','checkbox','1']],
  'Entry sound'=>[
   'hero_music'=>['Entry sound file (optional; replaces video audio)','audio',''],'sound_default'=>['Play entry sound once per visit','checkbox','1']],
  'Hero & energy beam'=>[
   'presenter'=>['Presented by','text','CCSA, DIBRUGARH UNIVERSITY PRESENTS'],'hero_eyebrow'=>['Hero eyebrow','text','A TECHNO-CULTURAL CONFLUENCE'],
   'hero_line1'=>['Hero headline, first line','text','Old roots.'],'hero_line2'=>['Hero headline, second line','text','New frequencies.'],
   'hero_description'=>['Hero description','textarea',"A meeting of minds. A celebration of roots.\nOne festival to make something extraordinary."],
   'hero_cta'=>['Hero button text','text','Explore the experiences'],'hero_side'=>['Hero side caption','textarea',"MANY WORLDS.\nONE CONNECTION."],
   'beam_cycle'=>['Energy beam cycle (3–20 seconds)','number','6']],
  'Characters & motion'=>[
   'show_characters'=>['Show 2D character artwork','checkbox','1'],
   'scene_motion'=>['Animate character scenes and sponsor lighting','checkbox','1'],
   'show_passport'=>['Offer the optional festival passport','checkbox','1'],
   'stage_heading'=>['Programme heading','text','Find your'],
   'stage_accent'=>['Programme accent','text','moment.'],
    'character_pikachu'=>['Pikachu — retained artwork library','image',''],
    'character_gengar'=>['Gallery — secret guardian artwork','image',''],
   'character_mlbb'=>['Joystick — Mobile Legends character artwork','image',''],
    'character_charizard'=>['Gaming event — fantasy companion artwork','image',''],
   'character_sonic'=>['Sports character — optional replacement artwork','image',''],
    'character_stuart'=>['Culture — retained guitarist artwork','image',''],
   'character_doraemon'=>['Introduction character — optional replacement artwork','image',''],
   'character_minion'=>['Stage crew — optional replacement artwork','image',''],
    'character_dragon'=>['Tulika — fantasy illustration artwork','image','']],
  'Our spirit & festival film'=>[
   'show_intro'=>['Show introduction & festival film','checkbox','1'],
   'intro_line1'=>['Introduction heading','text','Some connections'],'intro_line2'=>['Introduction accent line','text','change everything.'],
   'intro_description'=>['Introduction copy','textarea','Between a beat and a breakthrough. Between where we come from and what comes next. Anazori brings culture and technology together at the Centre for Computer Science and Applications, Dibrugarh University.'],
   'intro_video'=>['Festival video (choose from Media library)','video','/assets/2026/hero-sound.mp4'],
   'intro_video_poster'=>['Video poster image (optional thumbnail)','image','/assets/2026/hero-poster.jpg'],
   'intro_video_url'=>['Or external video URL (YouTube, Vimeo, or MP4 link)','url',''],
   'intro_video_autoplay'=>['Autoplay video (muted) when in view','checkbox','1'],
   'intro_video_controls'=>['Show video player controls','checkbox','1'],
   'intro_video_loop'=>['Loop video continuously','checkbox','1']],
  'Experiences & culture'=>[
   'brochure_pdf'=>['Festival brochure PDF','pdf','/assets/2026/ANAZORI_V16_Brochure_Neon.pdf'],
   'show_events'=>['Show featured experiences','checkbox','1'],'events_line1'=>['Experiences heading','text','Different passions.'],'events_line2'=>['Experiences accent line','text','Same electric feeling.'],
   'programme_note'=>['Programme announcement','textarea','A taste of what Anazori is made of. Dates and entry details will be announced here.'],
   'show_culture'=>['Show culture / tech section','checkbox','1'],'culture_title'=>['Culture title','text','Culture.'],'culture_copy'=>['Culture description','textarea',"The stories we carry.\nThe rhythm that brings us together."],
   'tech_title'=>['Tech title','text','Tech.'],'tech_copy'=>['Tech description','textarea',"The questions we ask.\nThe futures we build together."]],
  'Memories'=>[
   'show_memories'=>['Show homepage memories','checkbox','1'],'memory_line1'=>['Memories heading','text','More than a fest.'],'memory_line2'=>['Memories accent line','text','A feeling.'],
   'memory_copy'=>['Memories description','textarea',"Real people. Unscripted moments.\nA few frames from our earlier chapters."],
   'memory_image1'=>['Main memory image','image','/assets/2026/culture.webp'],'memory_image2'=>['Side memory image','image','/assets/2026/community.webp']],
  'Sponsorship & community'=>[
   'partners_line1'=>['Partners section heading','text','Good company.'],'partners_line2'=>['Partners heading accent','text','Great possibilities.'],
   'show_collaborations'=>['Show collaborations & partnerships','checkbox','1'],'collaboration_label'=>['Collaborations label','text','IN GOOD COMPANY'],'collaboration_heading'=>['Collaborations heading','text','Collaborations & partnerships.'],'collaboration_copy'=>['Collaborations introduction','textarea','The communities and organisations we create with.'],
   'show_sponsors'=>['Show sponsors','checkbox','1'],'sponsor_heading'=>['Sponsorship heading','text','Big ideas need good company.'],
   'sponsor_copy'=>['Sponsorship copy','textarea','Put your brand where fresh ideas, culture, and the next generation come together. Let’s create something worth remembering.'],
   'sponsor_cta'=>['Sponsorship button','text','Become a sponsor'],'sponsor_email'=>['Sponsorship email','email','anazori.ccsadu@gmail.com'],
   'volunteer_heading'=>['Volunteer heading','text','Be the energy behind it.'],
   'volunteer_copy'=>['Volunteer copy','textarea','From the first hello to the final encore. Bring your curiosity, meet your people, and help make Anazori happen.'],
   'volunteer_link'=>['Volunteer application link (optional)','url','']],
  'Visit & contact'=>[
   'contact_person1'=>['First contact name','text',''],'contact_email1'=>['First contact email','email',''],'contact_phone1'=>['First contact phone','text',''],
   'contact_person2'=>['Second contact name','text',''],'contact_email2'=>['Second contact email','email',''],'contact_phone2'=>['Second contact phone','text',''],
   'visit_line1'=>['Visit heading','text','All roads lead'],'visit_line2'=>['Visit heading accent','text','to connection.'],
   'show_visit'=>['Show venue & questions','checkbox','1'],'venue'=>['Venue name','text','Centre for Computer Science and Applications'],
   'address'=>['Venue address','textarea','Dibrugarh University, Assam, India'],'map_url'=>['Map link','url','https://www.google.com/maps/search/?api=1&query=Centre+for+Computer+Science+and+Applications+Dibrugarh+University'],
   'email'=>['Contact email','email','anazori.ccsadu@gmail.com'],'instagram'=>['Instagram','url','https://instagram.com/anazoriccsa'],
   'facebook'=>['Facebook','url','https://www.facebook.com/AnazoriDU/'],'institution_url'=>['Institution website','url','https://ccsdu.in/']],
  'Privacy policy & terms'=>[
   'privacy_content'=>['Privacy policy — use ## before a section heading','textarea',az_legal_defaults79()['privacy']],
   'terms_content'=>['Terms — use ## before a section heading','textarea',az_legal_defaults79()['terms']]],
  'Page headings & footer'=>[
   'events_page_line1'=>['Events page heading','text','Find your'],'events_page_line2'=>['Events page accent','text','kind of extraordinary.'],
   'events_page_copy'=>['Events page introduction','textarea','For the builders. The performers. The players. And everyone who refuses to be just one thing.'],
   'gallery_page_line1'=>['Gallery page heading','text','Some moments.'],'gallery_page_line2'=>['Gallery page accent','text','Forever Anazori.'],
   'gallery_page_copy'=>['Gallery introduction','textarea','The energy. The people. The little in-between moments. A look back, before we make what comes next.'],
   'people_page_line1'=>['People page heading','text','Good things start'],'people_page_line2'=>['People page accent','text','with great people.'],
   'people_page_copy'=>['People introduction','textarea','The faculty, students, volunteers, and shared ambition behind the Anazori story.'],
   'people_notice'=>['People announcement','textarea','The previous-edition committee is retained below. The confirmed team for the next chapter will be published here.'],
   'footer_line1'=>['Footer heading','text',"Let’s make"],'footer_line2'=>['Footer accent line','text','some memories.'],'footer_tagline'=>['Footer tagline','text','Made of culture. Made for tomorrow.']],
 ];
 foreach($schema as &$fields)foreach(['presenter','hero_eyebrow','hero_side','programme_note','volunteer_heading','volunteer_copy','volunteer_link'] as $key)unset($fields[$key]);unset($fields);
 return $schema;
}
function cms_defaults(): array {$out=['hero_video'=>'/assets/2026/hero-sound.mp4','hero_poster'=>'/assets/2026/hero-poster.jpg'];foreach(cms_setting_schema() as $fields)foreach($fields as $key=>$field)$out[$key]=$field[2]??'';return $out;}
