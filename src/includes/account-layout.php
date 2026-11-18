<?php
function az_account_start(string $title,string $description=''): void {
 $activePage='account';$pageTitle=$title.' · Anazori';require __DIR__.'/header.php';
 echo '<section class="account-shell section-pad"><div class="account-story"><span class="account-orbit" aria-hidden="true">16</span><h1>Your festival.<br><span>Your way in.</span></h1><p>One account. Every experience. Your passes, all together.</p><a class="text-link" href="/events.php">Explore the programme ›</a></div><div class="account-card"><h2>'.e($title).'</h2>';
 if($description)echo '<p>'.e($description).'</p>';
}
function az_account_end(): void {echo '</div></section>';require __DIR__.'/footer.php';}
function az_account_error(string $error): void {if($error)echo '<p class="account-notice error" role="alert">'.e($error).'</p>';}
