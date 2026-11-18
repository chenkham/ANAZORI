<?php
require_once __DIR__.'/festival.php';
set_security_headers();
$navParticipant=az_participant();
$pageTitle=$pageTitle??'ANAZORI 2026 — Culture × Tech';
$pageDescription=$pageDescription??setting('meta_description');
$activePage=$activePage??'home';
$legacyAdmin=$activePage==='admin';
$siteOrigin=rtrim(az_config()['site_url'] ?: ((!empty($_SERVER['HTTPS'])&&$_SERVER['HTTPS']!=='off'?'https':'http').'://'.($_SERVER['HTTP_HOST']??'localhost')), '/');
// A rebuilt entry must not keep importing chunks from a previous cached build.
$publicAssetUrl=static function(string $name): string {
    $path=__DIR__.'/../assets/2026/'.$name;
    return '/assets/2026/'.$name.'?v='.(is_file($path)?filemtime($path):'2026.82');
};
?>
<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#08090e">
<title><?= e($pageTitle) ?></title><meta name="description" content="<?= e($pageDescription) ?>">
<meta property="og:title" content="<?= e($pageTitle) ?>"><meta property="og:description" content="<?= e($pageDescription) ?>"><meta property="og:type" content="website"><meta property="og:image" content="<?= e($siteOrigin) ?>/assets/2026/social-v16.png"><meta property="og:image:width" content="1200"><meta property="og:image:height" content="630"><meta name="twitter:card" content="summary_large_image">
<?php if(!$legacyAdmin): ?><style><?php readfile(__DIR__.'/../assets/2026/loader81.css'); ?></style><script src="<?= e($publicAssetUrl('loader81.js')) ?>"></script><?php endif; ?>
<link rel="icon" href="<?= e(setting('logo')) ?>">
<?php if($legacyAdmin): ?><link rel="stylesheet" href="/assets/2026/admin.css"><?php endif; ?>
<link rel="preload" href="/assets/fonts/satoshi/Satoshi-Variable.woff2" as="font" type="font/woff2" crossorigin>
<?php if($activePage==='home'): ?><link rel="preload" href="/assets/fonts/bilbo/Bilbo-Regular.woff2" as="font" type="font/woff2" crossorigin><?php endif; ?>
<link rel="stylesheet" href="<?= e($publicAssetUrl('public.css')) ?>">
<?php if(in_array($activePage,['certificate','certificate-verify'],true)): ?><link rel="stylesheet" href="<?= e($publicAssetUrl('certificate/certificate.css')) ?>"><link rel="stylesheet" href="<?= e($publicAssetUrl('certificate/goc-certificate.css')) ?>"><?php endif; ?>
<script type="module" src="<?= e($publicAssetUrl('site.js')) ?>"></script>
</head><body class="reference-background page-<?= e($activePage) ?><?= $legacyAdmin?' legacy-admin':'' ?><?= setting('show_characters','1')==='1'?' has-festival-characters':'' ?>" data-scene-motion="<?= setting('scene_motion','1')==='1'?'on':'off' ?>">
<?php if(!$legacyAdmin)require __DIR__.'/pixel-loader81.php'; ?>
<noscript><style>body{opacity:1!important}[data-reveal]{opacity:1!important;transform:none!important}.passport-invitation,[data-discovery]{display:none!important}.programme-layout .programme-index{display:block!important}</style></noscript>
<?php if(!$legacyAdmin): require __DIR__.'/glass-background.php'; endif; ?>
<a class="skip-link" href="#main">Skip to content</a>
<div class="reading-progress" aria-hidden="true"></div>
<?php
$navItems=['home'=>['/',setting('nav_home')],'events'=>['/events.php',setting('nav_events')],'gallery'=>['/gallery.php',setting('nav_gallery')],'teams'=>['/teams.php',setting('nav_people')]];
?>
<header class="site-header"><div class="nav-shell">
<svg class="nav-trim" viewBox="0 0 1200 84" preserveAspectRatio="none" fill="none" aria-hidden="true"><path d="M38 7H1162l23 23v24l-23 23H38L15 54V30Z" vector-effect="non-scaling-stroke"/><path d="M30 24V16h26m1088 0h26v8M30 60v8h26m1088 0h26v-8" vector-effect="non-scaling-stroke"/></svg>
<a class="brand" href="/" aria-label="<?= e(setting('site_name')) ?> home"><img class="official-logo" src="<?= e(setting('logo')) ?>" width="50" height="56" alt="Anazori official logo"><span class="brand-wordmark"><?= anazori_wordmark() ?></span></a>
<nav class="desktop-nav" aria-label="Main navigation"><?php foreach($navItems as $key=>$item): ?><a href="<?= $item[0] ?>" <?= $activePage===$key?'aria-current="page"':'' ?>><span><?= e($item[1]) ?></span></a><?php endforeach; ?></nav>
<a class="header-cta" href="<?= $navParticipant?'/dashboard.php':'/account.php' ?>"><?= $navParticipant?'My festival':'Sign in' ?></a><button class="menu-button" aria-label="Open navigation" aria-controls="mobile-menu" aria-expanded="false"><span></span><span></span></button>
</div></header>
<div class="menu-backdrop" hidden aria-hidden="true"></div>
<nav id="mobile-menu" class="mobile-nav" aria-label="Mobile navigation" hidden>
 <span class="menu-coordinate">ANAZORI / <?= e(festival_version()) ?></span><span class="menu-trace" aria-hidden="true"></span>
 <?php foreach($navItems as $key=>$item): ?><a href="<?= $item[0] ?>" <?= $activePage===$key?'aria-current="page"':'' ?>><?= e($item[1]) ?></a><?php endforeach; ?>
 <a href="<?= $navParticipant?'/dashboard.php':'/account.php' ?>"><?= $navParticipant?'My festival':'Sign in' ?></a><a href="/#visit">Plan your visit</a>
</nav>
<main id="main">
