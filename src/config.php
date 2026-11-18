<?php
declare(strict_types=1);
// Portal configuration. Set environment variables on the host; no secrets belong in the web root.
return [
    'env' => getenv('ANAZORI_ENV') ?: 'development',
    'url' => rtrim(getenv('ANAZORI_URL') ?: '', '/'),
    'base_path' => '/' . trim(getenv('ANAZORI_BASE_PATH') ?: '', '/'),
    'data_dir' => getenv('ANAZORI_DATA_DIR') ?: dirname(__DIR__) . '/.anazori-data',
    'starts_at' => getenv('ANAZORI_STARTS_AT') ?: '', // ISO 8601 with timezone, once dates are confirmed.
    'edition' => getenv('ANAZORI_EDITION') ?: '2026',
    'announcement' => 'The next chapter is taking shape. Explore the programme and register your interest.',
    // Event records come from the CMS database.
    'events' => [],
];
