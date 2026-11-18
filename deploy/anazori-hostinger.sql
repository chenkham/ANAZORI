-- ANAZORI: Clean hosting installation: staff access, content and forms preserved; participant accounts and their operational data excluded
-- Import into a NEW EMPTY MySQL/MariaDB database selected in phpMyAdmin.
-- No CREATE DATABASE, USE, DROP, account grants or server-specific definers.
SET NAMES utf8mb4;

SET SQL_MODE='NO_AUTO_VALUE_ON_ZERO';

SET FOREIGN_KEY_CHECKS=0;


CREATE TABLE `az_auth_events` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `user_kind` varchar(20) NOT NULL,
  `user_id` int(11) DEFAULT NULL,
  `user_name` varchar(150) NOT NULL,
  `email` varchar(254) NOT NULL,
  `event` varchar(40) NOT NULL,
  `method` varchar(30) NOT NULL,
  `success` int(11) NOT NULL,
  `occurred_at` varchar(40) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `az_auth_events_email` (`email`,`id`),
  KEY `az_auth_events_user` (`user_kind`,`user_id`,`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;



CREATE TABLE `az_challenges` (
  `id` varchar(64) NOT NULL,
  `kind` varchar(30) NOT NULL,
  `user_kind` varchar(20) NOT NULL,
  `user_id` int(11) NOT NULL,
  `email_hash` varchar(64) NOT NULL,
  `code_hash` varchar(64) NOT NULL,
  `expires_at` bigint(20) NOT NULL,
  `attempts` int(11) NOT NULL DEFAULT 0,
  `consumed` int(11) NOT NULL DEFAULT 0,
  `created_at` bigint(20) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `az_challenges_user` (`user_kind`,`user_id`,`kind`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;



CREATE TABLE `az_checkins` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `ticket_id` int(11) NOT NULL,
  `staff_id` int(11) NOT NULL,
  `checked_at` varchar(40) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_ticket_id` (`ticket_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;



CREATE TABLE `az_checkout_drafts` (
  `participant_id` int(11) NOT NULL,
  `event_id` int(11) NOT NULL,
  `context_id` int(11) NOT NULL DEFAULT 0,
  `answers_json` mediumtext NOT NULL,
  `game_id` varchar(60) NOT NULL DEFAULT '',
  `team_name` varchar(120) NOT NULL DEFAULT '',
  `schema_hash` varchar(64) NOT NULL,
  `revision` int(11) NOT NULL DEFAULT 0,
  `updated_at` varchar(40) NOT NULL,
  `type_id` varchar(60) NOT NULL DEFAULT '',
  `state_json` text DEFAULT NULL,
  `request_id` varchar(80) NOT NULL DEFAULT '',
  PRIMARY KEY (`participant_id`,`event_id`,`context_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;



CREATE TABLE `az_draft_files` (
  `file_id` int(11) NOT NULL,
  `participant_id` int(11) NOT NULL,
  `event_id` int(11) NOT NULL,
  `context_id` int(11) NOT NULL DEFAULT 0,
  PRIMARY KEY (`file_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;



CREATE TABLE `az_event_reconciliations` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `event_id` int(11) NOT NULL,
  `statement_date` varchar(10) NOT NULL,
  `bank_total` bigint(20) NOT NULL,
  `recorded_total` bigint(20) NOT NULL,
  `difference` bigint(20) NOT NULL,
  `reference` varchar(150) NOT NULL,
  `note` mediumtext NOT NULL,
  `created_by` int(11) NOT NULL,
  `created_at` varchar(40) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;



CREATE TABLE `az_form_payment_refs` (
  `reference_hash` varchar(64) NOT NULL,
  `order_id` int(11) NOT NULL,
  `reference` varchar(100) NOT NULL,
  PRIMARY KEY (`reference_hash`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;



CREATE TABLE `az_form_responses` (
  `order_id` int(11) NOT NULL,
  `revision` int(11) NOT NULL DEFAULT 1,
  `raw_answers` mediumtext NOT NULL,
  `schema_json` mediumtext NOT NULL,
  `settings_json` mediumtext NOT NULL,
  `score` int(11) NOT NULL DEFAULT 0,
  `max_score` int(11) NOT NULL DEFAULT 0,
  `review_note` mediumtext DEFAULT NULL,
  `reviewed_by` int(11) DEFAULT NULL,
  `reviewed_at` varchar(40) DEFAULT NULL,
  PRIMARY KEY (`order_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;



CREATE TABLE `az_form_reviews` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `order_id` int(11) NOT NULL,
  `staff_id` int(11) NOT NULL,
  `action` varchar(30) NOT NULL,
  `note` mediumtext NOT NULL,
  `revision` int(11) NOT NULL,
  `created_at` varchar(40) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;



CREATE TABLE `az_mail_deliveries89` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `started_at` bigint(20) NOT NULL,
  `status` varchar(20) NOT NULL DEFAULT 'reserved',
  PRIMARY KEY (`id`),
  KEY `az_mail_budget89` (`started_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;



CREATE TABLE `az_mail_jobs89` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `dedupe_key` varchar(64) NOT NULL,
  `kind` varchar(40) NOT NULL,
  `payload` mediumtext NOT NULL,
  `order_id` int(11) DEFAULT NULL,
  `participant_id` int(11) DEFAULT NULL,
  `event_time` bigint(20) NOT NULL DEFAULT 0,
  `status` varchar(20) NOT NULL DEFAULT 'pending',
  `attempts` int(11) NOT NULL DEFAULT 0,
  `available_at` bigint(20) NOT NULL,
  `lease_until` bigint(20) NOT NULL DEFAULT 0,
  `claim_token` varchar(64) DEFAULT NULL,
  `created_at` bigint(20) NOT NULL,
  `sent_at` bigint(20) DEFAULT NULL,
  `last_error` varchar(40) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `dedupe_key` (`dedupe_key`),
  KEY `az_mail_ready89` (`status`,`available_at`,`id`),
  KEY `az_mail_reminder89` (`order_id`,`kind`,`event_time`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;



CREATE TABLE `az_manual_payments` (
  `order_id` int(11) NOT NULL,
  `method_snapshot` mediumtext NOT NULL,
  `reference` varchar(100) DEFAULT NULL,
  `reference_key` varchar(64) DEFAULT NULL,
  `paid_on` varchar(10) DEFAULT NULL,
  `proof_id` int(11) DEFAULT NULL,
  `status` varchar(20) NOT NULL DEFAULT 'AWAITING_PROOF',
  `revision` int(11) NOT NULL DEFAULT 1,
  `reviewed_by` int(11) DEFAULT NULL,
  `reviewed_at` varchar(40) DEFAULT NULL,
  `review_note` mediumtext DEFAULT NULL,
  `received_amount` int(11) NOT NULL DEFAULT 0,
  `created_at` varchar(40) NOT NULL,
  PRIMARY KEY (`order_id`),
  UNIQUE KEY `unique_reference_key` (`reference_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;



CREATE TABLE `az_orders` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `public_id` varchar(40) NOT NULL,
  `participant_id` int(11) NOT NULL,
  `event_id` int(11) NOT NULL,
  `event_slug` varchar(100) NOT NULL,
  `ticket_type` varchar(60) NOT NULL,
  `snapshot` mediumtext NOT NULL,
  `answers` mediumtext NOT NULL,
  `quantity` int(11) NOT NULL,
  `unit_price` int(11) NOT NULL,
  `amount` int(11) NOT NULL,
  `currency` varchar(3) NOT NULL DEFAULT 'INR',
  `state` varchar(30) NOT NULL,
  `environment` varchar(10) NOT NULL,
  `gateway_order` varchar(100) DEFAULT NULL,
  `gateway_payment` varchar(100) DEFAULT NULL,
  `provider_state` varchar(30) DEFAULT NULL,
  `expires_at` bigint(20) NOT NULL,
  `created_at` varchar(40) NOT NULL,
  `updated_at` varchar(40) NOT NULL,
  `provider` varchar(20) NOT NULL DEFAULT 'razorpay',
  `checkout_url` mediumtext DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_public_id` (`public_id`),
  UNIQUE KEY `unique_gateway_payment` (`gateway_payment`),
  UNIQUE KEY `unique_gateway_order` (`gateway_order`),
  KEY `st_orders_event_participant` (`event_id`,`participant_id`,`id`),
  KEY `az_orders_capacity` (`event_id`,`ticket_type`,`environment`,`state`,`expires_at`),
  KEY `az_orders_participant` (`participant_id`,`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;



CREATE TABLE `az_participants` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `email` varchar(254) NOT NULL,
  `name` varchar(100) NOT NULL,
  `password_hash` varchar(255) DEFAULT NULL,
  `google_sub` varchar(255) DEFAULT NULL,
  `email_verified` int(11) NOT NULL DEFAULT 0,
  `active` int(11) NOT NULL DEFAULT 1,
  `session_version` int(11) NOT NULL DEFAULT 0,
  `created_at` varchar(40) NOT NULL,
  `phone` varchar(25) NOT NULL DEFAULT '',
  `profile_completed` int(11) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_email` (`email`),
  UNIQUE KEY `unique_google_sub` (`google_sub`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;



CREATE TABLE `az_payment_proofs` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `order_id` int(11) NOT NULL,
  `filename` varchar(100) NOT NULL,
  `mime` varchar(40) NOT NULL,
  `size_bytes` int(11) NOT NULL,
  `sha256` varchar(64) NOT NULL,
  `reference` varchar(100) NOT NULL,
  `paid_on` varchar(10) NOT NULL,
  `uploaded_at` varchar(40) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_filename` (`filename`),
  KEY `az_proof_order` (`order_id`,`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;



CREATE TABLE `az_payment_reviews` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `order_id` int(11) NOT NULL,
  `staff_id` int(11) NOT NULL,
  `action` varchar(30) NOT NULL,
  `proof_id` int(11) DEFAULT NULL,
  `note` mediumtext NOT NULL,
  `created_at` varchar(40) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `az_review_order` (`order_id`,`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;



CREATE TABLE `az_rate_limits` (
  `rate_key` varchar(64) NOT NULL,
  `attempts` int(11) NOT NULL,
  `expires_at` bigint(20) NOT NULL,
  PRIMARY KEY (`rate_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;



CREATE TABLE `az_refunds` (
  `refund_id` varchar(100) NOT NULL,
  `order_id` int(11) NOT NULL,
  `amount` int(11) NOT NULL,
  `received_at` varchar(40) NOT NULL,
  PRIMARY KEY (`refund_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;



CREATE TABLE `az_registration_files` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `order_id` int(11) DEFAULT NULL,
  `submission_id` int(11) DEFAULT NULL,
  `participant_id` int(11) DEFAULT NULL,
  `event_id` int(11) NOT NULL,
  `field_id` varchar(60) NOT NULL,
  `label` varchar(120) NOT NULL,
  `original_name` varchar(200) NOT NULL,
  `filename` varchar(100) NOT NULL,
  `mime` varchar(100) NOT NULL,
  `size_bytes` int(11) NOT NULL,
  `sha256` varchar(64) NOT NULL,
  `active` int(11) NOT NULL DEFAULT 1,
  `created_at` varchar(40) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `filename` (`filename`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;



CREATE TABLE `az_ticket_blocks` (
  `ticket_id` int(11) NOT NULL,
  `previous_status` varchar(20) NOT NULL,
  `reason` mediumtext NOT NULL,
  `blocked_by` int(11) NOT NULL,
  `blocked_at` varchar(40) NOT NULL,
  `unblocked_by` int(11) DEFAULT NULL,
  `unblocked_at` varchar(40) DEFAULT NULL,
  PRIMARY KEY (`ticket_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;



CREATE TABLE `az_tickets` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `ticket_id` varchar(40) NOT NULL,
  `order_id` int(11) NOT NULL,
  `participant_id` int(11) NOT NULL,
  `event_id` int(11) NOT NULL,
  `token` varchar(140) NOT NULL,
  `status` varchar(20) NOT NULL DEFAULT 'VALID',
  `checked_at` varchar(40) DEFAULT NULL,
  `checked_by` int(11) DEFAULT NULL,
  `created_at` varchar(40) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_token` (`token`),
  UNIQUE KEY `unique_ticket_id` (`ticket_id`),
  KEY `az_tickets_participant` (`participant_id`),
  KEY `az_tickets_order` (`order_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;



CREATE TABLE `az_webhooks` (
  `event_id` varchar(150) NOT NULL,
  `received_at` varchar(40) NOT NULL,
  PRIMARY KEY (`event_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;



CREATE TABLE `cms_audit` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL,
  `username` varchar(100) NOT NULL,
  `action` varchar(100) NOT NULL,
  `detail` mediumtext NOT NULL,
  `created_at` varchar(40) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;



CREATE TABLE `cms_content` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `type` varchar(30) NOT NULL,
  `slug` varchar(100) NOT NULL,
  `title` varchar(255) NOT NULL,
  `data` mediumtext NOT NULL,
  `status` varchar(20) NOT NULL DEFAULT 'DRAFT',
  `sort_order` int(11) NOT NULL DEFAULT 0,
  `created_by` int(11) NOT NULL DEFAULT 0,
  `revision` int(11) NOT NULL DEFAULT 1,
  `updated_at` varchar(40) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_type_slug` (`type`,`slug`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


INSERT INTO `cms_content` (`id`,`type`,`slug`,`title`,`data`,`status`,`sort_order`,`created_by`,`revision`,`updated_at`) VALUES (1,'event','goc','Game of Codes','{\"short\":\"Code the future.\",\"description\":\"Solve algorithmic problems, debug code and optimise solutions under time constraints. Game of Codes brings solo participants and groups together for a preliminary round followed by the final.\",\"category\":\"tech\",\"format\":\"Coding Competition \\/ Solo and group\",\"image\":\"\\/assets\\/2026\\/together.webp\",\"art\":\"code\",\"color\":\"mint\",\"label\":\"Code the future\",\"starts_at\":\"2026-11-01T21:30\",\"ends_at\":\"2026-11-04T17:30\",\"venue\":\"Indra miri, Dibrugarh University\",\"fees\":\"200 INR\",\"prizes\":\"will be announce later\",\"eligibility\":\"Solo and group participation.\",\"rules\":\"A preliminary round, online or offline, is followed by the final round.\\r\\nParticipants solve algorithmic problems, debug code and optimise solutions within the time limit.\\r\\nSolutions are evaluated for accuracy, efficiency and creativity.\",\"rules_pdf\":\"\\/assets\\/2026\\/ANAZORI_V16_Brochure_Neon.pdf\",\"contact\":\"chenkham chowlu - 9395535864\\r\\nroktim -\",\"registration_url\":\"https:\\/\\/www.ccsdu.in\\/\",\"registration_mode\":\"interest\",\"game_categories\":\"[]\",\"registration_fee\":\"200\",\"registration_kind\":\"team\",\"registration_opens\":\"2026-10-23T22:03\",\"registration_closes\":\"\",\"registration_note\":\"Submit your details to the organising team. Your entry is subject to their confirmation.\",\"registration_closed_message\":\"Registration is currently closed. Contact the organising team for updates.\",\"interest_open\":\"1\",\"featured\":\"0\",\"status_label\":\"Programme preview\",\"ticket_types\":\"[{\\\"id\\\":\\\"standard-entry\\\",\\\"label\\\":\\\"Event ticket\\\",\\\"price\\\":20000,\\\"capacity\\\":0,\\\"active\\\":true,\\\"game\\\":\\\"\\\"}]\",\"payment_methods\":\"[]\",\"registration_form\":\"[{\\\"id\\\":\\\"college\\\",\\\"label\\\":\\\"College \\\\\\/ organisation\\\",\\\"type\\\":\\\"text\\\",\\\"required\\\":true,\\\"options\\\":[],\\\"help\\\":\\\"\\\",\\\"placeholder\\\":\\\"\\\",\\\"game\\\":\\\"\\\",\\\"allowed_values\\\":[]},{\\\"id\\\":\\\"phone\\\",\\\"label\\\":\\\"Contact number\\\",\\\"type\\\":\\\"tel\\\",\\\"required\\\":true,\\\"options\\\":[],\\\"help\\\":\\\"\\\",\\\"placeholder\\\":\\\"\\\",\\\"game\\\":\\\"\\\",\\\"allowed_values\\\":[]}]\",\"interest_form\":\"[{\\\"id\\\":\\\"college\\\",\\\"label\\\":\\\"College \\\\\\/ organisation\\\",\\\"type\\\":\\\"text\\\",\\\"required\\\":true,\\\"options\\\":[],\\\"help\\\":\\\"\\\",\\\"placeholder\\\":\\\"\\\",\\\"game\\\":\\\"\\\",\\\"allowed_values\\\":[]}]\",\"registration_questions\":\"\",\"interest_title\":\"Count me in.\",\"interest_intro\":\"Share your details with the organising team.\",\"interest_button\":\"Register my interest\",\"registration_title\":\"Make it official.\",\"registration_intro\":\"\",\"registration_button\":\"Submit registration\",\"registration_settings\":\"\",\"interest_settings\":\"\",\"form_workflow\":\"1\",\"registration_form_draft\":{\"questions\":[{\"id\":\"college\",\"label\":\"College \\/ organisation\",\"type\":\"image\",\"options\":[],\"help\":\"\",\"game\":\"\",\"media\":\"\",\"condition_field\":\"\",\"condition_value\":\"\",\"required\":false,\"rows\":[],\"allowed_values\":[],\"answer_key\":[],\"other\":false,\"shuffle\":false}],\"settings\":{\"accepting\":true,\"one_response\":true,\"allow_edit\":true,\"progress\":true,\"shuffle\":false,\"quiz\":false,\"show_score\":false,\"confirmation\":\"Your application is with the event coordinators. Your ticket will appear after approval.\"},\"title\":\"Make it official.\",\"intro\":\"\",\"button\":\"Submit registration\"},\"interest_form_draft\":\"\"}','PUBLISHED',4,0,13,'2026-10-10T19:28:23+00:00');

INSERT INTO `cms_content` (`id`,`type`,`slug`,`title`,`data`,`status`,`sort_order`,`created_by`,`revision`,`updated_at`) VALUES (2,'event','youth-parliament','Youth Parliament','{\"short\":\"Voices that shape tomorrow.\",\"description\":\"A simulated parliamentary session where students take the role of lawmakers to debate, question and deliberate on issues that matter to the nation and its youth. Youth Parliament makes its debut at Anazori V16.0.\",\"category\":\"culture\",\"format\":\"Mock Parliament Session\",\"image\":\"\",\"art\":\"parliament\",\"color\":\"blue\",\"label\":\"Voices that shape tomorrow\",\"starts_at\":\"\",\"ends_at\":\"\",\"venue\":\"Dibrugarh University\",\"fees\":\"Coming soon\",\"prizes\":\"\",\"eligibility\":\"\",\"rules\":\"Participants take the role of members of parliament in a mock house session.\\nFocus areas: current affairs, policy debates, youth and social issues.\\nEvaluation considers content, argumentation, public speaking and parliamentary conduct.\",\"rules_pdf\":\"\",\"contact\":\"\",\"registration_url\":\"\",\"interest_open\":\"1\",\"featured\":\"1\",\"status_label\":\"Programme preview\",\"symbol\":\"♫\",\"form_workflow\":\"1\",\"registration_kind\":\"individual\"}','PUBLISHED',8,0,5,'2026-10-07T19:59:39+00:00');

INSERT INTO `cms_content` (`id`,`type`,`slug`,`title`,`data`,`status`,`sort_order`,`created_by`,`revision`,`updated_at`) VALUES (3,'event','joystick','Joystick','{\"short\":\"Play. Compete. Conquer.\",\"description\":\"The battleground for BGMI, MLBB and Free Fire. Teams compete in high-energy matches where skill, teamwork and strategy decide the winner.\",\"category\":\"gaming\",\"format\":\"E-sports Group Stages\",\"image\":\"\",\"art\":\"game\",\"color\":\"lilac\",\"label\":\"Play. Compete. Conquer\",\"starts_at\":\"\",\"ends_at\":\"\",\"venue\":\"Dibrugarh University\",\"fees\":\"Coming soon\",\"prizes\":\"\",\"eligibility\":\"Team participation.\",\"rules\":\"\",\"rules_pdf\":\"\",\"contact\":\"\",\"registration_url\":\"\",\"registration_mode\":\"interest\",\"game_categories\":\"[{\\\"id\\\":\\\"mobile-legends\\\",\\\"label\\\":\\\"Mobile Legends\\\",\\\"active\\\":true},{\\\"id\\\":\\\"bgmi\\\",\\\"label\\\":\\\"BGMI\\\",\\\"active\\\":true},{\\\"id\\\":\\\"free-fire\\\",\\\"label\\\":\\\"Free Fire\\\",\\\"active\\\":true}]\",\"registration_fee\":\"0\",\"registration_kind\":\"individual\",\"registration_opens\":\"\",\"registration_closes\":\"\",\"registration_note\":\"Submit your details to the organising team. Your entry is subject to their confirmation.\",\"registration_closed_message\":\"Registration is currently closed. Contact the organising team for updates.\",\"interest_open\":\"1\",\"featured\":\"1\",\"status_label\":\"Programme preview\",\"ticket_types\":\"[{\\\"id\\\":\\\"standard-entry\\\",\\\"game\\\":\\\"\\\",\\\"label\\\":\\\"Event entry\\\",\\\"description\\\":\\\"\\\",\\\"people\\\":1,\\\"price\\\":0,\\\"capacity\\\":0,\\\"active\\\":true}]\",\"ticket_categories_enabled\":\"1\",\"payment_methods\":\"[]\",\"game_forms\":\"{\\\"mobile-legends\\\":{\\\"registration_form\\\":\\\"[{\\\\\\\"id\\\\\\\":\\\\\\\"college\\\\\\\",\\\\\\\"label\\\\\\\":\\\\\\\"College \\\\\\\\\\\\\\/ organisation\\\\\\\",\\\\\\\"type\\\\\\\":\\\\\\\"text\\\\\\\",\\\\\\\"required\\\\\\\":true,\\\\\\\"options\\\\\\\":[]},{\\\\\\\"id\\\\\\\":\\\\\\\"phone\\\\\\\",\\\\\\\"label\\\\\\\":\\\\\\\"Contact number\\\\\\\",\\\\\\\"type\\\\\\\":\\\\\\\"tel\\\\\\\",\\\\\\\"required\\\\\\\":true,\\\\\\\"options\\\\\\\":[]}]\\\",\\\"registration_settings\\\":\\\"{\\\\\\\"accepting\\\\\\\":true,\\\\\\\"one_response\\\\\\\":true,\\\\\\\"allow_edit\\\\\\\":true,\\\\\\\"progress\\\\\\\":true,\\\\\\\"shuffle\\\\\\\":false,\\\\\\\"quiz\\\\\\\":false,\\\\\\\"show_score\\\\\\\":false,\\\\\\\"confirmation\\\\\\\":\\\\\\\"Your application is with the event coordinators. Your ticket will appear after approval.\\\\\\\"}\\\",\\\"registration_title\\\":\\\" \\\\u00b7 Mobile Legends\\\",\\\"registration_intro\\\":\\\"\\\",\\\"registration_button\\\":\\\"\\\",\\\"interest_form\\\":\\\"[{\\\\\\\"id\\\\\\\":\\\\\\\"college\\\\\\\",\\\\\\\"label\\\\\\\":\\\\\\\"College \\\\\\\\\\\\\\/ organisation\\\\\\\",\\\\\\\"type\\\\\\\":\\\\\\\"text\\\\\\\",\\\\\\\"required\\\\\\\":true,\\\\\\\"options\\\\\\\":[]}]\\\",\\\"interest_settings\\\":\\\"{\\\\\\\"accepting\\\\\\\":true,\\\\\\\"one_response\\\\\\\":true,\\\\\\\"allow_edit\\\\\\\":true,\\\\\\\"progress\\\\\\\":true,\\\\\\\"shuffle\\\\\\\":false,\\\\\\\"quiz\\\\\\\":false,\\\\\\\"show_score\\\\\\\":false,\\\\\\\"confirmation\\\\\\\":\\\\\\\"Thank you for sharing your interest.\\\\\\\"}\\\",\\\"interest_title\\\":\\\" \\\\u00b7 Mobile Legends\\\",\\\"interest_intro\\\":\\\"\\\",\\\"interest_button\\\":\\\"\\\"},\\\"bgmi\\\":{\\\"registration_form\\\":\\\"[{\\\\\\\"id\\\\\\\":\\\\\\\"college\\\\\\\",\\\\\\\"label\\\\\\\":\\\\\\\"College \\\\\\\\\\\\\\/ organisation\\\\\\\",\\\\\\\"type\\\\\\\":\\\\\\\"text\\\\\\\",\\\\\\\"required\\\\\\\":true,\\\\\\\"options\\\\\\\":[]},{\\\\\\\"id\\\\\\\":\\\\\\\"phone\\\\\\\",\\\\\\\"label\\\\\\\":\\\\\\\"Contact number\\\\\\\",\\\\\\\"type\\\\\\\":\\\\\\\"tel\\\\\\\",\\\\\\\"required\\\\\\\":true,\\\\\\\"options\\\\\\\":[]}]\\\",\\\"registration_settings\\\":\\\"{\\\\\\\"accepting\\\\\\\":true,\\\\\\\"one_response\\\\\\\":true,\\\\\\\"allow_edit\\\\\\\":true,\\\\\\\"progress\\\\\\\":true,\\\\\\\"shuffle\\\\\\\":false,\\\\\\\"quiz\\\\\\\":false,\\\\\\\"show_score\\\\\\\":false,\\\\\\\"confirmation\\\\\\\":\\\\\\\"Your application is with the event coordinators. Your ticket will appear after approval.\\\\\\\"}\\\",\\\"registration_title\\\":\\\" \\\\u00b7 BGMI\\\",\\\"registration_intro\\\":\\\"\\\",\\\"registration_button\\\":\\\"\\\",\\\"interest_form\\\":\\\"[{\\\\\\\"id\\\\\\\":\\\\\\\"college\\\\\\\",\\\\\\\"label\\\\\\\":\\\\\\\"College \\\\\\\\\\\\\\/ organisation\\\\\\\",\\\\\\\"type\\\\\\\":\\\\\\\"text\\\\\\\",\\\\\\\"required\\\\\\\":true,\\\\\\\"options\\\\\\\":[]}]\\\",\\\"interest_settings\\\":\\\"{\\\\\\\"accepting\\\\\\\":true,\\\\\\\"one_response\\\\\\\":true,\\\\\\\"allow_edit\\\\\\\":true,\\\\\\\"progress\\\\\\\":true,\\\\\\\"shuffle\\\\\\\":false,\\\\\\\"quiz\\\\\\\":false,\\\\\\\"show_score\\\\\\\":false,\\\\\\\"confirmation\\\\\\\":\\\\\\\"Thank you for sharing your interest.\\\\\\\"}\\\",\\\"interest_title\\\":\\\" \\\\u00b7 BGMI\\\",\\\"interest_intro\\\":\\\"\\\",\\\"interest_button\\\":\\\"\\\"},\\\"free-fire\\\":{\\\"registration_form\\\":\\\"[{\\\\\\\"id\\\\\\\":\\\\\\\"college\\\\\\\",\\\\\\\"label\\\\\\\":\\\\\\\"College \\\\\\\\\\\\\\/ organisation\\\\\\\",\\\\\\\"type\\\\\\\":\\\\\\\"text\\\\\\\",\\\\\\\"required\\\\\\\":true,\\\\\\\"options\\\\\\\":[]},{\\\\\\\"id\\\\\\\":\\\\\\\"phone\\\\\\\",\\\\\\\"label\\\\\\\":\\\\\\\"Contact number\\\\\\\",\\\\\\\"type\\\\\\\":\\\\\\\"tel\\\\\\\",\\\\\\\"required\\\\\\\":true,\\\\\\\"options\\\\\\\":[]}]\\\",\\\"registration_settings\\\":\\\"{\\\\\\\"accepting\\\\\\\":true,\\\\\\\"one_response\\\\\\\":true,\\\\\\\"allow_edit\\\\\\\":true,\\\\\\\"progress\\\\\\\":true,\\\\\\\"shuffle\\\\\\\":false,\\\\\\\"quiz\\\\\\\":false,\\\\\\\"show_score\\\\\\\":false,\\\\\\\"confirmation\\\\\\\":\\\\\\\"Your application is with the event coordinators. Your ticket will appear after approval.\\\\\\\"}\\\",\\\"registration_title\\\":\\\" \\\\u00b7 Free Fire\\\",\\\"registration_intro\\\":\\\"\\\",\\\"registration_button\\\":\\\"\\\",\\\"interest_form\\\":\\\"[{\\\\\\\"id\\\\\\\":\\\\\\\"college\\\\\\\",\\\\\\\"label\\\\\\\":\\\\\\\"College \\\\\\\\\\\\\\/ organisation\\\\\\\",\\\\\\\"type\\\\\\\":\\\\\\\"text\\\\\\\",\\\\\\\"required\\\\\\\":true,\\\\\\\"options\\\\\\\":[]}]\\\",\\\"interest_settings\\\":\\\"{\\\\\\\"accepting\\\\\\\":true,\\\\\\\"one_response\\\\\\\":true,\\\\\\\"allow_edit\\\\\\\":true,\\\\\\\"progress\\\\\\\":true,\\\\\\\"shuffle\\\\\\\":false,\\\\\\\"quiz\\\\\\\":false,\\\\\\\"show_score\\\\\\\":false,\\\\\\\"confirmation\\\\\\\":\\\\\\\"Thank you for sharing your interest.\\\\\\\"}\\\",\\\"interest_title\\\":\\\" \\\\u00b7 Free Fire\\\",\\\"interest_intro\\\":\\\"\\\",\\\"interest_button\\\":\\\"\\\"}}\",\"registration_form\":\"\",\"interest_form\":\"\",\"registration_questions\":\"\",\"interest_title\":\"Count me in.\",\"interest_intro\":\"Share your details with the organising team.\",\"interest_button\":\"Register my interest\",\"registration_title\":\"Make it official.\",\"registration_intro\":\"\",\"registration_button\":\"Submit registration\",\"registration_settings\":\"\",\"interest_settings\":\"\",\"form_workflow\":\"1\",\"registration_form_draft\":\"\",\"interest_form_draft\":\"\"}','PUBLISHED',5,0,10,'2026-10-11T16:55:58+00:00');

INSERT INTO `cms_content` (`id`,`type`,`slug`,`title`,`data`,`status`,`sort_order`,`created_by`,`revision`,`updated_at`) VALUES (4,'event','treasure-hunt','Treasure Hunt','{\"short\":\"Clues. Puzzles. Glory.\",\"description\":\"A team-based hunt of clues, puzzles, strategy and problem-solving. Race against the clock, decode each clue and reach the treasure first.\",\"category\":\"adventure\",\"format\":\"Team Challenge\",\"image\":\"\",\"art\":\"treasure\",\"color\":\"yellow\",\"label\":\"Clues. Puzzles. Glory\",\"starts_at\":\"\",\"ends_at\":\"\",\"venue\":\"Dibrugarh University\",\"fees\":\"Coming soon\",\"prizes\":\"\",\"eligibility\":\"Team participation.\",\"rules\":\"Work with your team to decode the clues, solve the puzzles and follow the trail to the treasure within the challenge time.\",\"rules_pdf\":\"\",\"contact\":\"\",\"registration_url\":\"\",\"interest_open\":\"1\",\"featured\":\"0\",\"status_label\":\"Programme preview\",\"symbol\":\"?\",\"registration_form\":\"[{\\\"id\\\":\\\"college\\\",\\\"label\\\":\\\"College \\\\\\/ organisation\\\",\\\"type\\\":\\\"text\\\",\\\"required\\\":true,\\\"options\\\":[]},{\\\"id\\\":\\\"phone\\\",\\\"label\\\":\\\"Contact number\\\",\\\"type\\\":\\\"tel\\\",\\\"required\\\":true,\\\"options\\\":[]},{\\\"id\\\":\\\"team-name\\\",\\\"label\\\":\\\"Team name\\\",\\\"type\\\":\\\"text\\\",\\\"required\\\":true,\\\"options\\\":[]},{\\\"id\\\":\\\"issued-team-id\\\",\\\"label\\\":\\\"Issued team ID\\\",\\\"type\\\":\\\"text\\\",\\\"required\\\":true,\\\"options\\\":[],\\\"help\\\":\\\"Enter the ID supplied by the Treasure Hunt organisers.\\\",\\\"placeholder\\\":\\\"Your issued ID\\\"}]\",\"interest_form\":\"[{\\\"id\\\":\\\"college\\\",\\\"label\\\":\\\"College \\\\\\/ organisation\\\",\\\"type\\\":\\\"text\\\",\\\"required\\\":true,\\\"options\\\":[]},{\\\"id\\\":\\\"team-name\\\",\\\"label\\\":\\\"Team name\\\",\\\"type\\\":\\\"text\\\",\\\"required\\\":true,\\\"options\\\":[]},{\\\"id\\\":\\\"issued-team-id\\\",\\\"label\\\":\\\"Issued team ID\\\",\\\"type\\\":\\\"text\\\",\\\"required\\\":true,\\\"options\\\":[],\\\"help\\\":\\\"Enter the ID supplied by the Treasure Hunt organisers.\\\",\\\"placeholder\\\":\\\"Your issued ID\\\"}]\",\"form_workflow\":\"1\",\"registration_kind\":\"individual\"}','PUBLISHED',6,0,6,'2026-10-07T19:59:39+00:00');

INSERT INTO `cms_content` (`id`,`type`,`slug`,`title`,`data`,`status`,`sort_order`,`created_by`,`revision`,`updated_at`) VALUES (5,'event','workshops','Technical Workshop','{\"short\":\"Learn, build, lead.\",\"description\":\"Hands-on workshops in Web Development, Machine Learning and Cloud Computing. Sessions focus on practical application, helping participants leave with project-ready skills, new knowledge and working outputs.\",\"category\":\"tech\",\"format\":\"Web Development \\/ Machine Learning \\/ Cloud Computing\",\"image\":\"\",\"art\":\"workshop\",\"color\":\"yellow\",\"label\":\"Learn, build, lead\",\"starts_at\":\"\",\"ends_at\":\"\",\"venue\":\"Dibrugarh University\",\"fees\":\"Coming soon\",\"prizes\":\"\",\"eligibility\":\"\",\"rules\":\"\",\"rules_pdf\":\"\",\"contact\":\"\",\"registration_url\":\"\",\"interest_open\":\"1\",\"featured\":\"0\",\"status_label\":\"Programme preview\",\"symbol\":\"↗\",\"form_workflow\":\"1\",\"registration_kind\":\"individual\"}','PUBLISHED',2,0,5,'2026-10-07T19:59:39+00:00');

INSERT INTO `cms_content` (`id`,`type`,`slug`,`title`,`data`,`status`,`sort_order`,`created_by`,`revision`,`updated_at`) VALUES (6,'event','paper-presentation','Paper Presentation','{\"short\":\"Ideas worth sharing.\",\"description\":\"A platform for innovators and researchers to share work in computing and applied sciences, including emerging technologies, applied projects and case studies.\",\"category\":\"tech\",\"format\":\"Solo or pair \\/ 8-10 minutes with Q&A\",\"image\":\"\",\"art\":\"paper\",\"color\":\"pink\",\"label\":\"Ideas worth sharing\",\"starts_at\":\"\",\"ends_at\":\"\",\"venue\":\"Dibrugarh University\",\"fees\":\"Coming soon\",\"prizes\":\"\",\"eligibility\":\"Solo or pair participation.\",\"rules\":\"Presentations last 8-10 minutes and include Q&A with experts.\\r\\nFocus areas: emerging technologies, applied projects and case studies.\\r\\nEvaluation considers originality, depth of research and presentation skills.\",\"rules_pdf\":\"\",\"contact\":\"\",\"registration_url\":\"\",\"registration_mode\":\"open\",\"game_categories\":\"[]\",\"registration_fee\":\"200.00\",\"registration_kind\":\"team\",\"registration_opens\":\"\",\"registration_closes\":\"\",\"registration_note\":\"Submit your details to the organising team. Your entry is subject to their confirmation.\",\"registration_closed_message\":\"Registration is currently closed. Contact the organising team for updates.\",\"interest_open\":\"0\",\"featured\":\"0\",\"status_label\":\"Programme preview\",\"ticket_types\":\"[{\\\"id\\\":\\\"standard-entry\\\",\\\"game\\\":\\\"\\\",\\\"label\\\":\\\"Event ticket\\\",\\\"description\\\":\\\"\\\",\\\"people\\\":1,\\\"price\\\":20000,\\\"capacity\\\":0,\\\"active\\\":true},{\\\"id\\\":\\\"type-b3a2c34f29bb\\\",\\\"game\\\":\\\"\\\",\\\"label\\\":\\\"new\\\",\\\"description\\\":\\\"only chose when single\\\",\\\"people\\\":1,\\\"price\\\":10000,\\\"capacity\\\":0,\\\"active\\\":true}]\",\"ticket_categories_enabled\":\"1\",\"payment_methods\":\"[]\",\"game_forms\":\"\",\"registration_form\":\"[{\\\"id\\\":\\\"college\\\",\\\"label\\\":\\\"Number of Participants\\\",\\\"type\\\":\\\"radio\\\",\\\"required\\\":true,\\\"options\\\":[\\\"1\\\",\\\"2\\\"],\\\"rows\\\":[],\\\"help\\\":\\\"enter number of participants\\\",\\\"placeholder\\\":\\\"\\\",\\\"game\\\":\\\"\\\",\\\"allowed_values\\\":[],\\\"condition_field\\\":\\\"\\\",\\\"condition_value\\\":\\\"\\\",\\\"min\\\":\\\"\\\",\\\"max\\\":\\\"\\\",\\\"validation\\\":\\\"\\\",\\\"validation_value\\\":\\\"\\\",\\\"validation_message\\\":\\\"\\\",\\\"other\\\":false,\\\"shuffle\\\":false,\\\"media\\\":\\\"\\\",\\\"payment_upi\\\":\\\"\\\",\\\"payment_ticket\\\":\\\"\\\",\\\"file_types\\\":\\\"images-pdf\\\",\\\"file_count\\\":1,\\\"file_size\\\":5,\\\"purpose\\\":\\\"\\\",\\\"low_label\\\":\\\"\\\",\\\"high_label\\\":\\\"\\\",\\\"points\\\":0,\\\"answer_key\\\":[],\\\"feedback\\\":\\\"\\\"},{\\\"id\\\":\\\"phone\\\",\\\"label\\\":\\\"Name of the participants\\\",\\\"type\\\":\\\"text\\\",\\\"required\\\":true,\\\"options\\\":[],\\\"rows\\\":[],\\\"help\\\":\\\"\\\",\\\"placeholder\\\":\\\"\\\",\\\"game\\\":\\\"\\\",\\\"allowed_values\\\":[],\\\"condition_field\\\":\\\"\\\",\\\"condition_value\\\":\\\"\\\",\\\"min\\\":\\\"\\\",\\\"max\\\":\\\"\\\",\\\"validation\\\":\\\"\\\",\\\"validation_value\\\":\\\"\\\",\\\"validation_message\\\":\\\"\\\",\\\"other\\\":false,\\\"shuffle\\\":false,\\\"media\\\":\\\"\\\",\\\"payment_upi\\\":\\\"\\\",\\\"payment_ticket\\\":\\\"\\\",\\\"file_types\\\":\\\"images-pdf\\\",\\\"file_count\\\":1,\\\"file_size\\\":5,\\\"purpose\\\":\\\"\\\",\\\"low_label\\\":\\\"\\\",\\\"high_label\\\":\\\"\\\",\\\"points\\\":0,\\\"answer_key\\\":[],\\\"feedback\\\":\\\"\\\"},{\\\"id\\\":\\\"field-8130f373-1a86-4e94-927f-4e87ca8d9a60\\\",\\\"label\\\":\\\"Name of the institution\\\",\\\"type\\\":\\\"text\\\",\\\"required\\\":true,\\\"options\\\":[],\\\"rows\\\":[],\\\"help\\\":\\\"\\\",\\\"placeholder\\\":\\\"\\\",\\\"game\\\":\\\"\\\",\\\"allowed_values\\\":[],\\\"condition_field\\\":\\\"\\\",\\\"condition_value\\\":\\\"\\\",\\\"min\\\":\\\"\\\",\\\"max\\\":\\\"\\\",\\\"validation\\\":\\\"\\\",\\\"validation_value\\\":\\\"\\\",\\\"validation_message\\\":\\\"\\\",\\\"other\\\":false,\\\"shuffle\\\":false,\\\"media\\\":\\\"\\\",\\\"payment_upi\\\":\\\"\\\",\\\"payment_ticket\\\":\\\"\\\",\\\"file_types\\\":\\\"images-pdf\\\",\\\"file_count\\\":1,\\\"file_size\\\":5,\\\"purpose\\\":\\\"\\\",\\\"low_label\\\":\\\"\\\",\\\"high_label\\\":\\\"\\\",\\\"points\\\":0,\\\"answer_key\\\":[],\\\"feedback\\\":\\\"\\\"},{\\\"id\\\":\\\"field-0cf18ace-73db-4f1b-9ea1-6fb1be5481ef\\\",\\\"label\\\":\\\"phone number\\\",\\\"type\\\":\\\"text\\\",\\\"required\\\":true,\\\"options\\\":[],\\\"rows\\\":[],\\\"help\\\":\\\"\\\",\\\"placeholder\\\":\\\"\\\",\\\"game\\\":\\\"\\\",\\\"allowed_values\\\":[],\\\"condition_field\\\":\\\"\\\",\\\"condition_value\\\":\\\"\\\",\\\"min\\\":\\\"\\\",\\\"max\\\":\\\"\\\",\\\"validation\\\":\\\"\\\",\\\"validation_value\\\":\\\"\\\",\\\"validation_message\\\":\\\"\\\",\\\"other\\\":false,\\\"shuffle\\\":false,\\\"media\\\":\\\"\\\",\\\"payment_upi\\\":\\\"\\\",\\\"payment_ticket\\\":\\\"\\\",\\\"file_types\\\":\\\"images-pdf\\\",\\\"file_count\\\":1,\\\"file_size\\\":5,\\\"purpose\\\":\\\"\\\",\\\"low_label\\\":\\\"\\\",\\\"high_label\\\":\\\"\\\",\\\"points\\\":0,\\\"answer_key\\\":[],\\\"feedback\\\":\\\"\\\"},{\\\"id\\\":\\\"field-ee3cdbf2-6d40-4471-a837-f800bb3eebe5\\\",\\\"label\\\":\\\"email id\\\",\\\"type\\\":\\\"text\\\",\\\"required\\\":true,\\\"options\\\":[],\\\"rows\\\":[],\\\"help\\\":\\\"\\\",\\\"placeholder\\\":\\\"\\\",\\\"game\\\":\\\"\\\",\\\"allowed_values\\\":[],\\\"condition_field\\\":\\\"\\\",\\\"condition_value\\\":\\\"\\\",\\\"min\\\":\\\"\\\",\\\"max\\\":\\\"\\\",\\\"validation\\\":\\\"\\\",\\\"validation_value\\\":\\\"\\\",\\\"validation_message\\\":\\\"\\\",\\\"other\\\":false,\\\"shuffle\\\":false,\\\"media\\\":\\\"\\\",\\\"payment_upi\\\":\\\"\\\",\\\"payment_ticket\\\":\\\"\\\",\\\"file_types\\\":\\\"images-pdf\\\",\\\"file_count\\\":1,\\\"file_size\\\":5,\\\"purpose\\\":\\\"\\\",\\\"low_label\\\":\\\"\\\",\\\"high_label\\\":\\\"\\\",\\\"points\\\":0,\\\"answer_key\\\":[],\\\"feedback\\\":\\\"\\\"},{\\\"id\\\":\\\"field-81ffbc68-d089-40b5-ba22-1243473e700c\\\",\\\"label\\\":\\\"topic for presentation\\\",\\\"type\\\":\\\"description\\\",\\\"required\\\":false,\\\"options\\\":[],\\\"rows\\\":[],\\\"help\\\":\\\"the presentation topic will be here.\\\",\\\"placeholder\\\":\\\"\\\",\\\"game\\\":\\\"\\\",\\\"allowed_values\\\":[],\\\"condition_field\\\":\\\"\\\",\\\"condition_value\\\":\\\"\\\",\\\"min\\\":\\\"\\\",\\\"max\\\":\\\"\\\",\\\"validation\\\":\\\"\\\",\\\"validation_value\\\":\\\"\\\",\\\"validation_message\\\":\\\"\\\",\\\"other\\\":false,\\\"shuffle\\\":false,\\\"media\\\":\\\"\\\",\\\"payment_upi\\\":\\\"\\\",\\\"payment_ticket\\\":\\\"\\\",\\\"file_types\\\":\\\"images-pdf\\\",\\\"file_count\\\":1,\\\"file_size\\\":5,\\\"purpose\\\":\\\"\\\",\\\"low_label\\\":\\\"\\\",\\\"high_label\\\":\\\"\\\",\\\"points\\\":0,\\\"answer_key\\\":[],\\\"feedback\\\":\\\"\\\"},{\\\"id\\\":\\\"field-f6103246-e7b7-483c-9d53-19d9d97c1118\\\",\\\"label\\\":\\\"your topic\\\",\\\"type\\\":\\\"radio\\\",\\\"required\\\":true,\\\"options\\\":[\\\"technical topic\\\",\\\"non technical topic\\\"],\\\"rows\\\":[],\\\"help\\\":\\\"\\\",\\\"placeholder\\\":\\\"\\\",\\\"game\\\":\\\"\\\",\\\"allowed_values\\\":[],\\\"condition_field\\\":\\\"\\\",\\\"condition_value\\\":\\\"\\\",\\\"min\\\":\\\"\\\",\\\"max\\\":\\\"\\\",\\\"validation\\\":\\\"\\\",\\\"validation_value\\\":\\\"\\\",\\\"validation_message\\\":\\\"\\\",\\\"other\\\":false,\\\"shuffle\\\":false,\\\"media\\\":\\\"\\\",\\\"payment_upi\\\":\\\"\\\",\\\"payment_ticket\\\":\\\"\\\",\\\"file_types\\\":\\\"images-pdf\\\",\\\"file_count\\\":1,\\\"file_size\\\":5,\\\"purpose\\\":\\\"\\\",\\\"low_label\\\":\\\"\\\",\\\"high_label\\\":\\\"\\\",\\\"points\\\":0,\\\"answer_key\\\":[],\\\"feedback\\\":\\\"\\\"},{\\\"id\\\":\\\"field-4b1f9e79-a925-4823-b8ce-313e6c22efcf\\\",\\\"label\\\":\\\"registration fees\\\",\\\"type\\\":\\\"radio\\\",\\\"required\\\":true,\\\"options\\\":[\\\"70 for single\\\",\\\"120 for group\\\"],\\\"rows\\\":[],\\\"help\\\":\\\"\\\",\\\"placeholder\\\":\\\"\\\",\\\"game\\\":\\\"\\\",\\\"allowed_values\\\":[],\\\"condition_field\\\":\\\"\\\",\\\"condition_value\\\":\\\"\\\",\\\"min\\\":\\\"\\\",\\\"max\\\":\\\"\\\",\\\"validation\\\":\\\"\\\",\\\"validation_value\\\":\\\"\\\",\\\"validation_message\\\":\\\"\\\",\\\"other\\\":false,\\\"shuffle\\\":false,\\\"media\\\":\\\"\\\",\\\"payment_upi\\\":\\\"\\\",\\\"payment_ticket\\\":\\\"\\\",\\\"file_types\\\":\\\"images-pdf\\\",\\\"file_count\\\":1,\\\"file_size\\\":5,\\\"purpose\\\":\\\"\\\",\\\"low_label\\\":\\\"\\\",\\\"high_label\\\":\\\"\\\",\\\"points\\\":0,\\\"answer_key\\\":[],\\\"feedback\\\":\\\"\\\"},{\\\"id\\\":\\\"field-684d57ca-9e3f-41ea-b51c-fe03b1a09f3f\\\",\\\"label\\\":\\\"Qr payment\\\",\\\"type\\\":\\\"image\\\",\\\"required\\\":false,\\\"options\\\":[],\\\"rows\\\":[],\\\"help\\\":\\\"\\\",\\\"placeholder\\\":\\\"\\\",\\\"game\\\":\\\"\\\",\\\"allowed_values\\\":[],\\\"condition_field\\\":\\\"\\\",\\\"condition_value\\\":\\\"\\\",\\\"min\\\":\\\"\\\",\\\"max\\\":\\\"\\\",\\\"validation\\\":\\\"\\\",\\\"validation_value\\\":\\\"\\\",\\\"validation_message\\\":\\\"\\\",\\\"other\\\":false,\\\"shuffle\\\":false,\\\"media\\\":\\\"\\\\\\/uploads\\\\\\/media\\\\\\/2885673fba912b704b76d27f571c65adf5e4.png\\\",\\\"payment_upi\\\":\\\"\\\",\\\"payment_ticket\\\":\\\"type-b3a2c34f29bb\\\",\\\"file_types\\\":\\\"images-pdf\\\",\\\"file_count\\\":1,\\\"file_size\\\":5,\\\"purpose\\\":\\\"payment\\\",\\\"low_label\\\":\\\"\\\",\\\"high_label\\\":\\\"\\\",\\\"points\\\":0,\\\"answer_key\\\":[],\\\"feedback\\\":\\\"\\\"},{\\\"id\\\":\\\"field-84904c62-db49-4363-b37b-7ac0f64bb5b0\\\",\\\"label\\\":\\\"payment screen sort\\\",\\\"type\\\":\\\"file\\\",\\\"required\\\":true,\\\"options\\\":[],\\\"rows\\\":[],\\\"help\\\":\\\"\\\",\\\"placeholder\\\":\\\"\\\",\\\"game\\\":\\\"\\\",\\\"allowed_values\\\":[],\\\"condition_field\\\":\\\"\\\",\\\"condition_value\\\":\\\"\\\",\\\"min\\\":\\\"\\\",\\\"max\\\":\\\"\\\",\\\"validation\\\":\\\"\\\",\\\"validation_value\\\":\\\"\\\",\\\"validation_message\\\":\\\"\\\",\\\"other\\\":false,\\\"shuffle\\\":false,\\\"media\\\":\\\"\\\",\\\"payment_upi\\\":\\\"\\\",\\\"payment_ticket\\\":\\\"\\\",\\\"file_types\\\":\\\"images-pdf\\\",\\\"file_count\\\":1,\\\"file_size\\\":5,\\\"purpose\\\":\\\"\\\",\\\"low_label\\\":\\\"\\\",\\\"high_label\\\":\\\"\\\",\\\"points\\\":0,\\\"answer_key\\\":[],\\\"feedback\\\":\\\"\\\"}]\",\"interest_form\":\"\",\"registration_questions\":\"\",\"interest_title\":\"Count me in.\",\"interest_intro\":\"Share your details with the organising team.\",\"interest_button\":\"Register my interest\",\"registration_title\":\"paper presentation\",\"registration_intro\":\"this is demo for paper presentation\",\"registration_button\":\"Submit registration\",\"registration_settings\":\"{\\\"accepting\\\":true,\\\"one_response\\\":true,\\\"allow_edit\\\":true,\\\"progress\\\":true,\\\"shuffle\\\":false,\\\"quiz\\\":false,\\\"show_score\\\":false,\\\"confirmation\\\":\\\"Your application is with the event coordinators. Your ticket will appear after approval.\\\"}\",\"interest_settings\":\"\",\"form_workflow\":\"1\",\"registration_form_draft\":{\"questions\":[{\"id\":\"college\",\"label\":\"Number of Participants\",\"type\":\"radio\",\"options\":[\"1\",\"2\"],\"help\":\"enter number of participants\",\"game\":\"\",\"allowed_values\":[],\"condition_field\":\"\",\"condition_value\":\"\",\"other\":false,\"shuffle\":false,\"points\":\"0\",\"answer_key\":[],\"feedback\":\"\",\"required\":true,\"rows\":[]},{\"id\":\"phone\",\"label\":\"Name of the participants\",\"type\":\"text\",\"options\":[],\"help\":\"\",\"placeholder\":\"\",\"game\":\"\",\"allowed_values\":[],\"purpose\":\"\",\"condition_field\":\"\",\"condition_value\":\"\",\"validation\":\"\",\"validation_value\":\"\",\"min\":\"\",\"max\":\"\",\"validation_message\":\"\",\"points\":\"0\",\"answer_key\":[],\"feedback\":\"\",\"required\":true,\"rows\":[],\"other\":false,\"shuffle\":false},{\"id\":\"field-8130f373-1a86-4e94-927f-4e87ca8d9a60\",\"label\":\"Name of the institution\",\"type\":\"text\",\"options\":[],\"help\":\"\",\"placeholder\":\"\",\"game\":\"\",\"allowed_values\":[],\"purpose\":\"\",\"condition_field\":\"\",\"condition_value\":\"\",\"validation\":\"\",\"validation_value\":\"\",\"min\":\"\",\"max\":\"\",\"validation_message\":\"\",\"points\":\"0\",\"answer_key\":[],\"feedback\":\"\",\"required\":true,\"rows\":[],\"other\":false,\"shuffle\":false},{\"id\":\"field-0cf18ace-73db-4f1b-9ea1-6fb1be5481ef\",\"label\":\"phone number\",\"type\":\"text\",\"options\":[],\"help\":\"\",\"placeholder\":\"\",\"game\":\"\",\"allowed_values\":[],\"purpose\":\"\",\"condition_field\":\"\",\"condition_value\":\"\",\"validation\":\"\",\"validation_value\":\"\",\"min\":\"\",\"max\":\"\",\"validation_message\":\"\",\"points\":\"0\",\"answer_key\":[],\"feedback\":\"\",\"required\":true,\"rows\":[],\"other\":false,\"shuffle\":false},{\"id\":\"field-ee3cdbf2-6d40-4471-a837-f800bb3eebe5\",\"label\":\"email id\",\"type\":\"text\",\"options\":[],\"help\":\"\",\"placeholder\":\"\",\"game\":\"\",\"allowed_values\":[],\"purpose\":\"\",\"condition_field\":\"\",\"condition_value\":\"\",\"validation\":\"\",\"validation_value\":\"\",\"min\":\"\",\"max\":\"\",\"validation_message\":\"\",\"points\":\"0\",\"answer_key\":[],\"feedback\":\"\",\"required\":true,\"rows\":[],\"other\":false,\"shuffle\":false},{\"id\":\"field-81ffbc68-d089-40b5-ba22-1243473e700c\",\"label\":\"topic for presentation\",\"type\":\"description\",\"options\":[],\"help\":\"the presentation topic will be here.\",\"game\":\"\",\"condition_field\":\"\",\"condition_value\":\"\",\"required\":false,\"rows\":[],\"allowed_values\":[],\"answer_key\":[],\"other\":false,\"shuffle\":false},{\"id\":\"field-f6103246-e7b7-483c-9d53-19d9d97c1118\",\"label\":\"your topic\",\"type\":\"radio\",\"options\":[\"technical topic\",\"non technical topic\"],\"help\":\"\",\"game\":\"\",\"allowed_values\":[],\"condition_field\":\"\",\"condition_value\":\"\",\"other\":false,\"shuffle\":false,\"points\":\"0\",\"answer_key\":[],\"feedback\":\"\",\"required\":true,\"rows\":[]},{\"id\":\"field-4b1f9e79-a925-4823-b8ce-313e6c22efcf\",\"label\":\"registration fees\",\"type\":\"radio\",\"options\":[\"70 for single\",\"120 for group\"],\"help\":\"\",\"game\":\"\",\"allowed_values\":[],\"condition_field\":\"\",\"condition_value\":\"\",\"other\":false,\"shuffle\":false,\"points\":\"0\",\"answer_key\":[],\"feedback\":\"\",\"required\":true,\"rows\":[]},{\"id\":\"field-684d57ca-9e3f-41ea-b51c-fe03b1a09f3f\",\"label\":\"Qr payment\",\"type\":\"image\",\"options\":[],\"help\":\"\",\"game\":\"\",\"media\":\"\\/uploads\\/media\\/2885673fba912b704b76d27f571c65adf5e4.png\",\"payment_ticket\":\"type-b3a2c34f29bb\",\"payment_upi\":\"\",\"purpose\":\"payment\",\"condition_field\":\"\",\"condition_value\":\"\",\"required\":false,\"rows\":[],\"allowed_values\":[],\"answer_key\":[],\"other\":false,\"shuffle\":false},{\"id\":\"field-845f39e9-1237-43fd-8565-2b06a3817e38\",\"label\":\"Qr payment \",\"type\":\"image\",\"options\":[],\"help\":\"\",\"game\":\"\",\"media\":\"\\/anazori.mp4\",\"payment_ticket\":\"standard-entry\",\"payment_upi\":\"\",\"purpose\":\"payment\",\"condition_field\":\"\",\"condition_value\":\"\",\"required\":false,\"rows\":[],\"allowed_values\":[],\"answer_key\":[],\"other\":false,\"shuffle\":false},{\"id\":\"field-84904c62-db49-4363-b37b-7ac0f64bb5b0\",\"label\":\"payment screen sort\",\"type\":\"file\",\"options\":[],\"help\":\"\",\"game\":\"\",\"file_types\":\"images-pdf\",\"purpose\":\"\",\"file_count\":\"1\",\"file_size\":\"5\",\"condition_field\":\"\",\"condition_value\":\"\",\"required\":true,\"rows\":[],\"allowed_values\":[],\"answer_key\":[],\"other\":false,\"shuffle\":false}],\"settings\":{\"accepting\":true,\"one_response\":true,\"allow_edit\":true,\"progress\":true,\"shuffle\":false,\"quiz\":false,\"show_score\":false,\"confirmation\":\"Your application is with the event coordinators. Your ticket will appear after approval.\"},\"title\":\"paper presentation\",\"intro\":\"this is demo for paper presentation\",\"button\":\"Submit registration\"},\"interest_form_draft\":\"\"}','PUBLISHED',7,0,84,'2026-10-11T16:52:09+00:00');

INSERT INTO `cms_content` (`id`,`type`,`slug`,`title`,`data`,`status`,`sort_order`,`created_by`,`revision`,`updated_at`) VALUES (7,'event','tulika','Tulika','{\"short\":\"Colour the canvas of imagination.\",\"description\":\"An artistic event where imagination meets expression. Individual artists respond to live themes and create original artworks.\",\"category\":\"culture\",\"format\":\"Drawing & Painting Competition\",\"image\":\"\",\"art\":\"art\",\"color\":\"orange\",\"label\":\"Colour the canvas of imagination\",\"starts_at\":\"\",\"ends_at\":\"\",\"venue\":\"Dibrugarh University\",\"fees\":\"Coming soon\",\"prizes\":\"\",\"eligibility\":\"Solo participation.\",\"rules\":\"Create an original artwork in response to the live theme.\\nAllowed mediums: pencil, watercolour, acrylics, pastels or mixed media.\\nJudging considers creativity, originality, theme interpretation and technique.\",\"rules_pdf\":\"\",\"contact\":\"\",\"registration_url\":\"\",\"interest_open\":\"1\",\"featured\":\"0\",\"status_label\":\"Programme preview\",\"symbol\":\"✷\",\"form_workflow\":\"1\",\"registration_kind\":\"individual\"}','PUBLISHED',3,0,5,'2026-10-07T19:59:39+00:00');

INSERT INTO `cms_content` (`id`,`type`,`slug`,`title`,`data`,`status`,`sort_order`,`created_by`,`revision`,`updated_at`) VALUES (8,'gallery','memory-1','Finding our rhythm','{\"image\":\"\\/assets\\/2026\\/stage.webp\",\"alt\":\"Finding our rhythm\",\"category\":\"stage\",\"year\":\"2024\",\"description\":\"\"}','PUBLISHED',0,0,1,'2026-09-29T19:46:46+00:00');

INSERT INTO `cms_content` (`id`,`type`,`slug`,`title`,`data`,`status`,`sort_order`,`created_by`,`revision`,`updated_at`) VALUES (9,'gallery','memory-2','The people make the festival','{\"image\":\"\\/assets\\/2026\\/community.webp\",\"alt\":\"The people make the festival\",\"category\":\"community\",\"year\":\"2024\",\"description\":\"\"}','PUBLISHED',1,0,1,'2026-09-29T19:46:46+00:00');

INSERT INTO `cms_content` (`id`,`type`,`slug`,`title`,`data`,`status`,`sort_order`,`created_by`,`revision`,`updated_at`) VALUES (10,'gallery','memory-3','A moment worth celebrating','{\"image\":\"\\/assets\\/2026\\/culture.webp\",\"alt\":\"A moment worth celebrating\",\"category\":\"celebrations\",\"year\":\"2024\",\"description\":\"\"}','PUBLISHED',2,0,1,'2026-09-29T19:46:46+00:00');

INSERT INTO `cms_content` (`id`,`type`,`slug`,`title`,`data`,`status`,`sort_order`,`created_by`,`revision`,`updated_at`) VALUES (11,'gallery','memory-4','Ideas worth sharing','{\"image\":\"\\/assets\\/2026\\/together.webp\",\"alt\":\"Ideas worth sharing\",\"category\":\"celebrations\",\"year\":\"2024\",\"description\":\"\"}','PUBLISHED',3,0,1,'2026-09-29T19:46:46+00:00');

INSERT INTO `cms_content` (`id`,`type`,`slug`,`title`,`data`,`status`,`sort_order`,`created_by`,`revision`,`updated_at`) VALUES (12,'gallery','memory-5','Anazori 2024 · Archive frame 5','{\"image\":\"\\/assets\\/2026\\/archive-6212.webp\",\"alt\":\"Anazori 2024 · Archive frame 5\",\"category\":\"archive\",\"year\":\"2024\",\"description\":\"\"}','PUBLISHED',4,0,1,'2026-09-29T19:46:46+00:00');

INSERT INTO `cms_content` (`id`,`type`,`slug`,`title`,`data`,`status`,`sort_order`,`created_by`,`revision`,`updated_at`) VALUES (13,'gallery','memory-6','Anazori 2024 · Archive frame 6','{\"image\":\"\\/assets\\/2026\\/archive-6213.webp\",\"alt\":\"Anazori 2024 · Archive frame 6\",\"category\":\"archive\",\"year\":\"2024\",\"description\":\"\"}','PUBLISHED',5,0,1,'2026-09-29T19:46:46+00:00');

INSERT INTO `cms_content` (`id`,`type`,`slug`,`title`,`data`,`status`,`sort_order`,`created_by`,`revision`,`updated_at`) VALUES (14,'gallery','memory-7','Anazori 2024 · Archive frame 7','{\"image\":\"\\/assets\\/2026\\/archive-6224.webp\",\"alt\":\"Anazori 2024 · Archive frame 7\",\"category\":\"archive\",\"year\":\"2024\",\"description\":\"\"}','PUBLISHED',6,0,1,'2026-09-29T19:46:46+00:00');

INSERT INTO `cms_content` (`id`,`type`,`slug`,`title`,`data`,`status`,`sort_order`,`created_by`,`revision`,`updated_at`) VALUES (15,'gallery','memory-8','Anazori 2024 · Archive frame 8','{\"image\":\"\\/assets\\/2026\\/archive-6326.webp\",\"alt\":\"Anazori 2024 · Archive frame 8\",\"category\":\"archive\",\"year\":\"2024\",\"description\":\"\"}','PUBLISHED',7,0,1,'2026-09-29T19:46:46+00:00');

INSERT INTO `cms_content` (`id`,`type`,`slug`,`title`,`data`,`status`,`sort_order`,`created_by`,`revision`,`updated_at`) VALUES (16,'gallery','memory-9','Anazori 2024 · Archive frame 9','{\"image\":\"\\/assets\\/2026\\/archive-6327.webp\",\"alt\":\"Anazori 2024 · Archive frame 9\",\"category\":\"archive\",\"year\":\"2024\",\"description\":\"\"}','PUBLISHED',8,0,1,'2026-09-29T19:46:46+00:00');

INSERT INTO `cms_content` (`id`,`type`,`slug`,`title`,`data`,`status`,`sort_order`,`created_by`,`revision`,`updated_at`) VALUES (17,'gallery','memory-10','Anazori 2024 · Archive frame 10','{\"image\":\"\\/assets\\/2026\\/archive-6218.webp\",\"alt\":\"Anazori 2024 · Archive frame 10\",\"category\":\"archive\",\"year\":\"2024\",\"description\":\"\"}','PUBLISHED',9,0,1,'2026-09-29T19:46:46+00:00');

INSERT INTO `cms_content` (`id`,`type`,`slug`,`title`,`data`,`status`,`sort_order`,`created_by`,`revision`,`updated_at`) VALUES (18,'gallery','memory-11','Anazori 2024 · Archive frame 11','{\"image\":\"\\/assets\\/2026\\/archive-6219.webp\",\"alt\":\"Anazori 2024 · Archive frame 11\",\"category\":\"archive\",\"year\":\"2024\",\"description\":\"\"}','PUBLISHED',10,0,1,'2026-09-29T19:46:46+00:00');

INSERT INTO `cms_content` (`id`,`type`,`slug`,`title`,`data`,`status`,`sort_order`,`created_by`,`revision`,`updated_at`) VALUES (19,'gallery','memory-12','Anazori 2024 · Archive frame 12','{\"image\":\"\\/assets\\/2026\\/archive-6220.webp\",\"alt\":\"Anazori 2024 · Archive frame 12\",\"category\":\"archive\",\"year\":\"2024\",\"description\":\"\"}','PUBLISHED',11,0,1,'2026-09-29T19:46:46+00:00');

INSERT INTO `cms_content` (`id`,`type`,`slug`,`title`,`data`,`status`,`sort_order`,`created_by`,`revision`,`updated_at`) VALUES (20,'gallery','memory-13','Anazori 2024 · Archive frame 13','{\"image\":\"\\/assets\\/2026\\/archive-6221.webp\",\"alt\":\"Anazori 2024 · Archive frame 13\",\"category\":\"archive\",\"year\":\"2024\",\"description\":\"\"}','PUBLISHED',12,0,1,'2026-09-29T19:46:46+00:00');

INSERT INTO `cms_content` (`id`,`type`,`slug`,`title`,`data`,`status`,`sort_order`,`created_by`,`revision`,`updated_at`) VALUES (21,'gallery','memory-14','Anazori 2024 · Archive frame 14','{\"image\":\"\\/assets\\/2026\\/archive-6238.webp\",\"alt\":\"Anazori 2024 · Archive frame 14\",\"category\":\"archive\",\"year\":\"2024\",\"description\":\"\"}','PUBLISHED',13,0,1,'2026-09-29T19:46:46+00:00');

INSERT INTO `cms_content` (`id`,`type`,`slug`,`title`,`data`,`status`,`sort_order`,`created_by`,`revision`,`updated_at`) VALUES (22,'gallery','memory-15','Anazori 2024 · Archive frame 15','{\"image\":\"\\/assets\\/2026\\/archive-6328.webp\",\"alt\":\"Anazori 2024 · Archive frame 15\",\"category\":\"archive\",\"year\":\"2024\",\"description\":\"\"}','PUBLISHED',14,0,1,'2026-09-29T19:46:46+00:00');

INSERT INTO `cms_content` (`id`,`type`,`slug`,`title`,`data`,`status`,`sort_order`,`created_by`,`revision`,`updated_at`) VALUES (23,'gallery','memory-16','Anazori 2024 · Archive frame 16','{\"image\":\"\\/assets\\/2026\\/archive-6258.webp\",\"alt\":\"Anazori 2024 · Archive frame 16\",\"category\":\"archive\",\"year\":\"2024\",\"description\":\"\"}','PUBLISHED',15,0,1,'2026-09-29T19:46:46+00:00');

INSERT INTO `cms_content` (`id`,`type`,`slug`,`title`,`data`,`status`,`sort_order`,`created_by`,`revision`,`updated_at`) VALUES (24,'gallery','memory-17','Anazori 2024 · Archive frame 17','{\"image\":\"\\/assets\\/2026\\/archive-6231.webp\",\"alt\":\"Anazori 2024 · Archive frame 17\",\"category\":\"archive\",\"year\":\"2024\",\"description\":\"\"}','PUBLISHED',16,0,1,'2026-09-29T19:46:46+00:00');

INSERT INTO `cms_content` (`id`,`type`,`slug`,`title`,`data`,`status`,`sort_order`,`created_by`,`revision`,`updated_at`) VALUES (25,'gallery','memory-18','Anazori 2024 · Archive frame 18','{\"image\":\"\\/assets\\/2026\\/archive-6243.webp\",\"alt\":\"Anazori 2024 · Archive frame 18\",\"category\":\"archive\",\"year\":\"2024\",\"description\":\"\"}','PUBLISHED',17,0,1,'2026-09-29T19:46:46+00:00');

INSERT INTO `cms_content` (`id`,`type`,`slug`,`title`,`data`,`status`,`sort_order`,`created_by`,`revision`,`updated_at`) VALUES (26,'person','person-21','Prof. Tazid Ali','{\"group\":\"Chief Advisor\",\"role\":\"Chairperson\",\"image\":\"\\/coordinators\\/Chairperson.png\",\"description\":\"\",\"link\":\"https:\\/\\/dibru.ac.in\\/user-profile\\/tazid-ali\",\"edition\":\"Previous edition\"}','ARCHIVED',0,0,2,'2026-10-07T19:59:39+00:00');

INSERT INTO `cms_content` (`id`,`type`,`slug`,`title`,`data`,`status`,`sort_order`,`created_by`,`revision`,`updated_at`) VALUES (27,'person','person-16','Mrs. Kankana Dutta','{\"group\":\"Advisory Committee\",\"role\":\"Advisory member\",\"image\":\"\\/coordinators\\/kankana01.jpg\",\"description\":\"\",\"link\":\"https:\\/\\/dibru.ac.in\\/user-profile\\/kankana-dutta\",\"edition\":\"V16.0 \\/ 2026\"}','PUBLISHED',9,0,2,'2026-10-07T19:59:39+00:00');

INSERT INTO `cms_content` (`id`,`type`,`slug`,`title`,`data`,`status`,`sort_order`,`created_by`,`revision`,`updated_at`) VALUES (28,'person','person-9','Dr. Utpala Borgohain','{\"group\":\"Advisory Committee\",\"role\":\"Advisory member\",\"image\":\"\\/coordinators\\/utpala.png\",\"description\":\"\",\"link\":\"https:\\/\\/www.linkedin.com\\/in\\/utpala-borgohain-7b0260130\",\"edition\":\"V16.0 \\/ 2026\"}','PUBLISHED',2,0,2,'2026-10-07T19:59:39+00:00');

INSERT INTO `cms_content` (`id`,`type`,`slug`,`title`,`data`,`status`,`sort_order`,`created_by`,`revision`,`updated_at`) VALUES (29,'person','person-10','Dr. Rizwan Rehman','{\"group\":\"Advisory Committee\",\"role\":\"Advisory member\",\"image\":\"\\/coordinators\\/rizwan01.jpg\",\"description\":\"\",\"link\":\"https:\\/\\/www.linkedin.com\\/in\\/dr-rizwan-rehman-20854a5b\",\"edition\":\"V16.0 \\/ 2026\"}','PUBLISHED',3,0,2,'2026-10-07T19:59:39+00:00');

INSERT INTO `cms_content` (`id`,`type`,`slug`,`title`,`data`,`status`,`sort_order`,`created_by`,`revision`,`updated_at`) VALUES (30,'person','person-11','Dr. Toralima Bora','{\"group\":\"Advisory Committee\",\"role\":\"Advisory member\",\"image\":\"\\/coordinators\\/toralima.png\",\"description\":\"\",\"link\":\"https:\\/\\/dibru.ac.in\\/user-profile\\/toralima-bora\",\"edition\":\"V16.0 \\/ 2026\"}','PUBLISHED',4,0,2,'2026-10-07T19:59:39+00:00');

INSERT INTO `cms_content` (`id`,`type`,`slug`,`title`,`data`,`status`,`sort_order`,`created_by`,`revision`,`updated_at`) VALUES (31,'person','person-12','Dr. Ujjal Saikia','{\"group\":\"Advisory Committee\",\"role\":\"Advisory member\",\"image\":\"\\/coordinators\\/ujjal.png\",\"description\":\"\",\"link\":\"https:\\/\\/www.linkedin.com\\/in\\/dr-ujjal-saikia-641847289\",\"edition\":\"V16.0 \\/ 2026\"}','PUBLISHED',5,0,2,'2026-10-07T19:59:39+00:00');

INSERT INTO `cms_content` (`id`,`type`,`slug`,`title`,`data`,`status`,`sort_order`,`created_by`,`revision`,`updated_at`) VALUES (32,'person','person-14','Dr. Pranjal K. Bora','{\"group\":\"Advisory Committee\",\"role\":\"Advisory member\",\"image\":\"\\/coordinators\\/pranjal.png\",\"description\":\"\",\"link\":\"https:\\/\\/dibru.ac.in\\/user-profile\\/pranjal-kumar-bora\",\"edition\":\"V16.0 \\/ 2026\"}','PUBLISHED',7,0,2,'2026-10-07T19:59:39+00:00');

INSERT INTO `cms_content` (`id`,`type`,`slug`,`title`,`data`,`status`,`sort_order`,`created_by`,`revision`,`updated_at`) VALUES (33,'person','person-15','Mr. Ankumon Sarmah','{\"group\":\"Advisory Committee\",\"role\":\"Advisory member\",\"image\":\"\\/coordinators\\/ankumon.png\",\"description\":\"\",\"link\":\"https:\\/\\/dibru.ac.in\\/user-profile\\/ankumon-sarmah\",\"edition\":\"V16.0 \\/ 2026\"}','PUBLISHED',8,0,2,'2026-10-07T19:59:39+00:00');

INSERT INTO `cms_content` (`id`,`type`,`slug`,`title`,`data`,`status`,`sort_order`,`created_by`,`revision`,`updated_at`) VALUES (34,'person','person-17','Dr. Sumpi Saikia','{\"group\":\"President\",\"role\":\"President\",\"image\":\"\\/coordinators\\/sumpi01.jpg\",\"description\":\"\",\"link\":\"https:\\/\\/dibru.ac.in\\/user-profile\\/sumpi-saikia\",\"edition\":\"V16.0 \\/ 2026\"}','PUBLISHED',1,0,2,'2026-10-07T19:59:39+00:00');

INSERT INTO `cms_content` (`id`,`type`,`slug`,`title`,`data`,`status`,`sort_order`,`created_by`,`revision`,`updated_at`) VALUES (35,'person','person-18','Ms. Pinakshi Konwar','{\"group\":\"Advisory Committee\",\"role\":\"Advisory member\",\"image\":\"\\/coordinators\\/pinakshi.jpg\",\"description\":\"\",\"link\":\"https:\\/\\/www.instagram.com\\/pinakshi_k\",\"edition\":\"V16.0 \\/ 2026\"}','PUBLISHED',10,0,2,'2026-10-07T19:59:39+00:00');

INSERT INTO `cms_content` (`id`,`type`,`slug`,`title`,`data`,`status`,`sort_order`,`created_by`,`revision`,`updated_at`) VALUES (36,'person','person-20','Md Yasin Musfic Hussain','{\"group\":\"Student Convenor\",\"role\":\"Department Representative\",\"image\":\"\",\"description\":\"\",\"link\":\"https:\\/\\/www.instagram.com\\/yasin_m_hussain\",\"edition\":\"Previous edition\"}','ARCHIVED',10,0,2,'2026-10-07T19:59:39+00:00');

INSERT INTO `cms_content` (`id`,`type`,`slug`,`title`,`data`,`status`,`sort_order`,`created_by`,`revision`,`updated_at`) VALUES (37,'person','person-1','Priyanuj Kalita','{\"group\":\"Coordinators\",\"role\":\"Department Secretary\",\"image\":\"\\/coordinators\\/priyanuj.jpeg\",\"description\":\"\",\"link\":\"https:\\/\\/www.instagram.com\\/__priyanz__\",\"edition\":\"Previous edition\"}','ARCHIVED',11,0,2,'2026-10-07T19:59:39+00:00');

INSERT INTO `cms_content` (`id`,`type`,`slug`,`title`,`data`,`status`,`sort_order`,`created_by`,`revision`,`updated_at`) VALUES (38,'person','person-2','Prodyumna Borgohain','{\"group\":\"Coordinators\",\"role\":\"Head Coordinator\",\"image\":\"\\/coordinators\\/prodyumna01.png\",\"description\":\"\",\"link\":\"https:\\/\\/www.instagram.com\\/prodyumna_dances\",\"edition\":\"Previous edition\"}','ARCHIVED',12,0,2,'2026-10-07T19:59:39+00:00');

INSERT INTO `cms_content` (`id`,`type`,`slug`,`title`,`data`,`status`,`sort_order`,`created_by`,`revision`,`updated_at`) VALUES (39,'person','person-5','Tejaswini Phukon','{\"group\":\"Coordinators\",\"role\":\"Head Coordinator\",\"image\":\"\\/coordinators\\/tejaswini.jpeg\",\"description\":\"\",\"link\":\"https:\\/\\/www.instagram.com\\/enchantedbyyou28\",\"edition\":\"Previous edition\"}','ARCHIVED',13,0,2,'2026-10-07T19:59:39+00:00');

INSERT INTO `cms_content` (`id`,`type`,`slug`,`title`,`data`,`status`,`sort_order`,`created_by`,`revision`,`updated_at`) VALUES (45,'faq','question-1','What is Anazori?','{\"answer\":\"Anazori is the festival of CCSA, Dibrugarh University, bringing technical exploration and cultural expression into one shared experience.\"}','PUBLISHED',0,0,1,'2026-09-29T19:46:46+00:00');

INSERT INTO `cms_content` (`id`,`type`,`slug`,`title`,`data`,`status`,`sort_order`,`created_by`,`revision`,`updated_at`) VALUES (46,'faq','question-2','When is the next Anazori?','{\"answer\":\"The dates are being finalised. Confirmed dates and schedules will appear here and on our official social channels.\"}','PUBLISHED',1,0,1,'2026-09-29T19:46:46+00:00');

INSERT INTO `cms_content` (`id`,`type`,`slug`,`title`,`data`,`status`,`sort_order`,`created_by`,`revision`,`updated_at`) VALUES (47,'faq','question-3','How do I take part?','{\"answer\":\"Explore the experiences and register your interest. Entry details and event rules will be published on each event page.\"}','PUBLISHED',2,0,1,'2026-09-29T19:46:46+00:00');

INSERT INTO `cms_content` (`id`,`type`,`slug`,`title`,`data`,`status`,`sort_order`,`created_by`,`revision`,`updated_at`) VALUES (48,'faq','question-4','Can students from other colleges join?','{\"answer\":\"Eligibility is published for each event. Check the event page for participation rules before planning your entry.\"}','PUBLISHED',3,0,1,'2026-09-29T19:46:46+00:00');

INSERT INTO `cms_content` (`id`,`type`,`slug`,`title`,`data`,`status`,`sort_order`,`created_by`,`revision`,`updated_at`) VALUES (49,'faq','question-5','Want to collaborate or volunteer?','{\"answer\":\"Use the contact links below to connect with the organising team. We would love to hear from you.\"}','PUBLISHED',4,0,1,'2026-09-29T19:46:46+00:00');

INSERT INTO `cms_content` (`id`,`type`,`slug`,`title`,`data`,`status`,`sort_order`,`created_by`,`revision`,`updated_at`) VALUES (50,'sponsor','redbull','redbull','{\"image\":\"\\/uploads\\/media\\/acd49230351f7c2925d8deee0cad8cbaf9e9.png\",\"tier\":\"title partner\",\"description\":\"our first title partner\",\"link\":\"https:\\/\\/www.redbull.com\"}','PUBLISHED',1,1,1,'2026-10-06T07:22:54+00:00');

INSERT INTO `cms_content` (`id`,`type`,`slug`,`title`,`data`,`status`,`sort_order`,`created_by`,`revision`,`updated_at`) VALUES (51,'sponsor','star-cement','STAR CEMENT','{\"image\":\"\\/assets\\/logo.png\",\"tier\":\"stage partner\",\"description\":\"our partner is star cement this time and we love it\",\"link\":\"\"}','PUBLISHED',0,1,1,'2026-10-06T17:46:50+00:00');

INSERT INTO `cms_content` (`id`,`type`,`slug`,`title`,`data`,`status`,`sort_order`,`created_by`,`revision`,`updated_at`) VALUES (52,'collaboration','blitz','club partner','{\"image\":\"\\/uploads\\/media\\/2c311fc92105fbf62d74aeb15466eb0e02f5.png\",\"tier\":\"Community collaboration\",\"description\":\"\",\"link\":\"https:\\/\\/blitz.ccsdu.in\\/\"}','PUBLISHED',0,1,1,'2026-10-07T18:13:32+00:00');

INSERT INTO `cms_content` (`id`,`type`,`slug`,`title`,`data`,`status`,`sort_order`,`created_by`,`revision`,`updated_at`) VALUES (53,'event','inauguration','Inauguration Ceremony','{\"short\":\"The dawn of brilliance.\",\"description\":\"The official opening of Anazori V16.0. Industry experts, dignitaries and academic leaders deliver keynote addresses, setting the stage for innovation, creativity and competition.\",\"category\":\"culture\",\"format\":\"Opening ceremony \\/ Keynote addresses\",\"image\":\"\",\"art\":\"ceremony\",\"color\":\"lilac\",\"label\":\"The dawn of brilliance\",\"starts_at\":\"\",\"ends_at\":\"\",\"venue\":\"Dibrugarh University\",\"fees\":\"No registration required\",\"prizes\":\"\",\"eligibility\":\"\",\"rules\":\"\",\"rules_pdf\":\"\",\"contact\":\"\",\"registration_url\":\"\",\"registration_mode\":\"open\",\"game_categories\":\"[]\",\"registration_fee\":\"0\",\"registration_opens\":\"\",\"registration_closes\":\"\",\"registration_questions\":\"\",\"registration_note\":\"Share your contribution with the event coordinators.\",\"interest_title\":\"Count me in.\",\"interest_intro\":\"Share your details with the organising team.\",\"interest_button\":\"Register my interest\",\"registration_title\":\"Contribute to inauguration\",\"registration_intro\":\"Tell the coordinators how you would like to contribute or perform.\",\"registration_button\":\"Send contribution\",\"registration_closed_message\":\"Contributions are currently closed. Contact the event coordinators.\",\"interest_open\":\"0\",\"featured\":\"1\",\"status_label\":\"Programme preview\",\"payment_methods\":\"[]\",\"ticket_types\":\"[]\",\"registration_kind\":\"individual\",\"registration_settings\":\"{\\\"accepting\\\":true,\\\"one_response\\\":true,\\\"allow_edit\\\":false,\\\"progress\\\":true,\\\"confirmation\\\":\\\"Thank you. Your contribution has been sent to the event team.\\\"}\",\"registration_form\":\"[{\\\"id\\\":\\\"phone\\\",\\\"label\\\":\\\"Contact number\\\",\\\"type\\\":\\\"tel\\\",\\\"required\\\":true,\\\"options\\\":[]},{\\\"id\\\":\\\"contribution\\\",\\\"label\\\":\\\"How would you like to contribute or perform?\\\",\\\"type\\\":\\\"textarea\\\",\\\"required\\\":true,\\\"options\\\":[]}]\",\"form_workflow\":\"1\"}','PUBLISHED',1,0,3,'2026-10-08T04:35:41+00:00');

INSERT INTO `cms_content` (`id`,`type`,`slug`,`title`,`data`,`status`,`sort_order`,`created_by`,`revision`,`updated_at`) VALUES (54,'event','cultural-night','Cultural Night','{\"short\":\"Night of stars.\",\"description\":\"A Night of Stars brings tradition and modernity together through diverse cultural performances, culminating in a live act by a special guest artist.\",\"category\":\"culture\",\"format\":\"Live performances \\/ Guest artist\",\"image\":\"\",\"art\":\"performance\",\"color\":\"orange\",\"label\":\"Night of stars\",\"starts_at\":\"\",\"ends_at\":\"\",\"venue\":\"Dibrugarh University\",\"fees\":\"Free for performers\",\"prizes\":\"\",\"eligibility\":\"\",\"rules\":\"\",\"rules_pdf\":\"\",\"contact\":\"\",\"registration_url\":\"\",\"registration_mode\":\"open\",\"game_categories\":\"[]\",\"registration_fee\":\"0\",\"registration_opens\":\"\",\"registration_closes\":\"\",\"registration_questions\":\"\",\"registration_note\":\"Share your contribution with the event coordinators.\",\"interest_title\":\"Count me in.\",\"interest_intro\":\"Share your details with the organising team.\",\"interest_button\":\"Register my interest\",\"registration_title\":\"Contribute to cultural-night\",\"registration_intro\":\"Tell the coordinators how you would like to contribute or perform.\",\"registration_button\":\"Send contribution\",\"registration_closed_message\":\"Contributions are currently closed. Contact the event coordinators.\",\"interest_open\":\"0\",\"featured\":\"1\",\"status_label\":\"Programme preview\",\"payment_methods\":\"[]\",\"ticket_types\":\"[]\",\"registration_form\":\"[{\\\"id\\\":\\\"phone\\\",\\\"label\\\":\\\"Contact number\\\",\\\"type\\\":\\\"tel\\\",\\\"required\\\":true,\\\"options\\\":[]},{\\\"id\\\":\\\"performance\\\",\\\"label\\\":\\\"What would you like to perform?\\\",\\\"type\\\":\\\"textarea\\\",\\\"required\\\":true,\\\"options\\\":[]}]\",\"form_workflow\":\"1\",\"registration_kind\":\"individual\",\"registration_settings\":\"{\\\"accepting\\\":true,\\\"one_response\\\":true,\\\"allow_edit\\\":false,\\\"progress\\\":true,\\\"confirmation\\\":\\\"Thank you. Your contribution has been sent to the event team.\\\"}\"}','PUBLISHED',9,0,4,'2026-10-08T04:35:41+00:00');

INSERT INTO `cms_content` (`id`,`type`,`slug`,`title`,`data`,`status`,`sort_order`,`created_by`,`revision`,`updated_at`) VALUES (55,'person','v16-paramanandadeka','Prof. Paramananda Deka','{\"image\":\"\",\"description\":\"\",\"link\":\"\",\"group\":\"Chief Advisor\",\"role\":\"Chairperson, CCSA, Dibrugarh University\",\"edition\":\"V16.0 \\/ 2026\"}','PUBLISHED',0,0,1,'2026-10-07T19:59:39+00:00');

INSERT INTO `cms_content` (`id`,`type`,`slug`,`title`,`data`,`status`,`sort_order`,`created_by`,`revision`,`updated_at`) VALUES (56,'person','v16-kimashabora','Dr. Kimasha Bora','{\"image\":\"\",\"description\":\"\",\"link\":\"\",\"group\":\"Advisory Committee\",\"role\":\"Advisory member\",\"edition\":\"V16.0 \\/ 2026\"}','PUBLISHED',6,0,1,'2026-10-07T19:59:39+00:00');

INSERT INTO `cms_content` (`id`,`type`,`slug`,`title`,`data`,`status`,`sort_order`,`created_by`,`revision`,`updated_at`) VALUES (57,'person','v16-pranjitlahon','Mr. Pranjit Lahon','{\"image\":\"\",\"description\":\"\",\"link\":\"\",\"group\":\"Advisory Committee\",\"role\":\"Advisory member\",\"edition\":\"V16.0 \\/ 2026\"}','PUBLISHED',11,0,1,'2026-10-07T19:59:39+00:00');

INSERT INTO `cms_content` (`id`,`type`,`slug`,`title`,`data`,`status`,`sort_order`,`created_by`,`revision`,`updated_at`) VALUES (58,'person','v16-nirajnildutta','Nirajnil Dutta','{\"image\":\"\",\"description\":\"\",\"link\":\"\",\"group\":\"Event Convenor\",\"role\":\"Department Representative\",\"edition\":\"V16.0 \\/ 2026\"}','PUBLISHED',12,0,1,'2026-10-07T19:59:39+00:00');


CREATE TABLE `cms_login_attempts` (
  `attempt_key` varchar(100) NOT NULL,
  `attempts` int(11) NOT NULL,
  `expires_at` int(11) NOT NULL,
  PRIMARY KEY (`attempt_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;



CREATE TABLE `cms_media` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `path` varchar(255) NOT NULL,
  `title` varchar(255) NOT NULL,
  `mime` varchar(100) NOT NULL,
  `size_bytes` int(11) NOT NULL DEFAULT 0,
  `uploaded_by` int(11) NOT NULL DEFAULT 0,
  `created_at` varchar(40) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_path` (`path`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


INSERT INTO `cms_media` (`id`,`path`,`title`,`mime`,`size_bytes`,`uploaded_by`,`created_at`) VALUES (1,'/assets/2026/stage.webp','stage.webp','image/webp',36314,0,'2026-09-29T19:46:46+00:00');

INSERT INTO `cms_media` (`id`,`path`,`title`,`mime`,`size_bytes`,`uploaded_by`,`created_at`) VALUES (2,'/assets/2026/community.webp','community.webp','image/webp',45022,0,'2026-09-29T19:46:46+00:00');

INSERT INTO `cms_media` (`id`,`path`,`title`,`mime`,`size_bytes`,`uploaded_by`,`created_at`) VALUES (3,'/assets/2026/culture.webp','culture.webp','image/webp',101796,0,'2026-09-29T19:46:46+00:00');

INSERT INTO `cms_media` (`id`,`path`,`title`,`mime`,`size_bytes`,`uploaded_by`,`created_at`) VALUES (4,'/assets/2026/together.webp','together.webp','image/webp',46394,0,'2026-09-29T19:46:46+00:00');

INSERT INTO `cms_media` (`id`,`path`,`title`,`mime`,`size_bytes`,`uploaded_by`,`created_at`) VALUES (5,'/assets/2026/archive-6212.webp','archive-6212.webp','image/webp',44932,0,'2026-09-29T19:46:46+00:00');

INSERT INTO `cms_media` (`id`,`path`,`title`,`mime`,`size_bytes`,`uploaded_by`,`created_at`) VALUES (6,'/assets/2026/archive-6213.webp','archive-6213.webp','image/webp',19466,0,'2026-09-29T19:46:46+00:00');

INSERT INTO `cms_media` (`id`,`path`,`title`,`mime`,`size_bytes`,`uploaded_by`,`created_at`) VALUES (7,'/assets/2026/archive-6224.webp','archive-6224.webp','image/webp',47656,0,'2026-09-29T19:46:46+00:00');

INSERT INTO `cms_media` (`id`,`path`,`title`,`mime`,`size_bytes`,`uploaded_by`,`created_at`) VALUES (8,'/assets/2026/archive-6326.webp','archive-6326.webp','image/webp',29446,0,'2026-09-29T19:46:46+00:00');

INSERT INTO `cms_media` (`id`,`path`,`title`,`mime`,`size_bytes`,`uploaded_by`,`created_at`) VALUES (9,'/assets/2026/archive-6327.webp','archive-6327.webp','image/webp',27682,0,'2026-09-29T19:46:46+00:00');

INSERT INTO `cms_media` (`id`,`path`,`title`,`mime`,`size_bytes`,`uploaded_by`,`created_at`) VALUES (10,'/assets/2026/archive-6218.webp','archive-6218.webp','image/webp',33956,0,'2026-09-29T19:46:46+00:00');

INSERT INTO `cms_media` (`id`,`path`,`title`,`mime`,`size_bytes`,`uploaded_by`,`created_at`) VALUES (11,'/assets/2026/archive-6219.webp','archive-6219.webp','image/webp',37150,0,'2026-09-29T19:46:46+00:00');

INSERT INTO `cms_media` (`id`,`path`,`title`,`mime`,`size_bytes`,`uploaded_by`,`created_at`) VALUES (12,'/assets/2026/archive-6220.webp','archive-6220.webp','image/webp',34038,0,'2026-09-29T19:46:46+00:00');

INSERT INTO `cms_media` (`id`,`path`,`title`,`mime`,`size_bytes`,`uploaded_by`,`created_at`) VALUES (13,'/assets/2026/archive-6221.webp','archive-6221.webp','image/webp',80514,0,'2026-09-29T19:46:46+00:00');

INSERT INTO `cms_media` (`id`,`path`,`title`,`mime`,`size_bytes`,`uploaded_by`,`created_at`) VALUES (14,'/assets/2026/archive-6238.webp','archive-6238.webp','image/webp',34444,0,'2026-09-29T19:46:46+00:00');

INSERT INTO `cms_media` (`id`,`path`,`title`,`mime`,`size_bytes`,`uploaded_by`,`created_at`) VALUES (15,'/assets/2026/archive-6328.webp','archive-6328.webp','image/webp',25562,0,'2026-09-29T19:46:46+00:00');

INSERT INTO `cms_media` (`id`,`path`,`title`,`mime`,`size_bytes`,`uploaded_by`,`created_at`) VALUES (16,'/assets/2026/archive-6258.webp','archive-6258.webp','image/webp',51848,0,'2026-09-29T19:46:46+00:00');

INSERT INTO `cms_media` (`id`,`path`,`title`,`mime`,`size_bytes`,`uploaded_by`,`created_at`) VALUES (17,'/assets/2026/archive-6231.webp','archive-6231.webp','image/webp',39764,0,'2026-09-29T19:46:46+00:00');

INSERT INTO `cms_media` (`id`,`path`,`title`,`mime`,`size_bytes`,`uploaded_by`,`created_at`) VALUES (18,'/assets/2026/archive-6243.webp','archive-6243.webp','image/webp',36590,0,'2026-09-29T19:46:46+00:00');

INSERT INTO `cms_media` (`id`,`path`,`title`,`mime`,`size_bytes`,`uploaded_by`,`created_at`) VALUES (19,'/coordinators/Chairperson.png','Chairperson.png','image/png',1599432,0,'2026-09-29T19:46:46+00:00');

INSERT INTO `cms_media` (`id`,`path`,`title`,`mime`,`size_bytes`,`uploaded_by`,`created_at`) VALUES (20,'/coordinators/kankana01.jpg','kankana01.jpg','image/jpeg',1752029,0,'2026-09-29T19:46:46+00:00');

INSERT INTO `cms_media` (`id`,`path`,`title`,`mime`,`size_bytes`,`uploaded_by`,`created_at`) VALUES (21,'/coordinators/utpala.png','utpala.png','image/png',1598539,0,'2026-09-29T19:46:46+00:00');

INSERT INTO `cms_media` (`id`,`path`,`title`,`mime`,`size_bytes`,`uploaded_by`,`created_at`) VALUES (22,'/coordinators/rizwan01.jpg','rizwan01.jpg','image/jpeg',2108681,0,'2026-09-29T19:46:46+00:00');

INSERT INTO `cms_media` (`id`,`path`,`title`,`mime`,`size_bytes`,`uploaded_by`,`created_at`) VALUES (23,'/coordinators/toralima.png','toralima.png','image/png',1842126,0,'2026-09-29T19:46:46+00:00');

INSERT INTO `cms_media` (`id`,`path`,`title`,`mime`,`size_bytes`,`uploaded_by`,`created_at`) VALUES (24,'/coordinators/ujjal.png','ujjal.png','image/png',1484109,0,'2026-09-29T19:46:46+00:00');

INSERT INTO `cms_media` (`id`,`path`,`title`,`mime`,`size_bytes`,`uploaded_by`,`created_at`) VALUES (25,'/coordinators/pranjal.png','pranjal.png','image/png',1951716,0,'2026-09-29T19:46:46+00:00');

INSERT INTO `cms_media` (`id`,`path`,`title`,`mime`,`size_bytes`,`uploaded_by`,`created_at`) VALUES (26,'/coordinators/ankumon.png','ankumon.png','image/png',2875596,0,'2026-09-29T19:46:46+00:00');

INSERT INTO `cms_media` (`id`,`path`,`title`,`mime`,`size_bytes`,`uploaded_by`,`created_at`) VALUES (27,'/coordinators/sumpi01.jpg','sumpi01.jpg','image/jpeg',2404327,0,'2026-09-29T19:46:46+00:00');

INSERT INTO `cms_media` (`id`,`path`,`title`,`mime`,`size_bytes`,`uploaded_by`,`created_at`) VALUES (28,'/coordinators/pinakshi.jpg','pinakshi.jpg','image/jpeg',2730669,0,'2026-09-29T19:46:46+00:00');

INSERT INTO `cms_media` (`id`,`path`,`title`,`mime`,`size_bytes`,`uploaded_by`,`created_at`) VALUES (29,'/coordinators/priyanuj.jpeg','priyanuj.jpeg','image/jpeg',142472,0,'2026-09-29T19:46:46+00:00');

INSERT INTO `cms_media` (`id`,`path`,`title`,`mime`,`size_bytes`,`uploaded_by`,`created_at`) VALUES (30,'/coordinators/prodyumna01.png','prodyumna01.png','image/png',85189,0,'2026-09-29T19:46:46+00:00');

INSERT INTO `cms_media` (`id`,`path`,`title`,`mime`,`size_bytes`,`uploaded_by`,`created_at`) VALUES (31,'/coordinators/tejaswini.jpeg','tejaswini.jpeg','image/jpeg',302840,0,'2026-09-29T19:46:46+00:00');

INSERT INTO `cms_media` (`id`,`path`,`title`,`mime`,`size_bytes`,`uploaded_by`,`created_at`) VALUES (32,'/assets/logo.png','logo.png','image/png',233142,0,'2026-09-29T19:46:46+00:00');

INSERT INTO `cms_media` (`id`,`path`,`title`,`mime`,`size_bytes`,`uploaded_by`,`created_at`) VALUES (33,'/assets/2026/hero-sound.mp4','hero-sound.mp4','video/mp4',4241090,0,'2026-09-29T19:46:46+00:00');

INSERT INTO `cms_media` (`id`,`path`,`title`,`mime`,`size_bytes`,`uploaded_by`,`created_at`) VALUES (34,'/assets/2026/hero-poster.jpg','hero-poster.jpg','image/jpeg',42161,0,'2026-09-29T19:46:46+00:00');

INSERT INTO `cms_media` (`id`,`path`,`title`,`mime`,`size_bytes`,`uploaded_by`,`created_at`) VALUES (35,'/anazori.mp4','anazori.mp4','video/mp4',18206568,0,'2026-09-29T19:46:46+00:00');

INSERT INTO `cms_media` (`id`,`path`,`title`,`mime`,`size_bytes`,`uploaded_by`,`created_at`) VALUES (36,'/into_musictrim.mp3','into_musictrim.mp3','audio/mpeg',507405,0,'2026-09-29T19:46:46+00:00');

INSERT INTO `cms_media` (`id`,`path`,`title`,`mime`,`size_bytes`,`uploaded_by`,`created_at`) VALUES (37,'/into_music.mp3','into_music.mp3','audio/mpeg',653568,0,'2026-09-29T19:46:46+00:00');

INSERT INTO `cms_media` (`id`,`path`,`title`,`mime`,`size_bytes`,`uploaded_by`,`created_at`) VALUES (38,'/ANAZORI_V15.0_Brochure.pdf','ANAZORI_V15.0_Brochure.pdf','application/pdf',7688260,0,'2026-09-29T19:46:46+00:00');

INSERT INTO `cms_media` (`id`,`path`,`title`,`mime`,`size_bytes`,`uploaded_by`,`created_at`) VALUES (39,'/uploads/media/acd49230351f7c2925d8deee0cad8cbaf9e9.png','red-bull-logo-2831.png','image/png',98604,1,'2026-10-06T07:21:51+00:00');

INSERT INTO `cms_media` (`id`,`path`,`title`,`mime`,`size_bytes`,`uploaded_by`,`created_at`) VALUES (40,'/uploads/media/2c311fc92105fbf62d74aeb15466eb0e02f5.png','Picsart_26-09-25_19-44-10-894.png','image/png',1408359,1,'2026-10-07T18:12:30+00:00');

INSERT INTO `cms_media` (`id`,`path`,`title`,`mime`,`size_bytes`,`uploaded_by`,`created_at`) VALUES (41,'/assets/2026/ANAZORI_V16_Brochure_Neon.pdf','Anazori V16.0 - Official brochure','application/pdf',2774010,0,'2026-10-07T19:59:39+00:00');

INSERT INTO `cms_media` (`id`,`path`,`title`,`mime`,`size_bytes`,`uploaded_by`,`created_at`) VALUES (42,'/uploads/media/2885673fba912b704b76d27f571c65adf5e4.png','ANAZORI MAIN FONT.png','image/png',591496,1,'2026-10-10T17:30:04+00:00');


CREATE TABLE `cms_settings` (
  `setting_key` varchar(100) NOT NULL,
  `value` mediumtext NOT NULL,
  PRIMARY KEY (`setting_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


INSERT INTO `cms_settings` (`setting_key`,`value`) VALUES ('auth_history_schema','1');

INSERT INTO `cms_settings` (`setting_key`,`value`) VALUES ('brochure_release_63','1');

INSERT INTO `cms_settings` (`setting_key`,`value`) VALUES ('coordinator_workflow_schema','2');

INSERT INTO `cms_settings` (`setting_key`,`value`) VALUES ('event_options81','1');

INSERT INTO `cms_settings` (`setting_key`,`value`) VALUES ('event_participation_66','1');

INSERT INTO `cms_settings` (`setting_key`,`value`) VALUES ('game_forms81','1');

INSERT INTO `cms_settings` (`setting_key`,`value`) VALUES ('home_film_location_58','1');

INSERT INTO `cms_settings` (`setting_key`,`value`) VALUES ('launch_forms_52','1');

INSERT INTO `cms_settings` (`setting_key`,`value`) VALUES ('mail_schema89','1');

INSERT INTO `cms_settings` (`setting_key`,`value`) VALUES ('manual_finance_schema','1');

INSERT INTO `cms_settings` (`setting_key`,`value`) VALUES ('manual_payment_schema','1');

INSERT INTO `cms_settings` (`setting_key`,`value`) VALUES ('native_forms78','1');

INSERT INTO `cms_settings` (`setting_key`,`value`) VALUES ('official_contact_73','1');

INSERT INTO `cms_settings` (`setting_key`,`value`) VALUES ('participant_profile_schema','1');

INSERT INTO `cms_settings` (`setting_key`,`value`) VALUES ('platform_indexes','1');

INSERT INTO `cms_settings` (`setting_key`,`value`) VALUES ('platform_schema','1');

INSERT INTO `cms_settings` (`setting_key`,`value`) VALUES ('programme_release_43','1');

INSERT INTO `cms_settings` (`setting_key`,`value`) VALUES ('public_data_release_43','1');

INSERT INTO `cms_settings` (`setting_key`,`value`) VALUES ('registration_autosave88','1');

INSERT INTO `cms_settings` (`setting_key`,`value`) VALUES ('registration_progress79','1');

INSERT INTO `cms_settings` (`setting_key`,`value`) VALUES ('schema_version','1');

INSERT INTO `cms_settings` (`setting_key`,`value`) VALUES ('seeded','1');

INSERT INTO `cms_settings` (`setting_key`,`value`) VALUES ('settings_revision','9');

INSERT INTO `cms_settings` (`setting_key`,`value`) VALUES ('site','{\"site_name\":\"ANAZORI\",\"year\":\"2026\",\"tagline\":\"Culture × Tech\",\"logo\":\"\\/assets\\/logo.png\",\"meta_description\":\"Anazori V16.0, the flagship techno-cultural festival of CCSA, Dibrugarh University. Coding, workshops, art, esports, research, Youth Parliament and Cultural Night.\",\"nav_home\":\"Home\",\"nav_events\":\"Explore events\",\"nav_gallery\":\"The memories\",\"nav_people\":\"Our people\",\"header_cta\":\"Find your thing\",\"starts_at\":\"2026-11-02T03:36\",\"ends_at\":\"2026-11-06T04:37\",\"countdown_title\":\"\",\"date_note\":\"\",\"show_countdown\":\"1\",\"hero_video\":\"\\/assets\\/2026\\/hero-sound.mp4\",\"hero_poster\":\"\\/assets\\/2026\\/hero-poster.jpg\",\"hero_music\":\"\",\"sound_default\":\"1\",\"presenter\":\"CCSA, DIBRUGARH UNIVERSITY PRESENTS\",\"hero_eyebrow\":\"A TECHNO-CULTURAL CONFLUENCE\",\"hero_line1\":\"Old roots.\",\"hero_line2\":\"New frequencies.\",\"hero_description\":\"One festival. Infinite possibilities.\\nAnazori V16.0 brings coding, creativity, esports, research and culture together at CCSA, Dibrugarh University.\",\"hero_cta\":\"Explore the experiences\",\"hero_side\":\"MANY WORLDS.\\nONE CONNECTION.\",\"ticker_words\":\"CULTURE|TECHNOLOGY|YOU.\",\"ticker_speed\":\"35\",\"show_intro\":\"1\",\"intro_label\":\"01 \\/ THE ANAZORI SPIRIT\",\"intro_line1\":\"Some connections\",\"intro_line2\":\"change everything.\",\"intro_description\":\"Anazori is the flagship student-driven festival of the Centre for Computer Science and Applications, Dibrugarh University. Its sixteenth edition brings students from across Assam together for technical contests, hands-on workshops, esports, creative expression and an academic showcase.\\n\\nCCSA began as a Computer Centre in 1976, became the Centre for Computer Studies in 2004 and received its current name in 2018. It offers BCA, MCA, PGDCA and Ph.D. programmes in computer science and applications.\",\"robot_greeting\":\"নমস্কাৰ · Hello, explorer!\",\"robot_caption\":\"A little tech. A lot of heart.\",\"show_events\":\"1\",\"events_line1\":\"Different passions.\",\"events_line2\":\"Same electric feeling.\",\"programme_note\":\"A taste of what Anazori is made of. Dates and entry details will be announced here.\",\"show_culture\":\"1\",\"culture_title\":\"Culture.\",\"culture_copy\":\"The stories we carry.\\nThe rhythm that brings us together.\",\"tech_title\":\"Tech.\",\"tech_copy\":\"The questions we ask.\\nThe futures we build together.\",\"show_memories\":\"1\",\"memory_line1\":\"More than a fest.\",\"memory_line2\":\"A feeling.\",\"memory_copy\":\"Real people. Unscripted moments.\\nA few frames from our earlier chapters.\",\"memory_image1\":\"\\/assets\\/2026\\/culture.webp\",\"memory_image2\":\"\\/assets\\/2026\\/community.webp\",\"show_sponsors\":\"1\",\"sponsor_heading\":\"Big ideas need good company.\",\"sponsor_copy\":\"Put your brand where fresh ideas, culture, and the next generation come together. Let’s create something worth remembering.\",\"sponsor_cta\":\"Become a sponsor\",\"sponsor_email\":\"info@ccsdu.in\",\"sponsor_deck\":\"\\/ANAZORI_V15.0_Brochure.pdf\",\"volunteer_heading\":\"Be the energy behind it.\",\"volunteer_copy\":\"From the first hello to the final encore. Bring your curiosity, meet your people, and help make Anazori happen.\",\"volunteer_link\":\"\",\"show_visit\":\"1\",\"venue\":\"Centre for Computer Science and Applications\",\"address\":\"Dibrugarh University, Assam, India - 786004\",\"map_url\":\"https:\\/\\/www.google.com\\/maps\\/search\\/?api=1&query=27.449500%2C94.894778\",\"email\":\"info@ccsdu.in\",\"instagram\":\"https:\\/\\/instagram.com\\/anazoriccsa\",\"facebook\":\"https:\\/\\/www.facebook.com\\/AnazoriDU\\/\",\"institution_url\":\"https:\\/\\/ccsdu.in\\/\",\"events_page_line1\":\"Find your\",\"events_page_line2\":\"kind of extraordinary.\",\"events_page_copy\":\"For the builders. The performers. The players. And everyone who refuses to be just one thing.\",\"gallery_page_line1\":\"Some moments.\",\"gallery_page_line2\":\"Forever Anazori.\",\"gallery_page_copy\":\"The energy. The people. The little in-between moments. A look back, before we make what comes next.\",\"people_page_line1\":\"Good things start\",\"people_page_line2\":\"with great people.\",\"people_page_copy\":\"The faculty, students, volunteers, and shared ambition behind the Anazori story.\",\"people_notice\":\"The organising committee for Anazori V16.0.\",\"footer_line1\":\"Let’s make\",\"footer_line2\":\"some memories.\",\"footer_tagline\":\"Made of culture. Made for tomorrow.\",\"partners_line1\":\"Good company.\",\"partners_line2\":\"Great possibilities.\",\"show_characters\":\"1\",\"scene_motion\":\"1\",\"show_passport\":\"1\",\"stage_heading\":\"Find your\",\"stage_accent\":\"moment.\",\"character_pikachu\":\"\",\"character_gengar\":\"\",\"character_mlbb\":\"\",\"character_bgmi\":\"\\/coordinators\\/tejaswini.jpeg\",\"character_charizard\":\"\",\"character_sonic\":\"\",\"character_stuart\":\"\",\"character_doraemon\":\"\",\"character_minion\":\"\",\"character_dragon\":\"\",\"intro_video\":\"\\/assets\\/2026\\/hero-sound.mp4\",\"intro_video_poster\":\"\\/assets\\/2026\\/hero-poster.jpg\",\"intro_video_autoplay\":\"1\",\"intro_video_controls\":\"1\",\"intro_video_loop\":\"1\",\"contact_person1\":\"Anurag Priyam Chutia\",\"contact_email1\":\"anuragchutia2005@gmail.com\",\"contact_phone1\":\"+91 6003440122\",\"contact_person2\":\"Aryan Sharma\",\"contact_email2\":\"aryansharmaok@gmail.com\",\"contact_phone2\":\"+91 7099500880\",\"brochure_pdf\":\"\\/assets\\/2026\\/ANAZORI_V16_Brochure_Neon.pdf\"}');

INSERT INTO `cms_settings` (`setting_key`,`value`) VALUES ('studio_access_schema','2');

INSERT INTO `cms_settings` (`setting_key`,`value`) VALUES ('studio_finance_schema','3');


CREATE TABLE `events` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `slug` varchar(255) NOT NULL,
  `title` mediumtext NOT NULL,
  `tag_line` mediumtext DEFAULT NULL,
  `description` mediumtext DEFAULT NULL,
  `prizepool` bigint(20) DEFAULT 0,
  `event_date` mediumtext DEFAULT NULL,
  `last_reg_date` mediumtext DEFAULT NULL,
  `location` mediumtext DEFAULT NULL,
  `img` mediumtext DEFAULT NULL,
  `registration_fees` mediumtext DEFAULT NULL,
  `coordinator_details` mediumtext DEFAULT NULL,
  `status` mediumtext DEFAULT 'ACTIVE',
  `created_at` datetime DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_slug` (`slug`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


INSERT INTO `events` (`id`,`slug`,`title`,`tag_line`,`description`,`prizepool`,`event_date`,`last_reg_date`,`location`,`img`,`registration_fees`,`coordinator_details`,`status`,`created_at`) VALUES (1,'youth-parliament','Youth Parliament','Voices that shape tomorrow.','A simulated parliamentary session where students take the role of lawmakers to debate, question and deliberate on issues that matter to the nation and its youth. Youth Parliament makes its debut at Anazori V16.0.',0,'','','Dibrugarh University','','0','','ACTIVE','2026-09-28 19:06:36');

INSERT INTO `events` (`id`,`slug`,`title`,`tag_line`,`description`,`prizepool`,`event_date`,`last_reg_date`,`location`,`img`,`registration_fees`,`coordinator_details`,`status`,`created_at`) VALUES (2,'goc','Game of Codes','Code the future.','Solve algorithmic problems, debug code and optimise solutions under time constraints. Game of Codes brings solo participants and groups together for a preliminary round followed by the final.',0,'','','Dibrugarh University','','0','','ACTIVE','2026-09-28 19:06:36');

INSERT INTO `events` (`id`,`slug`,`title`,`tag_line`,`description`,`prizepool`,`event_date`,`last_reg_date`,`location`,`img`,`registration_fees`,`coordinator_details`,`status`,`created_at`) VALUES (3,'joystick','Joystick','Play. Compete. Conquer.','The battleground for BGMI, MLBB and Free Fire. Teams compete in high-energy matches where skill, teamwork and strategy decide the winner.',0,'','','Dibrugarh University','','0','','ACTIVE','2026-09-28 19:06:36');

INSERT INTO `events` (`id`,`slug`,`title`,`tag_line`,`description`,`prizepool`,`event_date`,`last_reg_date`,`location`,`img`,`registration_fees`,`coordinator_details`,`status`,`created_at`) VALUES (4,'treasure-hunt','Treasure Hunt','Clues. Puzzles. Glory.','A team-based hunt of clues, puzzles, strategy and problem-solving. Race against the clock, decode each clue and reach the treasure first.',0,'','','Dibrugarh University','','0','','ACTIVE','2026-09-28 19:06:36');

INSERT INTO `events` (`id`,`slug`,`title`,`tag_line`,`description`,`prizepool`,`event_date`,`last_reg_date`,`location`,`img`,`registration_fees`,`coordinator_details`,`status`,`created_at`) VALUES (5,'workshops','Technical Workshop','Learn, build, lead.','Hands-on workshops in Web Development, Machine Learning and Cloud Computing. Sessions focus on practical application, helping participants leave with project-ready skills, new knowledge and working outputs.',0,'','','Dibrugarh University','','0','','ACTIVE','2026-09-28 19:06:36');

INSERT INTO `events` (`id`,`slug`,`title`,`tag_line`,`description`,`prizepool`,`event_date`,`last_reg_date`,`location`,`img`,`registration_fees`,`coordinator_details`,`status`,`created_at`) VALUES (6,'paper-presentation','Paper Presentation','Ideas worth sharing.','A platform for innovators and researchers to share work in computing and applied sciences, including emerging technologies, applied projects and case studies.',0,'','','Dibrugarh University','','0','','ACTIVE','2026-09-28 19:06:36');

INSERT INTO `events` (`id`,`slug`,`title`,`tag_line`,`description`,`prizepool`,`event_date`,`last_reg_date`,`location`,`img`,`registration_fees`,`coordinator_details`,`status`,`created_at`) VALUES (7,'tulika','Tulika','Colour the canvas of imagination.','An artistic event where imagination meets expression. Individual artists respond to live themes and create original artworks.',0,'','','Dibrugarh University','','0','','ACTIVE','2026-09-28 19:06:36');

INSERT INTO `events` (`id`,`slug`,`title`,`tag_line`,`description`,`prizepool`,`event_date`,`last_reg_date`,`location`,`img`,`registration_fees`,`coordinator_details`,`status`,`created_at`) VALUES (8,'inauguration','Inauguration Ceremony','The dawn of brilliance.','The official opening of Anazori V16.0. Industry experts, dignitaries and academic leaders deliver keynote addresses, setting the stage for innovation, creativity and competition.',0,NULL,NULL,'Centre for Computer Science and Applications',NULL,NULL,NULL,'ACTIVE','2026-10-07 19:59:39');

INSERT INTO `events` (`id`,`slug`,`title`,`tag_line`,`description`,`prizepool`,`event_date`,`last_reg_date`,`location`,`img`,`registration_fees`,`coordinator_details`,`status`,`created_at`) VALUES (9,'cultural-night','Cultural Night','Night of stars.','A Night of Stars brings tradition and modernity together through diverse cultural performances, culminating in a live act by a special guest artist.',0,NULL,NULL,'Centre for Computer Science and Applications',NULL,NULL,NULL,'ACTIVE','2026-10-07 19:59:39');


CREATE TABLE `st_budgets` (
  `event_id` int(11) NOT NULL,
  `environment` varchar(10) NOT NULL,
  `allocated` bigint(20) NOT NULL DEFAULT 0,
  `revision` int(11) NOT NULL DEFAULT 1,
  `closed` int(11) NOT NULL DEFAULT 0,
  `updated_by` int(11) NOT NULL,
  `updated_at` varchar(40) NOT NULL,
  PRIMARY KEY (`event_id`,`environment`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;



CREATE TABLE `st_closeouts` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `event_id` int(11) NOT NULL,
  `environment` varchar(10) NOT NULL,
  `snapshot` mediumtext NOT NULL,
  `snapshot_hash` varchar(64) NOT NULL,
  `note` varchar(1000) NOT NULL,
  `created_by` int(11) NOT NULL,
  `created_at` varchar(40) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `st_closeouts_scope` (`event_id`,`environment`,`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;



CREATE TABLE `st_event_activity` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `event_id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `username` varchar(100) NOT NULL,
  `action` varchar(100) NOT NULL,
  `detail` mediumtext NOT NULL,
  `created_at` varchar(40) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `st_event_activity_event` (`event_id`,`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;



CREATE TABLE `st_event_assignments` (
  `user_id` int(11) NOT NULL,
  `event_id` int(11) NOT NULL,
  `assigned_by` int(11) NOT NULL,
  `assigned_at` varchar(40) NOT NULL,
  PRIMARY KEY (`user_id`,`event_id`),
  KEY `st_event_assignments_event` (`event_id`,`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


CREATE TABLE `st_expenses` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `event_id` int(11) NOT NULL,
  `environment` varchar(10) NOT NULL,
  `title` varchar(180) NOT NULL,
  `category` varchar(40) NOT NULL,
  `payee` varchar(150) NOT NULL,
  `amount` bigint(20) NOT NULL,
  `description` mediumtext NOT NULL,
  `invoice_reference` varchar(150) NOT NULL,
  `proof_evidence_id` int(11) DEFAULT NULL,
  `created_by` int(11) NOT NULL,
  `status` varchar(20) NOT NULL DEFAULT 'DRAFT',
  `revision` int(11) NOT NULL DEFAULT 1,
  `reviewed_by` int(11) DEFAULT NULL,
  `review_note` varchar(500) DEFAULT NULL,
  `paid_by` int(11) DEFAULT NULL,
  `payment_reference` varchar(150) DEFAULT NULL,
  `created_at` varchar(40) NOT NULL,
  `updated_at` varchar(40) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `st_expenses_scope` (`event_id`,`environment`,`status`,`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;



CREATE TABLE `st_finance_audit` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `event_id` int(11) DEFAULT NULL,
  `environment` varchar(10) NOT NULL,
  `user_id` int(11) NOT NULL,
  `action` varchar(60) NOT NULL,
  `detail` mediumtext NOT NULL,
  `created_at` varchar(40) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `st_audit_scope` (`event_id`,`environment`,`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;



CREATE TABLE `st_finance_commands` (
  `request_key` varchar(64) NOT NULL,
  `user_id` int(11) NOT NULL,
  `action` varchar(60) NOT NULL,
  `input_hash` varchar(64) NOT NULL,
  `result_id` int(11) NOT NULL DEFAULT 0,
  `created_at` varchar(40) NOT NULL,
  PRIMARY KEY (`request_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;



CREATE TABLE `st_finance_evidence` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `event_id` int(11) NOT NULL,
  `environment` varchar(10) NOT NULL,
  `filename` varchar(100) NOT NULL,
  `title` varchar(180) NOT NULL,
  `mime` varchar(100) NOT NULL,
  `size_bytes` int(11) NOT NULL,
  `sha256` varchar(64) NOT NULL,
  `uploaded_by` int(11) NOT NULL,
  `created_at` varchar(40) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_filename` (`filename`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;



CREATE TABLE `st_finance_ledger` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `event_id` int(11) NOT NULL,
  `environment` varchar(10) NOT NULL,
  `kind` varchar(30) NOT NULL,
  `amount` bigint(20) NOT NULL,
  `title` varchar(180) NOT NULL,
  `reference` varchar(150) NOT NULL,
  `source_id` int(11) DEFAULT NULL,
  `reverses_id` int(11) DEFAULT NULL,
  `created_by` int(11) NOT NULL,
  `created_at` varchar(40) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_reverses_id` (`reverses_id`),
  KEY `st_ledger_scope` (`event_id`,`environment`,`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;



CREATE TABLE `st_reconciliations` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `environment` varchar(10) NOT NULL,
  `statement_date` varchar(10) NOT NULL,
  `bank_total` bigint(20) NOT NULL,
  `recorded_total` bigint(20) NOT NULL,
  `difference` bigint(20) NOT NULL,
  `reference` varchar(150) NOT NULL,
  `note` varchar(1000) NOT NULL,
  `created_by` int(11) NOT NULL,
  `created_at` varchar(40) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;



CREATE TABLE `st_settlement_orders` (
  `settlement_id` int(11) NOT NULL,
  `order_id` int(11) NOT NULL,
  `gross` bigint(20) NOT NULL,
  `refunds` bigint(20) NOT NULL,
  `fees` bigint(20) NOT NULL DEFAULT 0,
  PRIMARY KEY (`settlement_id`,`order_id`),
  UNIQUE KEY `unique_order_id` (`order_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;



CREATE TABLE `st_settlements` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `environment` varchar(10) NOT NULL,
  `provider` varchar(20) NOT NULL,
  `reference` varchar(150) NOT NULL,
  `gross` bigint(20) NOT NULL,
  `refunds` bigint(20) NOT NULL,
  `fees` bigint(20) NOT NULL,
  `net` bigint(20) NOT NULL,
  `bank_date` varchar(10) NOT NULL,
  `bank_reference` varchar(150) NOT NULL,
  `created_by` int(11) NOT NULL,
  `created_at` varchar(40) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_environment_provider_reference` (`environment`,`provider`,`reference`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;



CREATE TABLE `submissions` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `event_id` bigint(20) NOT NULL,
  `name` mediumtext NOT NULL,
  `phone` mediumtext NOT NULL,
  `email` mediumtext DEFAULT NULL,
  `form_data` mediumtext DEFAULT NULL,
  `payment_proof` mediumtext DEFAULT NULL,
  `status` mediumtext DEFAULT 'PENDING',
  `created_at` datetime DEFAULT current_timestamp(),
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;



CREATE TABLE `users` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `username` varchar(255) NOT NULL,
  `password_hash` mediumtext NOT NULL,
  `role` mediumtext DEFAULT 'USER',
  `created_at` datetime DEFAULT current_timestamp(),
  `active` int(11) NOT NULL DEFAULT 1,
  `display_name` varchar(150) NOT NULL DEFAULT '',
  `email` varchar(254) NOT NULL DEFAULT '',
  `modules` mediumtext DEFAULT NULL,
  `session_version` int(11) NOT NULL DEFAULT 0,
  `must_change_password` int(11) NOT NULL DEFAULT 0,
  `permissions` mediumtext DEFAULT NULL,
  `staff_title` varchar(100) NOT NULL DEFAULT '',
  `event_scope` varchar(20) NOT NULL DEFAULT 'assigned',
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_username` (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


CREATE TABLE `visitors` (
  `id` bigint(20) NOT NULL,
  `count` bigint(20) DEFAULT 15847,
  `updated_at` datetime DEFAULT current_timestamp(),
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


SET FOREIGN_KEY_CHECKS=1;
