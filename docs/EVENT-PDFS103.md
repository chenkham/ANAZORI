# Named event PDFs

Open Organising Studio → your event → Event details → Event PDFs.

Each row has a coordinator-chosen link label and a PDF file. Examples: Rules PDF, Topics, Schedule, Judging criteria. Upload a PDF directly or select an existing PDF from Media library. Add PDF creates another row. Move up/down changes the public order; Remove hides a link after saving. Save the event to publish the list.

Up to 20 PDFs are supported per event. Labels support 1–100 characters; uploads retain the existing 12 MB PDF limit, MIME/content checks, login, CSRF and assigned-event permissions. These event documents are public links.

Existing event rules PDFs are retained as the initial Rules PDF row. Events without their own rules PDF retain the shared Festival brochure fallback until the coordinator edits the PDF list. Saving an empty list deliberately removes all PDF links. The first selected PDF is mirrored to the old rules field for compatibility.

An older cached editor preserves the named list when saving other event details. A referenced PDF cannot be removed from Media library until its event links are removed.

The new list is stored in the event's existing JSON data. No database reset, SQL import or new table is needed.

## Exact hPanel paths for this change

Replace:

- event.php
- includes/cms-schema.php
- includes/cms.php
- includes/cms-actions.php
- includes/event-setup-view.php
- assets/2026/studio.js
- assets/2026/public.css

Add:

- includes/event-documents103.php

These paths are relative to the domain's document root: the folder containing index.php and account.php. On this computer they are inside src/.

The small PDF-only ZIP assumes update102 is already installed. If it is not, use the combined update103 ZIP, which also contains update102 and the preceding code fixes. Both ZIPs update an existing Anazori V16 website; neither is a fresh site installation.

Back up files before replacement. Extract in the document root without an extra nested folder, retain all other files and private configuration/database/uploads, then purge any host/CDN cache. Reload the Studio editor before adding PDFs.
