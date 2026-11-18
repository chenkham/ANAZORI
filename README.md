# ANAZORI

The upload-ready website is in **src**. It contains PHP pages, APIs, built assets, Composer dependencies and public media. The former frontend source directory is now **frontend**.

```text
anazori/
  src/                 Website document root; upload this folder
  deploy/
    anazori-hostinger.sql
    private/           Production config + private key/storage; upload beside src
    HOSTINGER-SETUP.md
  frontend/            Editable JavaScript and CSS
  scripts/             Local preview, build and maintenance tools
  tests/               Automated checks
  docs/                Project documentation
  development/         Laptop-only configuration; do not upload
  anazori-config.php   Local/production configuration outside the document root
  anazori-private/     Private local key and submitted files
  .local/              Recovery backups, logs and downloaded tools
  data/                Retained old local SQLite database; not the active MySQL database
  legacy/              Archived media sources, screenshots, fonts and older code
```

See `deploy/HOSTINGER-SETUP.md` for exact direct-folder upload steps. No ZIP is required. Upload the production config from `deploy/private`; keep development material on the laptop.

## Local work

Run commands from the `anazori` directory:

```text
npm run serve
npm run serve:mobile -- <your-laptop-LAN-IP>
npm run build
python scripts/validate-hostinger-folder91.py
```

Preview: `http://127.0.0.1:8000/`. The PHP router lives in `scripts/router.php` and serves only `src`. The preview uses the existing WSL PHP/MySQL setup when `.local/use-wsl-php` is present. Build output goes directly to `src/assets/2026`; source remains in `frontend`.

Existing project guides are under `docs`. Historical one-off asset scripts and QA snapshots are retained for recovery; review their input/output paths before reusing them.
