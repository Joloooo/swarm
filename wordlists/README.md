# Bundled wordlists

Small, hand-curated wordlists shipped with SwarmAttacker so `gobuster_dir`
works on a fresh clone without any external download. The serious sweeps
(SecLists `medium`/`big`/`raft-*`) come from the optional SecLists
checkout that `./scripts/setup.sh --with-seclists` installs into
`~/.swarmattacker/seclists/`.

## Resolution order (see `src/tools/web_recon/gobuster.py`)

When the agent calls `gobuster_dir(wordlist="<name>")` the wrapper tries
the following paths in order and uses the first one that exists:

1. `~/.swarmattacker/seclists/...` — operator opted in via
   `--with-seclists`.
2. `/usr/share/seclists/...` — Kali / Parrot's apt-installed SecLists.
3. `/usr/share/wordlists/...` — Kali's built-in dirb / dirbuster paths.
4. `<repo>/wordlists/...` — this directory.

If `<name>` is an absolute path the wrapper passes it through unchanged.

## Files in this directory

| File | Lines | Source |
|---|---|---|
| `common.txt` | ~150 | Hand-curated. Covers admin panels, API roots (`api`, `api/v1`, `graphql`), config files (`.env`, `config.php`, `wp-config.php`), backups (`backup.sql`, `dump.sql`), VCS leaks (`.git`, `.svn`), framework markers (`composer.json`, `package.json`, `swagger.json`), and CMS entry points (`wp-admin`, `phpmyadmin`). Enough for a smoke test; not enough to replace SecLists for real coverage. |
