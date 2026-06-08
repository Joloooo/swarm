# Bundled wordlists

Real wordlists shipped with SwarmAttacker so `gobuster_dir` and credential
work have proper coverage on a fresh clone. Re-fetch / refresh any time with:

```bash
./scripts/download_wordlists.sh
```

That pulls the lists below from SecLists as **flat basenames** so the
`gobuster_dir` resolver's repo-bundled fallback (step 4) finds them with no
code change. For the *full* ~1 GB SecLists tree under
`~/.swarmattacker/seclists/`, use `./scripts/setup.sh --with-seclists` instead.

## Resolution order (see `src/tools/web_recon/gobuster.py`)

`gobuster_dir(wordlist="<name>")` tries these roots in order, first hit wins:

1. `~/.swarmattacker/seclists/...` — operator opted in via `--with-seclists`.
2. `/usr/share/seclists/...` — Kali / Parrot apt-installed SecLists.
3. `/usr/share/wordlists/...` — Kali's built-in dirb / dirbuster paths.
4. `<repo>/wordlists/<basename>` — this directory (matched by filename).

An absolute path is passed through unchanged. Preset → basename mapping:
`common` → `common.txt`, `medium` → `raft-medium-directories.txt`,
`big` → `raft-large-directories.txt` / `big.txt`.

## Files in this directory

| File | Lines | Source / use |
|---|---|---|
| `common.txt` | ~4.7k | SecLists `Discovery/Web-Content/common.txt` — the `common` preset. |
| `raft-medium-directories.txt` | ~30k | `medium` directory preset. |
| `raft-medium-files.txt` | ~17k | medium file enumeration. |
| `raft-large-directories.txt` | ~62k | `big` directory preset. |
| `big.txt` | ~20k | broad directory/file sweep. |
| `top-usernames-shortlist.txt` | ~17 | username spraying. |
| `rockyou.txt` | ~14.3M | **gitignored (133 MB)** — password cracking / credential spraying. Re-fetch with the script. |

> `rockyou.txt` is the only gitignored list (too big for git). Everything else
> here is committed, so directory enumeration works on a fresh clone; only the
> password list needs the download script.
