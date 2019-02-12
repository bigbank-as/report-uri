# report-uri

[CSP][], [Expect-CT][] and [HPKP][] report collection endpoint.

When browsers detect a `CSP`, `Expect-CT` or `HPKP`policy
violation, they can report this via a POST request to this
webserver for logging.

The report is logged to `/var/log/python/app.json`.

## Usage

Configure your application web server to include relevant security headers in their
HTTP Response and include a `report-uri` targeted to `https://<domain>/<header>`.

This will cause the visitor's browser to `POST` to that endpoint
with a JSON-encoded violation report, should a policy violation occur.

### CSP

Set `report-uri` to `https://<domain>/csp`.

```txt
Content-Security-Policy: default-src 'none';
    report-uri https://<domain>/csp;
    connect-src 'self';
    script-src 'self';
    img-src 'self';
    style-src 'self';
    font-src 'self';
```

### Expect-CT

Set `report-uri` to `https://<domain>/ct`.

```txt
Expect-CT: enforce, max-age=2592000, report-uri='https://<domain>/ct'
```

### HPKP

Set `report-uri` to `https://<domain>/hpkp`.

```txt
Public-Key-Pins: pin-sha256="5STGqlsMyQEztqRgv9VGaoKDgSNlecUSM/KacVfK7Xg=";
    report-uri="https://<domain>/hpkp";
    max-age=2592000;
```

## Testing

### CSP

Use any site with CSP and `report-uri` defined.
Edit its HTML with browser developer tools and try to load an external,
unauthorized resource such as an image.

It should violate the CSP and the browser will send a report to `report-uri`.

### HPKP

Use Chrome to visit a site that defines a HPKP header.
Close it, completely (`ps aux | grep chrome`).
Edit `~/.config/google-chrome/Default/TransportSecurity`, find the HPKP-s of
the site you just visited and edit one character of all its hashes
(invalidate it manually).

Open Chrome and visit the site, which will result in a Chrome error page
(`NET::ERR_SSL_PINNED_KEY_NOT_IN_CERT_CHAIN`) and a report sent to
`report-uri`. To later "fix" the state, visit `chrome://net-internals/#hsts`
and manually remove HPKP headers of the target domain.

### Expect-CT

Upon a violation, the User-Agent will POST a JSON object to the `report-uri`.
The full spec of the object is at [expect-ct-spec][].

```bash
curl -X POST \
  http://localhost:8080/ct \
  -H 'content-type: application/json' \
  -d '  {
      "expect-ct-report": {
        "hostname": "example.com",
        "port": "443",
        "effective-expiration-date": "2017"
      }
    }'
```

[CSP]: https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP#Enabling_reporting
[HPKP]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Public_Key_Pinning
[expect-ct-spec]: https://tools.ietf.org/html/draft-ietf-httpbis-expect-ct-02
[Expect-CT]: https://scotthelme.co.uk/a-new-security-header-expect-ct/
