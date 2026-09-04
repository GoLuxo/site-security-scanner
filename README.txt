# SiteGuard

I built this after noticing how many small business sites have basic security gaps nobody's checking for - missing headers, exposed `.env` files, certs nobody caught expiring in time. Point it at a URL and it runs through the usual suspects in a few seconds, then gives you a plain-language report and a letter grade you can actually hand to someone.

Everything it does is a normal, unauthenticated request - the same kind of request any browser makes just loading the page. No exploits, no brute-forcing, no bypassing anything. It only checks what's already publicly exposed.

**Only run this against sites you own or have permission to test.** Scanning something you don't control, even passively, isn't a good idea.

## What it checks

- Security headers - HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy
- TLS cert - valid, protocol, issuer, days until it expires
- Cookies - Secure / HttpOnly / SameSite flags on each one
- Common exposed files - `.env`, `.git/config`, backup files, that kind of thing
- robots.txt / sitemap.xml presence

## Setup

```bash
git clone https://github.com/<your-username>/site-security-scanner.git
cd site-security-scanner
pip install -r requirements.txt
```

## Running it

```bash
python scanner.py example.com
```

Save a copy of the report:

```bash
python scanner.py example.com --json report.json --md report.md
```

## Sample output

```
SiteGuard report for https://example.com
Overall grade: B  (85/100)

Security headers:
  [x] Strict-Transport-Security
  [x] Content-Security-Policy
  [ ] Permissions-Policy - missing

TLS certificate:
  [x] Valid - TLSv1.3, expires in 28 days

Exposed sensitive paths:
  None found.
```

## What's next

Thinking about batch scanning from a list of URLs, an HTML report option, and letting people define their own header checklist instead of the hardcoded one.

## License

MIT - see LICENSE.