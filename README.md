# contact.reducer · Domain Move (IONOS migration tracker)

Local tool for organising and verifying the move of domains, websites and email from three IONOS accounts into one consolidated contract, with websites going to VPS hosting. It tracks and verifies only: every migration and cancellation is done by hand.

## Run

From this folder:

```
npm start            # http://localhost:4760   (PORT=4770 npm start for another port)
```

Node 20 or later, no dependencies. The tracker binds to 127.0.0.1 only. Review links for agents use a separate port that is off until you turn on network sharing (see Review lists).

Data lives in `data/` (store, backups, review passwords and sessions). It is git-ignored: never commit it, and copy `data/store.json` by hand when moving the app to another machine.

## Files

| Path | Role |
|---|---|
| `server.js` | HTTP server, JSON API, local-only guards (Host check, same-origin writes, CSP) |
| `lib/csv.js` | CSV parser with delimiter detection (IONOS uses `;`) |
| `lib/importer.js` | Column mapping, record normalisation, merge that keeps tracking, default statuses, missing-info flags |
| `lib/store.js` | `data/store.json` with revision numbers; automatic backups in `data/backups` |
| `lib/jobs.js` | Background scan queue with a concurrency limit |
| `lib/net.js` | DNS through chosen resolvers, HTTP with per-hop redirect capture, TLS validity, IP/CIDR and CDN matching |
| `lib/verify.js` | Migration verification scan and verdict |
| `lib/tech.js` | Technology detection from public signals and IONOS export hints; detected vs inferred; database conclusion |
| `lib/source.js` | Optional source access (local folder or key-based SSH), read-only analysis of known config files |
| `public/health.js` | Plain-language health from a scan (server, site, SSL). Shared by the server (scan log) and the browser |
| `public/` | Browser UI (`app.js`, `derive.js` progress and readiness rules, `app.css`) |
| `lib/review.js` | Review lists: create, decide, passwords (scrypt), agent sessions, the agent API |
| `public/reviewtypes.js` | List types: the agent's answers and your decisions for each, shared by server and browser |
| `public/review.html`, `review.js`, `review.css` | The agent's review page (`/r/<list id>`) |
| `public/theme.js` | Sets light or dark before the page paints (light unless chosen; key `cmk-theme`) |
| `public/brand/`, `public/vendor/` | Cormack logos (light and dark), Remix Icon and the Inter font, served locally like Domain Manager's |

## Look and feel

Styled to match the other Cormack tools (Domain Manager): Cormack logo, Inter, Remix Icon, a 72px header with title and breadcrumb, a white sidebar where the current page is a blue pill, and 16px cards. **Light is the default**; the moon / sun button in the header switches to dark and the choice is remembered (it also applies to the agent's review page on the same address). The menu button hides the sidebar on a wide screen and opens it over the page on a narrow one.

## Using it

- **Dashboard** is the first page. Four cards (domains, on a VPS, still on IONOS shared, sites down) open Contracts with that filter. Below them, widgets you can drag by their header to rearrange (**Reset** puts them back): expiration timeline from the IONOS export, where sites are now, site health and SSL, IONOS destination, last scan, migration progress per track, review lists, domains expiring in the next 30 days, accounts, contracts closest to ready and the activity feed. Clicking a legend row, domain, account, list or contract opens it. Choosing an account in the sidebar narrows the dashboard to that account.
- The **bell** shows agent answers waiting for your decision (and contracts ready for cancellation review); the pill next to the title shows when the last full scan ran, or the scan in progress.
- **Contracts** shows each contract as one row with its progress, open issues and readiness. Click a row to see its domains inline.
- **Scan all sites** (top of the page) checks every domain. It shows which server the DNS points to (anything not on a configured VPS is flagged, with the provider from reverse DNS), whether the site is up, and whether SSL is valid. After the first full scan the button becomes **Rescan all sites** and shows when the last scan ran.
- **Scan log** lists every scan with its totals and what changed against the previous scan of the same domains.
- The chips under the scan button are filters: click one to see only those domains.
- A scan only moves the Website status forward, never back: **Moved** when every DNS record is on a VPS, the site answers and the certificate is valid; **Verified** when the marker file also matches. N/A and Verified are never changed by a scan.
- Per contract, the ⋯ menu rescans it, runs a technology scan, or sets a status for all its (shown) domains.

## Review lists

Hand a set of domains to someone else (an agent) to check, then record your decision on each.

1. On **Contracts**, filter what you want checked: a quick filter or chip (for example **Site: Down**) and **All / Domains / Subdomains**.
2. Click **Create review list**. Choose the **list type** (below), name it, choose the password, untick any domains you want to leave out (**Leave them out** unticks the ones that do not fit the type at the last scan). The first list sets the **master password**; later lists use it, or get their own password.
3. Copy the link and send it with the password. The agent signs in with their name and, for each domain, sees the domain, contract, server and site status, with **Open**, the answers for the list type, and **Add note**.
4. On the list (left panel, **Review lists**) you see every answer as it arrives and record your decision, with a **note to the agent** that shows on their page. **Rescan** re-checks the listed domains; **CSV** downloads the results.

| List type | Agent answers | Your decisions |
|---|---|---|
| Website down | To be removed · Should be live | Fixed · Remove · Issue to resolve |
| Website live on IONOS shared | Migrate · Remove + keep domain · Remove + cancel domain | Moved to (each VPS from Settings) · Removed: domain kept / domain cancelled · Issue to resolve |

The types are defined in `public/reviewtypes.js`. Answers and decisions are also written to each domain's Activity log. Closing a list keeps it readable for the agent but stops changes. Deleting a list (the bin on the Review lists page, or **Delete list** on the list) asks you to type `DELETE`. The agent never sees your notes, blockers or other tracker data.

**Sharing the link.** The tracker stays on 127.0.0.1. Review pages are served on a second port (default `PORT+1`, so 4761) that only answers `/r/<list id>`. It is off until you turn on **Network sharing** under Review lists; links then use this Mac's network address. For agents outside your network, point a tunnel (for example Cloudflare Tunnel) at `http://localhost:4761` and enter its address as **Public address**. `REVIEW_PORT` changes the port; `REVIEW_HOST=127.0.0.1` keeps the review port off the local network (tunnel only).

Passwords are stored as scrypt hashes and sessions as hashed tokens. Neither is ever sent to a browser or included in the JSON export. Ten wrong passwords lock a list for 15 minutes from that address. Changing a password signs everyone out of the lists it covers.

## Site and SSL states

- **Site:** Up, Redirects (to another domain), Not set up (Plesk login or default page, parking page, server default page), Down (no response or HTTP 4xx/5xx), No DNS.
- **SSL:** Valid, Invalid (certificate presented but wrong name, expired or untrusted), No HTTPS (no certificate offered at all).

## Verification verdicts (marker based)

- **Verified**: every A/AAAA record for root and www is on a configured VPS, HTTPS works with a valid certificate, and the marker file returns that VPS's token. A redirect domain counts as verified when it is served from the VPS and lands on the redirect target from the IONOS export.
- **Old hosting**: any record (including IPv6) still points to an old-hosting range.
- **Fails checks**: DNS is on the VPS but HTTP/HTTPS fails, or the root has no address.
- **Needs review**: the marker is missing or does not match, the IPs are unrecognised, or the site is behind a CDN/proxy with no marker to confirm the origin.

## Hosted on Plesk (ionos.cormackdeveloper.co.uk)

Online, the tracker signs you in through Cormack DevToolBox (cormackdeveloper.co.uk), so there's no separate password. Hosted mode switches on when `IMT_PUBLIC_URL` is set.

- **Sign-in:** every page and API call needs a DevToolBox sign-in, except review links (`/r/…`) and the files the review page loads. Review links keep their own passwords.
- **Port 4761:** the share listener is never opened. Review links use the public address.
- **Refuses to start** if the sign-in settings are missing.

**Plesk → Node.js on the subdomain:**
- Node.js version: **22**
- Application root: `/ionos` (outside the subdomain's document folder)
- Document root: `/ionos/public`
- Application startup file: `app.cjs` (Passenger loads it with `require()`; it imports `server.js`)
- Application mode: production

**Custom environment variables:**

| Name | Value |
|---|---|
| `IMT_PUBLIC_URL` | `https://ionos.cormackdeveloper.co.uk` |
| `IMT_SSO_SECRET` | the same value as `DTB_SSO_SECRET` in DevToolBox (32+ characters) |
| `IMT_SSO_URL` | optional, default `https://cormackdeveloper.co.uk/sso` (the parent domain) |
| `IMT_SESSION_HOURS` | optional, default 12 (1 to 72) |

**On the DevToolBox dashboard,** add the app as a **hosted app** with the address `https://ionos.cormackdeveloper.co.uk`. The dashboard only issues tickets to hosted apps.

**Data:** copy `data/store.json` (and `data/backups/` if wanted) into `/ionos/data/` once, owned by the subscription's system user. After that, the server copy is the live one. Stop using the local copy, or the two will drift apart.

**Sign out:** `/_sso/logout` ends this app's session and goes back to the dashboard.

**Source scans** use SSH from the machine the tracker runs on. On the server there are no SSH keys for the sites, so those scans report "ssh" errors. DNS, site, SSL and tech scans work as before.

## Data handling

- Auth codes and contact columns (RegC/AdminC/TechC) are never stored.
- Source scans read a directory listing and a fixed list of config files. Only the database type, host and name are kept. Credentials are never extracted.
- SSH runs with `BatchMode=yes`, so it never prompts for or stores passwords.
