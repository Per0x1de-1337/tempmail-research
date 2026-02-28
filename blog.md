# How Temp Email Providers Beat Blocklists With Shared MX Infrastructure

I wanted to test a simple idea: can disposable-email domains be found earlier by looking at MX infrastructure instead of waiting for public blocklists?

The answer from this run was yes. Blocklists catch domains one at a time. The mail infrastructure behind those domains is often shared across many names.

That means the useful signal is not the domain name. It is the MX host.

## What I Ran

This was live data from `2026-02-25`, with the public blocklist pinned to the end of February 2026. No accounts were created and no email was sent. SMTP validation used `RCPT TO` probes only.


| Stage                         | Source                                         | Volume                      |
| ----------------------------- | ---------------------------------------------- | --------------------------- |
| Public blocklist snapshot     | `disposable-email-domains` GitHub at `523cca1` | 5,173 domains               |
| February 2026 blocklist delta | git commit diffs from Feb 1-25                 | 111 new domains             |
| Reference MX fingerprint      | 27 major temp email providers                  | 37 unique MX hosts          |
| Blocklist MX sample           | February additions plus random sample          | 406 domains resolved        |
| Detection gap                 | whois creation date vs blocklist commit        | 25 February additions       |
| CT example                    | crt.sh certificate timestamp                   | 1 domain, `imashr.com`      |
| Catch-all validation          | SMTP `RCPT TO` probe                           | 6 cluster domains           |
| Certstream feed               | `wss://certstream.calidog.io/`                 | 75-second listen, timed out |


Scripts:

```text
tempmail/temp_email_ct_research.py
```

Outputs:

```text
tempmail/outputs/temp_email_feb2026_findings.json
tempmail/outputs/detection_gap_feb2026.json
```

## Blocklists Move One Domain At A Time

February 2026 alone added 111 domains to the public blocklist across 13 git commits.

That sounds active until you look at how operators scale. A temp-email operator does not need a new mail system for every new domain. They can register another domain, point MX at an existing backend, and keep going until the new name is reported.

Resolving MX records for 406 blocklisted domains gave me 290 domains with live MX records. Multiple MX hosts each served 20 or more blocklisted domains.

The largest clusters in the February sample:


| MX host(s)                                      | Domains in sample | Pattern                                         |
| ----------------------------------------------- | ----------------- | ----------------------------------------------- |
| `smtp.yopmail.com`                              | 43                | Yopmail satellite batch                         |
| `mail.wabblywabble.com` + `mail.wallywatts.com` | 22                | random short `.com` names, dual MX              |
| `route1/2/3.mx.cloudflare.net`                  | 21                | Cloudflare Email Routing, `mytemp.email` family |
| `mail.casadorock.com`                           | 22                | short random `.us` and `.org` names             |


None of the wabblywabble-cluster domains said "temp" in the name:

```text
cimario.com
aixind.com
icubik.com
dnsclick.com
ixunbo.com
```

They looked like expired startups or typo domains. They all resolved to the same dual MX pair:

```text
mail.wabblywabble.com
mail.wallywatts.com
```

That is the evasion model:

```text
new domain -> old mail server -> zero keyword signal
```

## The Wabblywabble Cluster

This was the strongest non-Yopmail finding in the February run.

Twenty-two domains in the blocklist sample pointed at the wabblywabble/wallywatts dual-MX pair. Every domain I checked had both MX records.

Examples from the February additions:

```text
cimario.com      MX  mail.wabblywabble.com, mail.wallywatts.com
aixind.com       MX  mail.wabblywabble.com, mail.wallywatts.com
hopesx.com       MX  mail.wabblywabble.com, mail.wallywatts.com
icubik.com       MX  mail.wabblywabble.com, mail.wallywatts.com
dnsclick.com     MX  mail.wabblywabble.com, mail.wallywatts.com
ixunbo.com       MX  mail.wabblywabble.com, mail.wallywatts.com
```

## Reference MX Fingerprints

I built the fingerprint from 27 reference providers: Guerrilla Mail, Mailinator, Yopmail, temp-mail.org, mail.tm, and others.

The high-signal MX hosts:

```text
smtp.yopmail.com                yopmail.com satellites
mail.wabblywabble.com           dual-MX cluster
mail.wallywatts.com             dual-MX cluster
route{1,2,3}.mx.cloudflare.net  mytemp.email family
mail.guerrillamail.com          guerrillamail.com, sharklasers.com
in.mail.tm                      mail.tm
mx.yandex.net                   tempmailo.com, mail.tm
mx.maildrop.cc                  maildrop.cc
```

Of 111 domains added to the blocklist in February 2026, 60 matched a reference MX at blocklist time.

```text
reference MX hit rate: 60/111 = 54.1%
```

## The Detection Gap

I measured the time between domain registration and blocklist inclusion for February where whois returned useful dates.

For domains registered in 2025, the gap looked like this:


| Domain             | Registered | Blocklisted | Gap      |
| ------------------ | ---------- | ----------- | -------- |
| `dumbass.nl`       | 2025-08-05 | 2026-02-11  | 190 days |
| `pdf-cutter.com`   | 2025-05-18 | 2026-02-11  | 269 days |
| `rbs1.xyz`         | 2025-01-10 | 2026-02-11  | 397 days |
| `rulersonline.com` | 2025-01-14 | 2026-02-11  | 393 days |


Summary:

```text
median gap: 331 days
range:      190-397 days
```

Legacy domains inflate the overall picture. `dnsclick.com` was registered in 2017 and blocklisted in February 2026. That 2,986-day gap says less about current temp-mail spin-up behavior than the 2025 registrations do.

The 2025 subset is the useful view: newly created disposable-email domains were live for six to thirteen months before public blocklist inclusion.

## The CT Example

One domain in this run showed the CT-plus-MX pattern directly.

On `2026-02-23`, crt.sh showed `imashr.com` receiving its first TLS certificate. At research time, it was not on the public blocklist. Its MX resolved to:

```text
mail.wabblywabble.com
mail.wallywatts.com
```

That was the same cluster as `cimario.com` and `aixind.com`.

The blocklist added `imashr.com` 89 days later, on `2026-05-23`.

That is the timing window I care about. CT shows the domain exists. MX shows where mail flows. The blocklist arrives later.

## Catch-All Probing Is Getting Weaker

SMTP `RCPT TO` against a random address used to be a useful disposable-email test. In this run it worked as confirmation, not as the primary signal.

On the wabblywabble cluster sample, four of six domains confirmed catch-all. On a wider February sample including Yopmail and Cloudflare-route domains, many returned `550` on RCPT despite being disposable by MX match and blocklist presence.

That looks like hardening against random recipient probes.

I would still use RCPT probing after the MX signal is strong. I would not use it as the first filter.

## Scoring Model

Based on this run, I would start with a score like this:


| Signal                                             | Weight | Why                    |
| -------------------------------------------------- | ------ | ---------------------- |
| MX matches reference temp-email backend            | 4      | direct fingerprint hit |
| MX host serves 3+ blocklisted domains              | 3      | cluster expansion      |
| Domain registered within 90 days                   | 2      | fresh spin-up risk     |
| Catch-all RCPT confirmed                           | 2      | useful confirmation    |
| Domain contains `temp`, `trash`, or `fake` keyword | 1      | weak and easy to avoid |


The workflow would be:

```text
new domain observed
  -> resolve MX
  -> compare against known disposable MX fingerprints
  -> compare MX host against blocklisted-neighbor clusters
  -> add age and catch-all confirmation if available
```

I would not block only because a domain shares MX with a suspicious cluster. Shared mail infrastructure can create false positives. I would use it as a queueing signal, especially when the domain is new and the MX host already serves multiple disposable domains.

## Reproducing The Run

Pin the blocklist to the end of February 2026:

```bash
git clone https://github.com/disposable-email-domains/disposable-email-domains.git
cd disposable-email-domains
git checkout 523cca1
```

Run the research pipeline:

```bash
cd tempmail
python3 main.py --skip-certstream
```

This writes `outputs/temp_email_feb2026_findings.json` and `outputs/detection_gap_feb2026.json`.

## Closing Notes

Blocklists of disposable-email domains work, but they are late.

In this February 2026 run, newly registered temp-email domains operated for a median of 331 days before appearing on the public blocklist. Sixty of 111 February additions shared MX with known reference backends and could have been flagged at DNS propagation. The wabblywabble cluster had 22 domains on the same dual MX pair with no naming pattern.

The detection surface I would build on is not "domain is on a blocklist." It is "domain just pointed MX at mail infrastructure already serving disposable email."

For that, MX fingerprinting and cluster detection are the pieces that matter. CT monitoring adds timing when the network path allows it.