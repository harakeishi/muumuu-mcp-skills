---
name: domain-report
description: Generate a security and health report for your domains. DNS configuration checks (SPF/DMARC/CAA), subdomain takeover detection, and lookalike domain monitoring (typosquatting/homograph attacks). Triggers on "domain report", "domain audit", "DNS health", "domain security"
---

# Domain Report - Domain Security & Health Report

## Overview

Perform a comprehensive security and health check on your domains and generate a Markdown report.
Combines muumuu-domain MCP + dig/curl/openssl commands for diagnosis.

### Prerequisites

- [muumuu-domain MCP Server](https://github.com/because0/muumuu-domain-mcp-server) configured in Claude Code
- `dig`, `curl`, `openssl` commands available

## When to Use

- When you want to check the security posture of your domains
- For periodic DNS configuration health checks
- To monitor whether lookalike domains have been registered by third parties
- When the user says "domain report", "domain audit", "DNS health check"

## Execution Flow

### Phase 1: Target Domain Identification

1. User specifies domain → use as-is
2. No domain specified → retrieve domain list via `mcp__muumuu-domain__list-me-domains` and ask user to select
3. "All" → target all domains (confirm if more than 10)

### Phase 2: Information Gathering (Parallel Execution)

Execute the following **in parallel via sub-agents** for each target domain:

#### 2-A: Domain Basic Info
```
mcp__muumuu-domain__get-me-domain(domain-id)
```
- Retrieve domain state, expiry date

#### 2-B: Full DNS Record Retrieval
```
mcp__muumuu-domain__list-me-dns-records(domain-id, page-size: 100)
```
- Retrieve all records (handle pagination)

#### 2-C: DNS Propagation Check (via Bash)
```bash
# Check actual responses for each record type
dig +short example.com A
dig +short example.com AAAA
dig +short example.com MX
dig +short example.com TXT
dig +short example.com NS
dig +short example.com CAA
dig +short _dmarc.example.com TXT
```

#### 2-D: Lookalike Domain Search
Generate lookalike domain candidates for use in "Phase 4: Lookalike Domain Monitoring" and search via search-domains.

### Phase 3: DNS Health Check

Run the following checks against the gathered data.

#### 3-1: Email Authentication Check

| Check Item | Method | Severity |
|-----------|--------|----------|
| SPF not configured | No `v=spf1` in TXT records | Critical |
| SPF allows all (`+all`) | SPF value ends with `+all` | Critical |
| DMARC not configured | No TXT record at `_dmarc.{domain}` | Warning |
| DMARC policy is `none` | Running with `p=none` | Info |
| DKIM not found | No DKIM selector in TXT records | Info (hard to detect; informational only) |

**SPF Check Details**:
```
v=spf1 include:_spf.google.com ~all  → OK
v=spf1 include:_spf.google.com -all  → OK (strict)
v=spf1 +all                           → Allows all (dangerous)
No SPF record                          → Spoofing possible
```

**DMARC Check Details**:
```
v=DMARC1; p=reject; ...    → Most secure
v=DMARC1; p=quarantine; ... → Recommended level
v=DMARC1; p=none; ...      → Monitor only (hardening recommended)
No DMARC record             → No last line of defense for email auth
```

#### 3-2: SSL/CA Authentication Check

| Check Item | Method | Severity |
|-----------|--------|----------|
| CAA record not configured | No CAA record exists | Warning |
| SSL certificate expiry | Check via `openssl s_client` | Warning if within 30 days |

```bash
# SSL certificate check
echo | openssl s_client -servername example.com -connect example.com:443 2>/dev/null | openssl x509 -noout -dates -issuer 2>/dev/null
```

#### 3-3: Subdomain Takeover Risk

| Check Item | Method | Severity |
|-----------|--------|----------|
| CNAME target unresolvable | `dig` on CNAME value → NXDOMAIN | Critical |
| A record target not responding | `curl -sI --max-time 5 http://{ip}` → timeout | Warning |

**Subdomain Takeover Detection Logic**:
```
1. Retrieve all CNAME records
2. Resolve each CNAME target via dig
3. NXDOMAIN or SERVFAIL → takeover risk detected
4. Cloud service CNAMEs (*.herokuapp.com, *.azurewebsites.net, etc.) are high priority
```

Known dangerous CNAME patterns:
- `*.herokuapp.com` → Heroku
- `*.azurewebsites.net` → Azure
- `*.cloudfront.net` → CloudFront
- `*.s3.amazonaws.com` → S3
- `*.github.io` → GitHub Pages
- `*.netlify.app` → Netlify
- `*.vercel.app` → Vercel (auto-protection available)
- `*.shopify.com` → Shopify

#### 3-4: Additional Checks

| Check Item | Method | Severity |
|-----------|--------|----------|
| Wildcard DNS record | `*.domain` A/CNAME record exists | Info |
| Suspected unused A record | A record target not responding to HTTP | Info |

### Phase 4: Lookalike Domain Monitoring (Homograph / Typosquatting)

Generate lookalike domain candidates from the SLD (second-level domain) of the target and check their registration status.

#### 4-1: Lookalike Domain Candidate Generation

For target domain `example.com`:

**Typosquatting** (character swap, omission, addition):
```
examlpe.com    # adjacent character swap
exmple.com     # character omission
examplle.com   # character duplication
exampke.com    # adjacent key typo (l→k)
```
Generation rules:
- Swap adjacent 2-character pairs (all patterns)
- Single character omission (all positions)
- Single character duplication (all positions)
- Adjacent key substitution (QWERTY layout, major characters only)
- Limit to representative candidates if too many (max 15)

**Character/digit substitution (homograph-like)**:
```
examp1e.com    # l→1
exarnple.com   # m→rn
examp|e.com    # l→| (pipe)
```
Substitution table:
| Original | Substitutions |
|----------|--------------|
| l | 1, i |
| o | 0 |
| i | 1, l |
| a | 4 |
| e | 3 |
| s | 5 |
| m | rn |

**TLD variants**:
```
example.net, example.org, example.jp, example.co.jp, example.info
```

#### 4-2: Availability Check

Search generated candidates via `mcp__muumuu-domain__search-domains`:
```
mcp__muumuu-domain__search-domains(q: "examlpe.com")
mcp__muumuu-domain__search-domains(q: "examp1e", tlds: ["com", "net", "jp"])
```

**Note**: API call volume can be high, so be selective with candidates. TLD variants can be batched into a single API call using the `tlds` parameter.

#### 4-3: Risk Classification

| Status | Risk | Action |
|--------|------|--------|
| Registered by third party | High | Possible phishing site. Recommend checking actual content |
| Available | Medium | Consider defensive registration |
| Owned by you | Safe | No issue |
| Unsearchable (premium, etc.) | Unknown | Recommend manual check |

### Phase 5: Report Generation

Generate a Markdown report following the template below and save to file.

Output path: `domain-report-{domain}-{YYYYMMDD}.md`

```markdown
# Domain Security Report - {domain}

Generated: {YYYY-MM-DD HH:MM}

## Summary

| Item | Result |
|------|--------|
| Domain | {domain} |
| State | {active/inactive} |
| Expiry | {expiry_date} |
| DNS Records | {count} |
| Issues Found | Critical: {n}, Warning: {n}, Info: {n} |

## DNS Health Check

### Critical

- **[CRITICAL] SPF not configured**: Risk of email spoofing
  - Recommended: Add TXT record `v=spf1 include:{appropriate SPF source} ~all`

### Warning

- **[WARNING] DMARC not configured**: No last line of defense for email authentication
  - Recommended: Add `v=DMARC1; p=none; rua=mailto:dmarc@{domain}` and harden gradually

### Info

- **[INFO] CAA record not configured**: Any CA can issue SSL certificates for this domain
  - Recommended: Add CAA record to restrict issuance to your CA only

## Subdomain Takeover Risk

| Subdomain | Record Type | Target | Status | Risk |
|-----------|------------|--------|--------|------|
| staging.example.com | CNAME | old-app.herokuapp.com | NXDOMAIN | Critical |

## Similar Domain Monitoring

### Typosquatting

| Domain | Type | Status | Risk |
|--------|------|--------|------|
| examp1e.com | Digit substitution (l→1) | Registered by third party | High |
| examlpe.com | Character swap | Available | Medium |

### TLD Variants

| Domain | Status | Risk |
|--------|--------|------|
| example.net | Available | Medium |
| example.org | Registered by third party | High |

## Recommendations

1. **[Immediate]** Configure SPF record
2. **[Recommended]** Set DMARC to `p=quarantine` or higher
3. **[Recommended]** Remove CNAME for staging.example.com (takeover risk)
4. **[Consider]** Defensive registration of example.net

## DNS Records (Reference)

| FQDN | Type | Value | TTL |
|------|------|-------|-----|
| example.com. | A | 76.76.21.21 | 300 |
| ... | ... | ... | ... |
```

## Implementation Notes

### API Call Efficiency

- Use `page-size: 100` for `list-me-dns-records` to fetch all at once
- Batch lookalike domain searches using the `tlds` parameter
- Use sub-agents for parallel execution when targeting multiple domains

### dig Command Fallback

If `dig` is unavailable, use `nslookup` or `host`:
```bash
# If dig is unavailable
nslookup -type=TXT _dmarc.example.com
host -t MX example.com
```

### Error Handling

- MCP auth error → prompt user to re-authenticate
- Domain not found → retry with FQDN filter on `list-me-domains`
- dig timeout → use `dig +time=3` for 3-second timeout
- Lookalike domain search API error → skip and note "search unavailable" in report

### Multiple Domains

When targeting more than 10 domains:
1. Confirm with AskUserQuestion whether to proceed with all
2. Generate individual report files per domain
3. Generate a separate summary report:

```markdown
# Domain Portfolio Summary - {YYYY-MM-DD}

| Domain | Expiry | Critical | Warning | Info |
|--------|--------|----------|---------|------|
| example.com | 2027/03/15 | 1 | 2 | 1 |
| example.jp | 2026/06/01 | 0 | 0 | 1 |
```
