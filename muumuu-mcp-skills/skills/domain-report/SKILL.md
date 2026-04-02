---
name: domain-report
description: Generate a security and health report for your domains. DNS configuration checks (SPF/DMARC/CAA/DNSSEC), subdomain takeover detection, and lookalike domain monitoring (typosquatting/homograph attacks). Triggers on "domain report", "domain audit", "DNS health", "domain security"
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

### Phase 1: Target Domain Identification & Usage Classification

1. User specifies domain → use as-is
2. No domain specified → retrieve domain list via `mcp__muumuu-domain__list-me-domains` and ask user to select
3. "All" → target all domains (confirm if more than 10)

After identifying the target domain, **classify its usage status** based on DNS records and HTTP response:

| Condition | Classification |
|-----------|---------------|
| Has A/AAAA/CNAME/ALIAS record AND HTTP 200 | **Active** (full report) |
| Has A/AAAA/CNAME/ALIAS record but no HTTP response | **Partially configured** (full report with notes) |
| NS records only, no other records | **Unused / Brand protection** (compact report) |

**For unused domains**: Skip SSL check, subdomain takeover check, and detailed lookalike tables. Focus on SPF `-all` recommendation, auto-renew status, and high-risk lookalike domains only (third-party registered).

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

#### 2-C: DNS Propagation & Security Check (via Bash)
```bash
# Check actual responses for each record type
dig +short example.com A
dig +short example.com AAAA
dig +short example.com MX
dig +short example.com TXT
dig +short example.com NS
dig +short example.com CAA
dig +short _dmarc.example.com TXT

# DNSSEC check
dig example.com DNSKEY +short
dig example.com DS +short
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

Only for **active** domains (skip for unused domains).

| Check Item | Method | Severity |
|-----------|--------|----------|
| CAA record not configured | No CAA record exists | Warning |
| SSL certificate expiry | Check via `openssl s_client` | Warning if within 30 days |

```bash
# SSL certificate check
echo | openssl s_client -servername example.com -connect example.com:443 2>/dev/null | openssl x509 -noout -dates -issuer 2>/dev/null
```

#### 3-3: DNSSEC Check

| Check Item | Method | Severity |
|-----------|--------|----------|
| DNSSEC not enabled | No DNSKEY or DS record found via `dig` | Info |

```bash
dig example.com DNSKEY +short
dig example.com DS +short
```

- If both return empty → DNSSEC is not enabled
- DNSSEC protects against DNS spoofing/cache poisoning attacks
- Severity is Info because enabling DNSSEC requires registrar support and misconfiguration can cause outages

#### 3-4: Subdomain Takeover Risk

Only for **active** domains (skip for unused domains).

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

#### 3-5: Additional Checks

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

#### 4-3: Risk Classification & Display Rules

| Status | Risk | Action |
|--------|------|--------|
| Registered by third party | High | Possible phishing site. Recommend checking actual content |
| Available | Medium | Consider defensive registration |
| Owned by you | Safe | No issue |
| Unsearchable (premium, etc.) | Unknown | Recommend manual check |

**Display rules for the report**:
- **If any third-party registrations are found**: Show full table with all results, highlighting the threats
- **If ALL lookalike domains are available (no threats)**: Show a single summary line instead of a full table:
  > "No lookalike domains registered by third parties. All {n} candidates checked are available."
- **Unsearchable/errored candidates**: Omit from table entirely. Only mention if the unsearchable domain is a major TLD variant (.com, .net, .jp)

### Phase 5: Report Generation

Generate a Markdown report and save to file.

Output path: `domain-report-{domain}-{YYYYMMDD}.md`

**IMPORTANT: Report structure rules**:

1. **Start with an Executive Summary** (2-3 lines max) stating the domain's status and the top actions needed. The reader should understand the situation without reading further.

2. **Use the user's language** for the report content. Detect from conversation context.

3. **After presenting the report**, offer to fix actionable items via MCP:
   - "Would you like me to add the SPF record via MCP now?"
   - "Would you like me to add the DMARC record?"
   - "Would you like me to add the CAA record?"
   This turns the report from read-only into an actionable workflow.

#### Report Template

```markdown
# Domain Security Report - {domain}

Generated: {YYYY-MM-DD}

> **Executive Summary**: {1-2 sentence description of domain status and key actions needed}
> Example: "yaserarenai.dev is an active domain hosted on Lolipop Managed Cloud. SPF and DMARC are not configured — email spoofing is possible. Add `v=spf1 -all` and enable auto-renewal."
> Example (unused): "mouda.me has no DNS records configured (brand protection only). Add `v=spf1 -all` to prevent email spoofing. No lookalike domain threats detected."

## Summary

| Item | Result |
|------|--------|
| Domain | {domain} |
| State | {active/inactive} |
| Classification | {Active / Unused / Partially configured} |
| Expiry | {expiry_date} |
| Auto-renew | {Enabled/Disabled} |
| DNS Records | {count} |
| Issues Found | Critical: {n}, Warning: {n}, Info: {n} |

## DNS Health Check

### Critical
{Only show if critical issues exist}

### Warning
{Only show if warnings exist}

### Info
{Only show if info items exist}

## Subdomain Takeover Risk
{Only for active domains. Omit section entirely for unused domains.}

## Similar Domain Monitoring

{If no third-party registrations found:}
> No lookalike domains registered by third parties were detected. {n} candidates checked across typosquatting, homograph, and TLD variants — all available.

{If third-party registrations found: show full table with ONLY the threats, plus a count of safe candidates}

## Recommendations

| Priority | Action | Details |
|----------|--------|---------|
| ... | ... | ... |

## DNS Records (Reference)
{Full table of current DNS records}
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
