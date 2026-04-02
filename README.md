# muumuu-mcp-skills

A collection of [Claude Code](https://docs.anthropic.com/en/docs/claude-code) skills for the [Muumuu Domain MCP Server](https://github.com/because0/muumuu-domain-mcp-server).

## Skills

### `/domain-report` - Domain Security & Health Report

Performs a comprehensive security and health check on your domains and generates a Markdown report.

**What it checks:**

- **DNS Health**: SPF / DMARC / CAA record configuration
- **SSL Certificates**: Expiry dates, issuer verification
- **Subdomain Takeover**: CNAME target liveness checks
- **Lookalike Domain Monitoring**: Typosquatting and homograph attack detection

**Usage:**

```
/domain-report example.com
```

**Example output:**

```
Domain Security Report - example.com

Issues Found: Critical 1 / Warning 2 / Info 1

- [CRITICAL] SPF not configured: Email spoofing risk
- [WARNING] DMARC not configured: No last line of defense for email auth
- [WARNING] CAA not configured: Any CA can issue SSL certificates
```

## Prerequisites

1. [Claude Code](https://docs.anthropic.com/en/docs/claude-code) installed
2. [Muumuu Domain MCP Server](https://github.com/because0/muumuu-domain-mcp-server) configured

## Installation

### Step 1: Add the marketplace

```
/plugin marketplace add harakeishi/muumuu-mcp-skills
```

### Step 2: Install the plugin

```
/plugin install muumuu-mcp-skills@harakeishi-muumuu-mcp-skills
```

### Alternative: Local testing

```bash
claude --plugin-dir /path/to/muumuu-mcp-skills
```

## License

MIT
