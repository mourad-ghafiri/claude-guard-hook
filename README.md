# claude-guard

A global Claude Code hook that intercepts sensitive data before it reaches the LLM — secrets, API keys, PII, and system info are replaced with `{{GUARD:...}}` placeholders. When Claude writes back, real values are transparently restored.

> **Note**: This is a **hook**, not a plugin. Hooks intercept Claude's built-in tools (Read, Write, Bash) via `~/.claude/settings.json`. They work silently in the background.

## Quick start

```bash
git clone https://github.com/mourad-ghafiri/claude-guard-hook
cd claude-guard-hook
npm run guard:install
```

**Restart Claude Code after installing.**

## Usage

```bash
npm run guard              # Interactive menu (recommended)
npm run guard:install      # Install
npm run guard:uninstall    # Uninstall
npm run guard:reload       # Rebuild + apply changes
npm run guard status       # Show status
npm run guard patterns     # List all patterns
npm run guard help         # All commands
```

## How it works

```
User prompt ──> [UserPromptSubmit] ──> redact secrets → {{GUARD:...}}
                                       feedback: "⚠ redacted 2 secret(s)"

File read   ──> [PreToolUse Read]  ──> block protected files (mock content)
                                       redact secrets + system info

File write  ──> [PreToolUse Write] ──> restore {{GUARD:...}} → real values

Bash cmd    ──> [PreToolUse Bash]  ──> restore placeholders in commands
                                       block env dumps + protected files
```

## Strategies

| Strategy | Result | Reversible | When to use |
|----------|--------|------------|-------------|
| `placeholder` | `{{GUARD:Name:hex}}` | Yes | Default. Round-trips safely through Claude |
| `mask` | `[REDACTED]` | No | Hide completely, no trace |
| `replace` | Custom `replaceBy` value | No | Swap with a safe alternative |

## Patterns

All 48 patterns live in `config/default-config.json` — one flat list. Each pattern has `id`, `name`, `pattern` (regex), `category`, `enabled`, `redactionStrategy`, and optionally `replaceBy`.

### Add patterns — copy-paste examples

**Company info:**

```bash
npm run guard -- pattern add --name "Company Domain" --regex "acme-corp.com" --strategy replace --replaceBy "example.com"
npm run guard -- pattern add --name "Company Name" --regex "Acme Corp" --strategy replace --replaceBy "Company"
npm run guard -- pattern add --name "Internal API" --regex "https://api.acme-corp.com" --strategy replace --replaceBy "https://api.example.com"
npm run guard -- pattern add --name "Internal Dashboard" --regex "https://dashboard.acme-corp.com" --strategy replace --replaceBy "https://dashboard.example.com"
npm run guard -- pattern add --name "Project Name" --regex "Project Phoenix" --strategy replace --replaceBy "Project X"
npm run guard -- pattern add --name "Slack Workspace" --regex "acme-corp.slack.com" --strategy replace --replaceBy "workspace.slack.com"
npm run guard -- pattern add --name "Jira URL" --regex "acme-corp.atlassian.net" --strategy replace --replaceBy "company.atlassian.net"
```

**GitHub / repos:**

```bash
npm run guard -- pattern add --name "GitHub Org" --regex "github.com/acme-corp" --strategy replace --replaceBy "github.com/example-org"
npm run guard -- pattern add --name "Git Remote" --regex "git@github.com:acme-corp" --strategy replace --replaceBy "git@github.com:example-org"
npm run guard -- pattern add --name "GitHub API" --regex "api.github.com/repos/acme-corp" --strategy replace --replaceBy "api.github.com/repos/example-org"
npm run guard -- pattern add --name "GitLab Instance" --regex "gitlab.acme-corp.com" --strategy replace --replaceBy "gitlab.example.com"
npm run guard -- pattern add --name "NPM Scope" --regex "@acme-corp/" --strategy replace --replaceBy "@example-org/"
npm run guard -- pattern add --name "Docker Hub Org" --regex "docker.io/acme-corp/" --strategy replace --replaceBy "docker.io/example-org/"
```

**People:**

```bash
npm run guard -- pattern add --name "Employee Username" --regex "jdoe" --strategy replace --replaceBy "user123"
npm run guard -- pattern add --name "Employee Name" --regex "John Doe" --strategy replace --replaceBy "Test User"
npm run guard -- pattern add --name "Corp Email" --regex "@acme-corp.com" --strategy replace --replaceBy "@example.com"
npm run guard -- pattern add --name "Team Name" --regex "Platform Engineering" --strategy replace --replaceBy "Engineering Team"
npm run guard -- pattern add --name "Employee ID" --regex "EMP-[0-9]{6}" --category pii --strategy placeholder
```

**Infrastructure:**

```bash
npm run guard -- pattern add --name "Internal Host" --regex "internal.acme-corp.com" --strategy replace --replaceBy "internal.example.com"
npm run guard -- pattern add --name "DB Host" --regex "db-prod.acme-corp.com" --strategy replace --replaceBy "db.example.com"
npm run guard -- pattern add --name "Redis Host" --regex "redis.acme-corp.com" --strategy replace --replaceBy "cache.example.com"
npm run guard -- pattern add --name "S3 Bucket" --regex "s3://acme-" --strategy replace --replaceBy "s3://example-"
npm run guard -- pattern add --name "K8s Namespace" --regex "acme-production" --strategy replace --replaceBy "example-ns"
npm run guard -- pattern add --name "Docker Registry" --regex "registry.acme-corp.com" --strategy replace --replaceBy "registry.example.com"
```

**Secrets & auth:**

```bash
npm run guard -- pattern add --name "Internal API Key" --regex "acme_[a-zA-Z0-9]{32}" --category api_key --strategy placeholder
npm run guard -- pattern add --name "Webhook URL" --regex "hooks.slack.com/services/" --strategy mask
npm run guard -- pattern add --name "Sentry DSN" --regex "sentry.io" --strategy mask
```

**After adding patterns, apply:**

```bash
npm run guard:reload
```

### Test a pattern

```bash
npm run guard -- pattern test builtin_email "contact john@example.com please"
# Redacted: contact {{GUARD:Email Address:test1234}} please

npm run guard -- pattern test custom_company_domain "visit app.acme-corp.com/dashboard"
# Redacted: visit app.example.com/dashboard
```

### Enable / disable

```bash
npm run guard -- disable builtin_phone_us
npm run guard -- enable builtin_phone_us
```

### User config

Overrides at `~/.claude/claude-guard.json` merge by ID with defaults:

```json
{
  "patterns": [
    { "id": "builtin_email", "enabled": false },
    {
      "id": "custom_company_domain",
      "name": "Company Domain",
      "pattern": "acme-corp.com",
      "category": "infrastructure",
      "enabled": true,
      "redactionStrategy": "replace",
      "replaceBy": "example.com"
    }
  ]
}
```

### Built-in pattern categories

| Category | Patterns |
|----------|---------|
| `api_key` | AWS, OpenAI, Anthropic, Google, Azure, Stripe, SendGrid, GCP, Firebase, Supabase, Linear, Datadog |
| `credential` | Passwords, secrets, tokens, Basic Auth URLs, Azure Client Secret |
| `pii` | Credit Card, SSN, Email, Phone, Passport, IBAN |
| `token` | JWT, GitHub, GitLab, Slack, npm, PyPI, Vault, Doppler, Telegram, Vercel, Cloudflare, Docker, Terraform |
| `infrastructure` | Database URLs, Private/Public IPs, DigitalOcean |
| `file_content` | PEM Private Keys, Age Secret Keys |

## Protected files & folders

Claude is blocked from reading sensitive files. Mock placeholder content is served instead.

**Files**: `.env*`, `*.pem`, `*.key`, `credentials*`, `secrets.*`, `.npmrc`, `.netrc`, `.git-credentials`, `.pgpass`, `*.tfstate`, `terraform.tfvars`, `*.p12`, SSH keys, and configs for AWS, Azure, GCP, Docker, Kubernetes, Terraform, Helm, Vault, Vercel, Netlify, Heroku, Fly.io, Firebase, Supabase, Railway, Wrangler.

**Folders**: `.aws`, `.ssh`, `.gnupg`, `.docker`, `.kube`, `.vault.d`, `gcloud`, `.azure`, `.terraform.d`, `.helm`, `.ansible`, `.firebase`, `.vercel`, `.netlify`, `.heroku`, `.fly`, `.wrangler`, `.supabase`, `.railway`.

**Add custom protected paths** via `npm run guard` → "Manage protected files & folders".

### System info masking

| Value | Placeholder |
|-------|-------------|
| Home directory | `{{GUARD:SYS_HOMEDIR:hex}}` |
| Working directory | `{{GUARD:SYS_CWD:hex}}` |
| Username | `{{GUARD:SYS_USERNAME:hex}}` |
| Project name | `{{GUARD:SYS_PROJECT:hex}}` |

## Configuration

```bash
npm run guard config                                      # view
npm run guard config set behavior.maskSystemInfo false     # change
npm run guard config reset                                # reset
```

| Option | Default | Description |
|--------|---------|-------------|
| `enabled` | `true` | Master kill switch |
| `behavior.blockProtectedFileReads` | `true` | Block reading protected files |
| `behavior.maskSystemInfo` | `true` | Mask username, homedir, cwd, project |
| `behavior.scanUserPrompts` | `true` | Redact secrets in user prompts |
| `behavior.logDetections` | `true` | Show CLI messages on redaction |

## Development

```bash
npm install && npm run build
npm test
npm run guard:reload
```

## License

MIT
