# SecretFinder

A high-performance Go tool for discovering secrets, API keys, and sensitive data in JavaScript files. SecretFinder scans for patterns matching common services like Google, AWS, Stripe, Facebook, and many others.

## Features

- **63 Pre-built Patterns**: Built-in regex patterns for detecting secrets from 100+ services
- **Concurrent Processing**: Multi-threaded scanning for fast results
- **Cookie Support**: Scan authenticated JavaScript files by passing cookies
- **Multiple Input Methods**: URLs, local files, or lists of URLs
- **Flexible Output**: Results to file or stdout with optional color coding
- **Context Extraction**: Show surrounding code around matches
- **Pattern Filtering**: Scan for specific patterns or categories

## Supported Services

SecretFinder can detect secrets from:

**Cloud Providers**
- AWS (Access Keys, Secret Keys, Session Tokens, Account IDs)
- Google (API Keys, OAuth tokens, Firebase, reCAPTCHA)
- Azure (Storage Keys, App Insights)
- Heroku API Keys

**Version Control**
- GitHub (Personal Access Tokens, OAuth Tokens, App Tokens)

**Payment Processing**
- Stripe (Publishable/Secret Keys)
- PayPal (Client IDs/Secrets)
- Square (Access Tokens, API Keys)

**Communication**
- Slack (Webhooks, Bot Tokens, App Tokens)
- Discord (Webhooks, Bot Tokens)
- Telegram (Bot Tokens)

**Social Media**
- Facebook/Meta (Access Tokens, App Secrets)
- Twitter/X (API Keys, Secrets, Bearer Tokens)

**Database & Storage**
- Database connection strings (MongoDB, MySQL, PostgreSQL, Redis)
- Dropbox API Keys/Secrets

**Developer Tools**
- Auth0 Client Secrets
- Shopify Access Tokens/API Secrets
- SendGrid API Keys
- Twilio Account SIDs/Auth Tokens
- Mailgun API Keys
- Datadog API Keys
- New Relic API Keys
- Zoom API Keys/Secrets
- npm Auth Tokens

**Other**
- JWT Tokens
- Private Keys (RSA, etc.)
- Generic API Keys and Secrets
- Base64 encoded data

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/secretfinder.git
cd secretfinder

# Build the tool
go build -o secretfinder main.go

# (Optional) Install to system
sudo mv secretfinder /usr/local/bin/
```

## Usage

### Basic Usage

```bash
# Scan a single URL
secretfinder -i https://example.com/app.js

# Scan a local file
secretfinder -i /path/to/file.js

# Scan multiple URLs from a file
secretfinder -i urls.txt

# Output to stdout instead of file
secretfinder -i https://example.com/app.js -o cli

# Verbose mode
secretfinder -i https://example.com/app.js -v
```

### Advanced Usage

```bash
# Use cookies for authenticated scanning
secretfinder -i https://example.com/app.js -c "session=abc123; token=xyz789"

# Custom user agent
secretfinder -i https://example.com/app.js -u "MyCustomUserAgent/1.0"

# Scan for specific patterns only
secretfinder -i https://example.com/app.js -p aws,google,stripe

# Include context around matches
secretfinder -i https://example.com/app.js -x -l 3

# Disable colored output
secretfinder -i https://example.com/app.js -o cli -n

# Custom timeout and workers
secretfinder -i urls.txt -t 30 -w 50
```

### Input Methods

**1. Direct URL:**
```bash
secretfinder -i https://example.com/app.js
```

**2. Local File:**
```bash
secretfinder -i /path/to/local/file.js
```

**3. URL List File:**
Create a file `urls.txt` with one URL per line:
```
https://example.com/app1.js
https://example.com/app2.js
https://api.example.com/config.js
```

Then scan:
```bash
secretfinder -i urls.txt
```

**4. Stdin:**
```bash
echo "https://example.com/app.js" | secretfinder -o cli
```

Or interactive:
```bash
secretfinder -i -
# Then paste URLs (press Ctrl+D when done)
```

### Cookie Support

For authenticated JavaScript files, pass cookies in the format `key1=value1; key2=value2`:

```bash
secretfinder -i https://example.com/protected/app.js \
  -c "session=your_session_token; auth=your_auth_token"
```

### Pattern Filtering

Scan for specific patterns or categories:

```bash
# Only AWS secrets
secretfinder -i app.js -p aws

# Multiple categories
secretfinder -i app.js -p aws,google,stripe

# Output with CLI formatting
secretfinder -i app.js -p jwt,database -o cli
```

## Command Line Options

| Flag | Description | Default |
|------|-------------|---------|
| `-i, --input` | Input: URL, file, or URL list file | required |
| `-o, --output` | Output file ('cli' for stdout) | secrets.txt |
| `-c, --cookies` | Cookies for authenticated requests | empty |
| `-u, --user-agent` | User-Agent header | Mozilla/5.0 |
| `-t, --timeout` | Request timeout in seconds | 10 |
| `-w, --workers` | Number of worker goroutines | CPU*2 |
| `-v, --verbose` | Enable verbose output | false |
| `-x, --context` | Include surrounding context | false |
| `-l, --context-lines` | Number of context lines | 2 |
| `-p, --patterns` | Patterns to match (all/aws/google/etc.) | all |
| `-n, --no-colors` | Disable colored output | false |
| `-h, --help` | Show help message | |
| `--version` | Show version | |

## Output Format

SecretFinder outputs results grouped by severity:

```
Secret Scan Results
==================

Scan Time: 2026-04-16T16:01:09+06:00 to 2026-04-16T16:01:09+06:00
Files Scanned: 1
Patterns Used: 63
Total Secrets Found: 20

[CRITICAL] 3 secrets

  File: test.js
    Line: 11
    Pattern: stripe-secret-key (Stripe Secret Key)
    Category: stripe
    Severity: CRITICAL
    Match: sk_live_51Msw1234567890abcdefghijklmnopqrstuv
    Line: const stripeKey = "sk_live_51Msw1234567890abcdefghijklmnopqrstuv";

[HIGH] 3 secrets
...
```

## Examples

### Example 1: Scan a Website's JavaScript

```bash
secretfinder -i https://example.com/assets/app.js -o cli -v
```

### Example 2: Scan Multiple Files

```bash
# Create URL list
cat > urls.txt << EOF
https://example.com/app.js
https://example.com/config.js
https://api.example.com/sdk.js
EOF

# Scan all URLs
secretfinder -i urls.txt -o report.txt -v
```

### Example 3: Authenticated Scanning

```bash
secretfinder -i https://dashboard.example.com/app.js \
  -c "session_id=abc123; auth_token=xyz789" \
  -o cli
```

### Example 4: Targeted Pattern Search

```bash
# Only look for AWS secrets
secretfinder -i https://example.com/app.js -p aws -o cli

# Multiple specific patterns
secretfinder -i https://example.com/app.js -p aws,google,github -o cli
```

### Example 5: With Context

```bash
# Show 3 lines before and after each match
secretfinder -i app.js -x -l 3 -o cli
```

## Tips for Best Results

1. **Use verbose mode** (`-v`) to see scan progress
2. **Start with all patterns** to get a complete picture, then filter if needed
3. **Use context** (`-x`) to understand how secrets are being used
4. **Check both critical and high severity** findings first
5. **For authenticated sites**, always test with cookies first
6. **Scan minified and unminified** JS files separately
7. **Look for configuration files** (`config.js`, `settings.js`, etc.)

## Security Considerations

⚠️ **Important Security Notes:**

1. **Only scan websites you have permission to test**
2. **Handle found secrets responsibly** - report them, don't exploit them
3. **Rotate any exposed secrets immediately**
4. **Store scan results securely** - they contain sensitive data
5. **Don't commit scan results to version control**

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is for educational and authorized security testing purposes only. Users are responsible for ensuring they have proper authorization before scanning any systems. The authors are not responsible for any misuse of this tool.

## Changelog

### v1.0.0 (2026-04-16)
- Initial release
- 63 built-in patterns
- Support for URL, file, and URL list inputs
- Cookie authentication support
- Context extraction
- Concurrent processing
