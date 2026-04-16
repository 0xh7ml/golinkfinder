package pattern

import (
	"regexp"
	"strings"
)

// Pattern represents a secret detection pattern
type Pattern struct {
	Name        string
	Description string
	Regex       *regexp.Regexp
	Category    string
	Severity    string
}

// PatternLibrary holds all available patterns
type PatternLibrary struct {
	patterns []Pattern
	byName   map[string]*Pattern
	byCategory map[string][]*Pattern
}

// NewLibrary creates a new pattern library with all default patterns
func NewLibrary() *PatternLibrary {
	lib := &PatternLibrary{
		patterns: make([]Pattern, 0),
		byName:   make(map[string]*Pattern),
		byCategory: make(map[string][]*Pattern),
	}

	lib.registerDefaultPatterns()
	return lib
}

// GetPattern returns a pattern by name
func (lib *PatternLibrary) GetPattern(name string) (*Pattern, bool) {
	p, ok := lib.byName[strings.ToLower(name)]
	return p, ok
}

// GetPatterns returns patterns by names (or all if "all" is specified)
func (lib *PatternLibrary) GetPatterns(names []string) []Pattern {
	if len(names) == 0 || (len(names) == 1 && strings.ToLower(names[0]) == "all") {
		return lib.patterns
	}

	var result []Pattern
	seen := make(map[string]bool)

	for _, name := range names {
		name = strings.ToLower(strings.TrimSpace(name))

		// Check if it's a category
		if patterns, ok := lib.byCategory[name]; ok {
			for _, p := range patterns {
				if !seen[p.Name] {
					result = append(result, *p)
					seen[p.Name] = true
				}
			}
			continue
		}

		// Check if it's a specific pattern
		if p, ok := lib.byName[name]; ok {
			if !seen[p.Name] {
				result = append(result, *p)
				seen[p.Name] = true
			}
		}
	}

	return result
}

// GetAllCategories returns all category names
func (lib *PatternLibrary) GetAllCategories() []string {
	cats := make([]string, 0, len(lib.byCategory))
	for cat := range lib.byCategory {
		cats = append(cats, cat)
	}
	return cats
}

// registerPattern adds a pattern to the library
func (lib *PatternLibrary) registerPattern(pattern Pattern) {
	lib.patterns = append(lib.patterns, pattern)
	lib.byName[strings.ToLower(pattern.Name)] = &pattern

	if pattern.Category != "" {
		lib.byCategory[strings.ToLower(pattern.Category)] = append(
			lib.byCategory[strings.ToLower(pattern.Category)], &pattern)
	}
}

// registerDefaultPatterns registers all built-in patterns
func (lib *PatternLibrary) registerDefaultPatterns() {
	// AWS Patterns
	lib.registerPattern(Pattern{
		Name:        "aws-access-key",
		Description: "AWS Access Key ID",
		Regex:       regexp.MustCompile(`(?i)(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`),
		Category:    "aws",
		Severity:    "high",
	})
	lib.registerPattern(Pattern{
		Name:        "aws-secret-key",
		Description: "AWS Secret Access Key",
		Regex:       regexp.MustCompile(`(?i)aws_?(?:secret|access)?(?:key)?["\x27]*\s{0,30}(?::|=>|=)\s{0,30}["\x27]*([a-z0-9/+=]{40})`),
		Category:    "aws",
		Severity:    "critical",
	})
	lib.registerPattern(Pattern{
		Name:        "aws-session-token",
		Description: "AWS Session Token",
		Regex:       regexp.MustCompile(`(?i)(?:aws.?session|aws.?session.?token|aws.?token)["\x27]*\s{0,30}(?::|=>|=)\s{0,30}["\x27]*([a-z0-9/+=]{16,200})`),
		Category:    "aws",
		Severity:    "high",
	})
	lib.registerPattern(Pattern{
		Name:        "aws-account-id",
		Description: "AWS Account ID",
		Regex:       regexp.MustCompile(`(?i)aws_?(?:account)_?(?:id)?["\x27]*\s{0,30}(?::|=>|=)\s{0,30}["\x27]*([0-9]{4}-?[0-9]{4}-?[0-9]{4})`),
		Category:    "aws",
		Severity:    "medium",
	})
	lib.registerPattern(Pattern{
		Name:        "aws-mws-auth-token",
		Description: "Amazon MWS Auth Token",
		Regex:       regexp.MustCompile(`amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`),
		Category:    "aws",
		Severity:    "high",
	})

	// Google Patterns
	lib.registerPattern(Pattern{
		Name:        "google-api-key",
		Description: "Google API Key",
		Regex:       regexp.MustCompile(`(?i)(?:google|gcp)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}(AIza[0-9A-Za-z\-_]{35})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
		Category:    "google",
		Severity:    "high",
	})
	lib.registerPattern(Pattern{
		Name:        "google-oauth-client-id",
		Description: "Google OAuth Client ID",
		Regex:       regexp.MustCompile(`(?i)(?:google|oauth|client)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([0-9]+-[0-9a-z_]{32}\.apps\.googleusercontent\.com)(?:['|\"|\n|\r|\s|\x60|;]|$)`),
		Category:    "google",
		Severity:    "medium",
	})
	lib.registerPattern(Pattern{
		Name:        "google-oauth-client-secret",
		Description: "Google OAuth Client Secret",
		Regex:       regexp.MustCompile(`(?i)(?:google|oauth|client)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9\-_]{24})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
		Category:    "google",
		Severity:    "high",
	})
	lib.registerPattern(Pattern{
		Name:        "google-cloud-platform-key",
		Description: "Google Cloud Platform Service Account",
		Regex:       regexp.MustCompile(`(?i)"type":\s*"service_account"`),
		Category:    "google",
		Severity:    "critical",
	})
	lib.registerPattern(Pattern{
		Name:        "google-firebase-api-key",
		Description: "Firebase API Key",
		Regex:       regexp.MustCompile(`(?i)AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}`),
		Category:    "google",
		Severity:    "high",
	})
	lib.registerPattern(Pattern{
		Name:        "google-recaptcha-site-key",
		Description: "Google reCAPTCHA Site Key",
		Regex:       regexp.MustCompile(`(?i)6L[0-9A-Za-z_-]{38}`),
		Category:    "google",
		Severity:    "low",
	})
	lib.registerPattern(Pattern{
		Name:        "google-recaptcha-secret-key",
		Description: "Google reCAPTCHA Secret Key",
		Regex:       regexp.MustCompile(`(?i)6L[0-9A-Za-z_-]{38}`),
		Category:    "google",
		Severity:    "medium",
	})

	// Facebook/Meta Patterns
	lib.registerPattern(Pattern{
		Name:        "facebook-access-token",
		Description: "Facebook Access Token",
		Regex:       regexp.MustCompile(`(?i)(?:facebook|fb|meta)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}(EAAC[a-z0-9]{20,})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
		Category:    "facebook",
		Severity:    "high",
	})
	lib.registerPattern(Pattern{
		Name:        "facebook-app-secret",
		Description: "Facebook App Secret",
		Regex:       regexp.MustCompile(`(?i)(?:facebook|fb|meta)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-f0-9]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
		Category:    "facebook",
		Severity:    "high",
	})
	lib.registerPattern(Pattern{
		Name:        "facebook-page-access-token",
		Description: "Facebook Page Access Token",
		Regex:       regexp.MustCompile(`(?i)EAA[a-zA-Z0-9\-_]{20,}`),
		Category:    "facebook",
		Severity:    "high",
	})

	// Stripe Patterns
	lib.registerPattern(Pattern{
		Name:        "stripe-publishable-key",
		Description: "Stripe Publishable Key",
		Regex:       regexp.MustCompile(`(?i)(?:stripe)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}(pk_live_[a-zA-Z0-9]{24,})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
		Category:    "stripe",
		Severity:    "medium",
	})
	lib.registerPattern(Pattern{
		Name:        "stripe-secret-key",
		Description: "Stripe Secret Key",
		Regex:       regexp.MustCompile(`(?i)(?:stripe)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}(sk_live_[a-zA-Z0-9]{24,})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
		Category:    "stripe",
		Severity:    "critical",
	})
	lib.registerPattern(Pattern{
		Name:        "stripe-test-publishable-key",
		Description: "Stripe Test Publishable Key",
		Regex:       regexp.MustCompile(`pk_test_[a-zA-Z0-9]{24,}`),
		Category:    "stripe",
		Severity:    "low",
	})
	lib.registerPattern(Pattern{
		Name:        "stripe-test-secret-key",
		Description: "Stripe Test Secret Key",
		Regex:       regexp.MustCompile(`sk_test_[a-zA-Z0-9]{24,}`),
		Category:    "stripe",
		Severity:    "medium",
	})
	lib.registerPattern(Pattern{
		Name:        "stripe-api-key",
		Description: "Stripe API Key",
		Regex:       regexp.MustCompile(`(?i)stripe[a-z0-9_]{0,30}(?:['\"\x60]*)(?:=|:)[\s"'\x60]*([a-zA-Z]{0,4}_[a-zA-Z0-9]{24,})`),
		Category:    "stripe",
		Severity:    "critical",
	})

	// GitHub Patterns
	lib.registerPattern(Pattern{
		Name:        "github-personal-access-token",
		Description: "GitHub Personal Access Token",
		Regex:       regexp.MustCompile(`(?i)ghp_[a-zA-Z0-9]{36}`),
		Category:    "github",
		Severity:    "critical",
	})
	lib.registerPattern(Pattern{
		Name:        "github-oauth-access-token",
		Description: "GitHub OAuth Access Token",
		Regex:       regexp.MustCompile(`(?i)gho_[a-zA-Z0-9]{36}`),
		Category:    "github",
		Severity:    "critical",
	})
	lib.registerPattern(Pattern{
		Name:        "github-app-token",
		Description: "GitHub App Token",
		Regex:       regexp.MustCompile(`(?i)(ghu|ghs)_[a-zA-Z0-9]{36}`),
		Category:    "github",
		Severity:    "critical",
	})
	lib.registerPattern(Pattern{
		Name:        "github-refresh-token",
		Description: "GitHub Refresh Token",
		Regex:       regexp.MustCompile(`(?i)ghr_[a-zA-Z0-9]{36}`),
		Category:    "github",
		Severity:    "high",
	})

	// Slack Patterns
	lib.registerPattern(Pattern{
		Name:        "slack-webhook",
		Description: "Slack Webhook URL",
		Regex:       regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Z0-9]{8}/B[A-Z0-9]{8,12}/[A-Za-z0-9]{24}`),
		Category:    "slack",
		Severity:    "high",
	})
	lib.registerPattern(Pattern{
		Name:        "slack-token",
		Description: "Slack Token",
		Regex:       regexp.MustCompile(`(?i)(?:slack)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}(xox[a-z]-[a-z0-9-]{10,48})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
		Category:    "slack",
		Severity:    "high",
	})
	lib.registerPattern(Pattern{
		Name:        "slack-app-token",
		Description: "Slack App Level Token",
		Regex:       regexp.MustCompile(`xapp-[1-9]-[A-Za-z0-9+-]{44,243}`),
		Category:    "slack",
		Severity:    "high",
	})

	// JWT Tokens
	lib.registerPattern(Pattern{
		Name:        "jwt-token",
		Description: "JSON Web Token",
		Regex:       regexp.MustCompile(`(?i)eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*`),
		Category:    "jwt",
		Severity:    "high",
	})

	// Azure Patterns
	lib.registerPattern(Pattern{
		Name:        "azure-storage-key",
		Description: "Azure Storage Account Key",
		Regex:       regexp.MustCompile(`(?i)(?:AccountName|SharedAccessKeyName|SharedSecretIssuer)\s*=\s*([^;]{1,80})\s*;\s*.{0,10}\s*(?:AccountKey|SharedAccessKey|SharedSecretValue)\s*=\s*([^;]{1,100})(?:;|$)`),
		Category:    "azure",
		Severity:    "critical",
	})
	lib.registerPattern(Pattern{
		Name:        "azure-app-insights-key",
		Description: "Azure Application Insights Key",
		Regex:       regexp.MustCompile(`(?i)APPINSIGHTS_INSTRUMENTATIONKEY=([a-z0-9-]+)`),
		Category:    "azure",
		Severity:    "medium",
	})
	lib.registerPattern(Pattern{
		Name:        "azure-connection-string",
		Description: "Azure Connection String",
		Regex:       regexp.MustCompile(`(?i)(?:AccountKey|SharedAccessKey|DefaultEndpointsProtocol)\s*=\s*[^;]+;?.*`),
		Category:    "azure",
		Severity:    "critical",
	})

	// Twitter/X Patterns
	lib.registerPattern(Pattern{
		Name:        "twitter-api-key",
		Description: "Twitter API Key",
		Regex:       regexp.MustCompile(`(?i)(?:twitter|x)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{25})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
		Category:    "twitter",
		Severity:    "medium",
	})
	lib.registerPattern(Pattern{
		Name:        "twitter-api-secret",
		Description: "Twitter API Secret",
		Regex:       regexp.MustCompile(`(?i)(?:twitter|x)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{50})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
		Category:    "twitter",
		Severity:    "high",
	})
	lib.registerPattern(Pattern{
		Name:        "twitter-bearer-token",
		Description: "Twitter Bearer Token",
		Regex:       regexp.MustCompile(`(?i)AAAAAAAA[a-zA-Z0-9%-_]{35,}`),
		Category:    "twitter",
		Severity:    "high",
	})

	// Auth0 Patterns
	lib.registerPattern(Pattern{
		Name:        "auth0-client-secret",
		Description: "Auth0 Client Secret",
		Regex:       regexp.MustCompile(`(?i)(?:auth0)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-zA-Z0-9_-]{43})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
		Category:    "auth0",
		Severity:    "high",
	})

	// Shopify Patterns
	lib.registerPattern(Pattern{
		Name:        "shopify-access-token",
		Description: "Shopify Access Token",
		Regex:       regexp.MustCompile(`shpat_[a-zA-Z0-9]{32}`),
		Category:    "shopify",
		Severity:    "high",
	})
	lib.registerPattern(Pattern{
		Name:        "shopify-api-secret",
		Description: "Shopify API Secret",
		Regex:       regexp.MustCompile(`(?i)(?:shopify)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
		Category:    "shopify",
		Severity:    "critical",
	})

	// PayPal Patterns
	lib.registerPattern(Pattern{
		Name:        "paypal-client-id",
		Description: "PayPal Client ID",
		Regex:       regexp.MustCompile(`(?i)(?:paypal)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{32,})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
		Category:    "paypal",
		Severity:    "medium",
	})
	lib.registerPattern(Pattern{
		Name:        "paypal-client-secret",
		Description: "PayPal Client Secret",
		Regex:       regexp.MustCompile(`(?i)(?:paypal)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{40,})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
		Category:    "paypal",
		Severity:    "high",
	})

	// Telegram Patterns
	lib.registerPattern(Pattern{
		Name:        "telegram-bot-token",
		Description: "Telegram Bot Token",
		Regex:       regexp.MustCompile(`(?i)(?:telegram)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([0-9]{8,10}:[A-Za-z0-9_-]{35})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
		Category:    "telegram",
		Severity:    "high",
	})

	// SendGrid Patterns
	lib.registerPattern(Pattern{
		Name:        "sendgrid-api-key",
		Description: "SendGrid API Key",
		Regex:       regexp.MustCompile(`(?i)(?:sendgrid)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}(SG\.[a-zA-Z0-9_-]{22,}\.[a-zA-Z0-9_-]{43,})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
		Category:    "sendgrid",
		Severity:    "high",
	})

	// Twilio Patterns
	lib.registerPattern(Pattern{
		Name:        "twilio-account-sid",
		Description: "Twilio Account SID",
		Regex:       regexp.MustCompile(`(?i)(?:twilio)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}(AC[a-z0-9_]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
		Category:    "twilio",
		Severity:    "medium",
	})
	lib.registerPattern(Pattern{
		Name:        "twilio-auth-token",
		Description: "Twilio Auth Token",
		Regex:       regexp.MustCompile(`(?i)(?:twilio)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
		Category:    "twilio",
		Severity:    "high",
	})

	// Mailgun Patterns
	lib.registerPattern(Pattern{
		Name:        "mailgun-api-key",
		Description: "Mailgun API Key",
		Regex:       regexp.MustCompile(`(?i)(?:mailgun)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}(key-[a-z0-9]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
		Category:    "mailgun",
		Severity:    "high",
	})

	// Datadog Patterns
	lib.registerPattern(Pattern{
		Name:        "datadog-api-key",
		Description: "Datadog API Key",
		Regex:       regexp.MustCompile(`(?i)(?:datadog)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
		Category:    "datadog",
		Severity:    "high",
	})

	// New Relic Patterns
	lib.registerPattern(Pattern{
		Name:        "newrelic-api-key",
		Description: "New Relic API Key",
		Regex:       regexp.MustCompile(`(?i)(?:newrelic|new-relic|nr)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}(NRAK-[a-zA-Z0-9]{27})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
		Category:    "newrelic",
		Severity:    "high",
	})

	// Square Patterns
	lib.registerPattern(Pattern{
		Name:        "square-access-token",
		Description: "Square Access Token",
		Regex:       regexp.MustCompile(`(?i)(?:square)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}(EAAA[a-zA-Z0-9_-]{60})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
		Category:    "square",
		Severity:    "high",
	})
	lib.registerPattern(Pattern{
		Name:        "square-api-key",
		Description: "Square API Key",
		Regex:       regexp.MustCompile(`(?i)(?:square)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}(sandbox|production):[a-z0-9_-]{22}(?:['|\"|\n|\r|\s|\x60|;]|$)`),
		Category:    "square",
		Severity:    "high",
	})

	// Dropbox Patterns
	lib.registerPattern(Pattern{
		Name:        "dropbox-api-key",
		Description: "Dropbox API Key",
		Regex:       regexp.MustCompile(`(?i)(?:dropbox)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{15})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
		Category:    "dropbox",
		Severity:    "medium",
	})
	lib.registerPattern(Pattern{
		Name:        "dropbox-api-secret",
		Description: "Dropbox API Secret",
		Regex:       regexp.MustCompile(`(?i)(?:dropbox)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{16})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
		Category:    "dropbox",
		Severity:    "high",
	})

	// Heroku Patterns
	lib.registerPattern(Pattern{
		Name:        "heroku-api-key",
		Description: "Heroku API Key",
		Regex:       regexp.MustCompile(`(?i)(?:heroku)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
		Category:    "heroku",
		Severity:    "high",
	})

	// Zoom Patterns
	lib.registerPattern(Pattern{
		Name:        "zoom-api-key",
		Description: "Zoom API Key",
		Regex:       regexp.MustCompile(`(?i)(?:zoom)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9_-]{20,})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
		Category:    "zoom",
		Severity:    "high",
	})
	lib.registerPattern(Pattern{
		Name:        "zoom-api-secret",
		Description: "Zoom API Secret",
		Regex:       regexp.MustCompile(`(?i)(?:zoom)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
		Category:    "zoom",
		Severity:    "high",
	})

	// Discord Patterns
	lib.registerPattern(Pattern{
		Name:        "discord-webhook",
		Description: "Discord Webhook URL",
		Regex:       regexp.MustCompile(`https://discordapp\.com/api/webhooks/[0-9]+/[A-Za-z0-9\-]+`),
		Category:    "discord",
		Severity:    "high",
	})
	lib.registerPattern(Pattern{
		Name:        "discord-webhook-alt",
		Description: "Discord Webhook URL (Alternative)",
		Regex:       regexp.MustCompile(`https://discord\.com/api/webhooks/[0-9]+/[A-Za-z0-9\-]+`),
		Category:    "discord",
		Severity:    "high",
	})
	lib.registerPattern(Pattern{
		Name:        "discord-bot-token",
		Description: "Discord Bot Token",
		Regex:       regexp.MustCompile(`(?i)(?:discord)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([A-Za-z0-9_-]{24,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{27,})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
		Category:    "discord",
		Severity:    "critical",
	})

	// npm Patterns
	lib.registerPattern(Pattern{
		Name:        "npm-auth-token",
		Description: "npm Auth Token",
		Regex:       regexp.MustCompile(`(?i)(?:npm)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}(//registry\.npmjs\.org/:_authToken=[a-z0-9\-]{36})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
		Category:    "npm",
		Severity:    "high",
	})

	// Generic API Key Patterns
	lib.registerPattern(Pattern{
		Name:        "generic-api-key",
		Description: "Generic API Key",
		Regex:       regexp.MustCompile(`(?i)(?:api[_-]?key|apikey|api-key|key)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9\-_]{16,64})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
		Category:    "generic",
		Severity:    "medium",
	})
	lib.registerPattern(Pattern{
		Name:        "generic-secret",
		Description: "Generic Secret",
		Regex:       regexp.MustCompile(`(?i)(?:secret|password|pass|pwd|token)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9\-_]{16,64})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
		Category:    "generic",
		Severity:    "medium",
	})
	lib.registerPattern(Pattern{
		Name:        "base64-string",
		Description: "Potential Base64 Encoded Secret",
		Regex:       regexp.MustCompile(`(?:[A-Za-z0-9+/]{32}={0,2}|[A-Za-z0-9+/]{40}={0,2}|[A-Za-z0-9+/]{64}={0,2})`),
		Category:    "generic",
		Severity:    "low",
	})

	// Database Connection Strings
	lib.registerPattern(Pattern{
		Name:        "database-connection-string",
		Description: "Database Connection String",
		Regex:       regexp.MustCompile(`(?i)(?:mongodb|mysql|postgres|redis|postgresql)(?:\+[\w]+)?:\/\/(?:[^\s:]+:[^\s@]+@)?[^\s/]+(?:\/[^\s?]*)?`),
		Category:    "database",
		Severity:    "critical",
	})

	// Private Key Patterns
	lib.registerPattern(Pattern{
		Name:        "private-key",
		Description: "Private Key",
		Regex:       regexp.MustCompile(`-----BEGIN [A-Z]+ PRIVATE KEY-----`),
		Category:    "crypto",
		Severity:    "critical",
	})
	lib.registerPattern(Pattern{
		Name:        "rsa-private-key",
		Description: "RSA Private Key",
		Regex:       regexp.MustCompile(`-----BEGIN RSA PRIVATE KEY-----`),
		Category:    "crypto",
		Severity:    "critical",
	})
}
