package parser

import (
	"fmt"
	"regexp"
	"strings"
)

// LinkPattern represents different types of link patterns we can find
type LinkPattern struct {
	Name        string
	Regex       *regexp.Regexp
	Description string
}

// Endpoint represents a found endpoint with context
type Endpoint struct {
	Link     string            `json:"link"`
	Context  string            `json:"context,omitempty"`
	Line     int               `json:"line,omitempty"`
	Column   int               `json:"column,omitempty"`
	Type     string            `json:"type,omitempty"`
	Source   string            `json:"source,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// Parser handles JavaScript parsing and endpoint extraction
type Parser struct {
	patterns     []LinkPattern
	contextLines int
}

// New creates a new parser instance
func New() *Parser {
	p := &Parser{
		contextLines: 3, // Number of context lines to include
	}
	p.initializePatterns()
	return p
}

// initializePatterns sets up all the regex patterns for finding endpoints
func (p *Parser) initializePatterns() {
	// Comprehensive patterns to match Python linkfinder coverage
	patterns := []LinkPattern{
		{
			Name:        "absolute_urls",
			Regex:       regexp.MustCompile(`(?:"(https?://[^"\s]+)"|'(https?://[^'\s]+)'|` + "`" + `(https?://[^` + "`" + `\s]+)` + "`" + `)`),
			Description: "Complete HTTP/HTTPS URLs",
		},
		{
			Name:        "api_endpoints_quoted",
			Regex:       regexp.MustCompile(`(?:"(/api/[^"\s]*)|'(/api/[^'\s]*)'|` + "`" + `(/api/[^` + "`" + `\s]*)` + "`" + `)`),
			Description: "API endpoints with quotes",
		},
		{
			Name:        "api_endpoints_unquoted",
			Regex:       regexp.MustCompile(`\b(api/v\d+/[a-zA-Z0-9_\-/]+)\b`),
			Description: "API endpoints without leading slash or quotes",
		},
		{
			Name:        "versioned_endpoints",
			Regex:       regexp.MustCompile(`(?:"(/v\d+/[^"\s]*)|'(/v\d+/[^'\s]*)'|` + "`" + `(/v\d+/[^` + "`" + `\s]*)` + "`" + `)`),
			Description: "Versioned API endpoints",
		},
		{
			Name:        "path_segments",
			Regex:       regexp.MustCompile(`(?:"((?:/[a-zA-Z0-9_\-]+){2,}(?:/[a-zA-Z0-9_\-]*)*(?:\?[^"\s]*)?)|'((?:/[a-zA-Z0-9_\-]+){2,}(?:/[a-zA-Z0-9_\-]*)*(?:\?[^'\s]*)?)'|` + "`" + `((?:/[a-zA-Z0-9_\-]+){2,}(?:/[a-zA-Z0-9_\-]*)*(?:\?[^` + "`" + `\s]*)?)` + "`" + `)`),
			Description: "Multi-segment URL paths",
		},
		{
			Name:        "static_assets",
			Regex:       regexp.MustCompile(`(?:"([^"\s]*\.(png|jpg|jpeg|gif|webp|svg|ico|css|js|woff|woff2|ttf|eot)(?:\?[^"\s]*)?)|'([^'\s]*\.(png|jpg|jpeg|gif|webp|svg|ico|css|js|woff|woff2|ttf|eot)(?:\?[^'\s]*)?)'|` + "`" + `([^` + "`" + `\s]*\.(png|jpg|jpeg|gif|webp|svg|ico|css|js|woff|woff2|ttf|eot)(?:\?[^` + "`" + `\s]*)?)` + "`" + `)`),
			Description: "Static assets with common extensions",
		},
		{
			Name:        "content_types",
			Regex:       regexp.MustCompile(`\b(application/[a-zA-Z0-9\-+]+|text/[a-zA-Z0-9\-+]+|image/[a-zA-Z0-9\-+]+|audio/[a-zA-Z0-9\-+]+|video/[a-zA-Z0-9\-+]+)\b`),
			Description: "MIME content types",
		},
		{
			Name:        "file_extensions",
			Regex:       regexp.MustCompile(`(?:"([^"\s]*\.[a-zA-Z0-9]{2,4}(?:\?[^"\s]*)?)|'([^'\s]*\.[a-zA-Z0-9]{2,4}(?:\?[^'\s]*)?)'|` + "`" + `([^` + "`" + `\s]*\.[a-zA-Z0-9]{2,4}(?:\?[^` + "`" + `\s]*)?)` + "`" + `)`),
			Description: "Files with extensions",
		},
		{
			Name:        "relative_paths",
			Regex:       regexp.MustCompile(`(?:"(\.\./[^"\s]*|\.\/[^"\s]*)|'(\.\./[^'\s]*|\.\/[^'\s]*)'|` + "`" + `(\.\./[^` + "`" + `\s]*|\.\/[^` + "`" + `\s]*)` + "`" + `)`),
			Description: "Relative paths",
		},
		{
			Name:        "base64_data_urls",
			Regex:       regexp.MustCompile(`(?:"(data:[^";]+;base64,[^"]+)|'(data:[^';]+;base64,[^']+)')`),
			Description: "Base64 data URLs",
		},
		{
			Name:        "ajax_urls",
			Regex:       regexp.MustCompile(`(?i)(?:url|href|src|action|endpoint|baseURL)\s*[:=]\s*(?:"([^"\s]+)"|'([^'\s]+)'|` + "`" + `([^` + "`" + `\s]+)` + "`" + `)`),
			Description: "AJAX and form URLs",
		},
		{
			Name:        "fetch_urls",
			Regex:       regexp.MustCompile(`(?i)fetch\s*\(\s*(?:"([^"\s]+)"|'([^'\s]+)'|` + "`" + `([^` + "`" + `\s]+)` + "`" + `)`),
			Description: "Fetch API URLs",
		},
		{
			Name:        "websocket_urls",
			Regex:       regexp.MustCompile(`(?i)(?:new\s+)?websocket\s*\(\s*(?:"(wss?://[^"\s]+)"|'(wss?://[^'\s]+)'|` + "`" + `(wss?://[^` + "`" + `\s]+)` + "`" + `)`),
			Description: "WebSocket URLs",
		},
	}

	p.patterns = patterns
}

// ParseContent extracts endpoints from JavaScript content
func (p *Parser) ParseContent(content, source string, includeContext bool, filterRegex *regexp.Regexp) ([]Endpoint, error) {
	if content == "" {
		return nil, fmt.Errorf("empty content")
	}

	var allEndpoints []Endpoint
	lines := strings.Split(content, "\n")

	// Process each pattern
	for _, pattern := range p.patterns {
		matches := pattern.Regex.FindAllStringSubmatch(content, -1)
		matchPositions := pattern.Regex.FindAllStringSubmatchIndex(content, -1)

		for i, match := range matches {
			// Extract the actual endpoint from capture groups
			endpoint := ""
			for j := 1; j < len(match); j++ {
				if match[j] != "" {
					endpoint = match[j]
					break
				}
			}

			if endpoint == "" {
				continue
			}

			// Clean and validate the endpoint
			endpoint = p.cleanEndpoint(endpoint)
			if !p.isValidEndpoint(endpoint) {
				continue
			}

			// Apply filter if provided
			if filterRegex != nil && !filterRegex.MatchString(endpoint) {
				continue
			}

			// Find line and column
			var lineNum, colNum int
			var context string

			if i < len(matchPositions) && includeContext {
				pos := matchPositions[i][0]
				lineNum, colNum = p.findLineColumn(content, pos)
				context = p.extractContext(lines, lineNum-1) // Convert to 0-based index
			}

			ep := Endpoint{
				Link:   endpoint,
				Source: source,
				Type:   pattern.Name,
				Line:   lineNum,
				Column: colNum,
			}

			if includeContext {
				ep.Context = context
			}

			allEndpoints = append(allEndpoints, ep)
		}
	}

	// Remove duplicates while preserving context from first occurrence
	return p.removeDuplicates(allEndpoints), nil
}

// cleanEndpoint cleans and normalizes the endpoint
func (p *Parser) cleanEndpoint(endpoint string) string {
	// Remove leading/trailing whitespace
	endpoint = strings.TrimSpace(endpoint)

	// Remove quotes if present
	if len(endpoint) >= 2 {
		if (endpoint[0] == '"' && endpoint[len(endpoint)-1] == '"') ||
			(endpoint[0] == '\'' && endpoint[len(endpoint)-1] == '\'') ||
			(endpoint[0] == '`' && endpoint[len(endpoint)-1] == '`') {
			endpoint = endpoint[1 : len(endpoint)-1]
		}
	}

	return endpoint
}

// isValidEndpoint checks if an endpoint is valid and worth including
func (p *Parser) isValidEndpoint(endpoint string) bool {
	if endpoint == "" || len(endpoint) < 2 {
		return false
	}

	// Skip very long strings (likely not URLs)
	if len(endpoint) > 500 {
		return false
	}

	// Allow base64 data URLs
	if strings.HasPrefix(endpoint, "data:") {
		return true
	}

	// Allow content types
	if strings.Contains(endpoint, "/") && (strings.HasPrefix(endpoint, "application/") ||
		strings.HasPrefix(endpoint, "text/") || strings.HasPrefix(endpoint, "image/") ||
		strings.HasPrefix(endpoint, "audio/") || strings.HasPrefix(endpoint, "video/")) {
		return true
	}

	// Allow complete URLs
	if strings.HasPrefix(endpoint, "http://") || strings.HasPrefix(endpoint, "https://") ||
		strings.HasPrefix(endpoint, "ftp://") || strings.HasPrefix(endpoint, "ftps://") ||
		strings.HasPrefix(endpoint, "ws://") || strings.HasPrefix(endpoint, "wss://") {
		return true
	}

	// Skip obvious JavaScript keywords - but be less aggressive
	jsKeywords := []string{
		"function", "return", "console.log", "document.get", "window.location",
		"this.state", "typeof", "instanceof", "undefined", "null",
	}

	endpointLower := strings.ToLower(endpoint)
	for _, keyword := range jsKeywords {
		if strings.Contains(endpointLower, keyword) {
			return false
		}
	}

	// Skip if it contains obvious JavaScript operators
	if strings.Contains(endpoint, "===") || strings.Contains(endpoint, "!==") ||
		strings.Contains(endpoint, "&&") || strings.Contains(endpoint, "||") ||
		strings.Contains(endpoint, "=>") || strings.Contains(endpoint, "...") {
		return false
	}

	// Skip if it looks like JavaScript method calls
	if strings.Contains(endpoint, "()") && !strings.HasSuffix(endpoint, ".js()") {
		return false
	}

	// Allow paths starting with /
	if strings.HasPrefix(endpoint, "/") {
		// Skip very short paths
		if len(endpoint) < 3 {
			return false
		}
		// Allow valid path characters
		for _, r := range endpoint[1:] {
			if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
				r == '/' || r == '-' || r == '_' || r == '.' || r == '?' || r == '&' || r == '=' ||
				r == '#' || r == ':' || r == '%') {
				return false
			}
		}
		return true
	}

	// Allow API endpoints without leading slash
	if strings.HasPrefix(endpoint, "api/") {
		return true
	}

	// Allow relative paths
	if strings.HasPrefix(endpoint, "./") || strings.HasPrefix(endpoint, "../") {
		return true
	}

	// Allow files with extensions
	if strings.Contains(endpoint, ".") {
		parts := strings.Split(endpoint, ".")
		if len(parts) >= 2 {
			ext := strings.ToLower(parts[len(parts)-1])
			// Common web file extensions
			validExts := []string{
				"html", "htm", "php", "asp", "aspx", "jsp", "js", "css", "json", "xml",
				"txt", "csv", "pdf", "doc", "docx", "xls", "xlsx", "zip", "rar",
				"jpg", "jpeg", "png", "gif", "webp", "svg", "ico", "bmp", "tiff",
				"mp3", "mp4", "avi", "mov", "wmv", "flv", "webm", "wav", "ogg",
				"woff", "woff2", "ttf", "eot", "otf",
				"action", "do", "cfm", "pl", "py", "rb", "go", "java", "cpp",
			}
			for _, validExt := range validExts {
				if ext == validExt {
					return true
				}
			}
		}
	}

	// Skip if it's mostly special characters (likely code)
	alphaNumCount := 0
	for _, r := range endpoint {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			alphaNumCount++
		}
	}
	if len(endpoint) > 10 && float64(alphaNumCount)/float64(len(endpoint)) < 0.3 {
		return false
	}

	return false
}

// findLineColumn finds the line and column number for a given position
func (p *Parser) findLineColumn(content string, pos int) (line, col int) {
	line = 1
	col = 1

	for i := 0; i < pos && i < len(content); i++ {
		if content[i] == '\n' {
			line++
			col = 1
		} else {
			col++
		}
	}

	return line, col
}

// extractContext extracts context lines around the found endpoint
func (p *Parser) extractContext(lines []string, lineIndex int) string {
	start := lineIndex - p.contextLines
	if start < 0 {
		start = 0
	}

	end := lineIndex + p.contextLines + 1
	if end > len(lines) {
		end = len(lines)
	}

	var contextLines []string
	for i := start; i < end; i++ {
		prefix := "  "
		if i == lineIndex {
			prefix = "► " // Mark the line with the match
		}
		contextLines = append(contextLines, prefix+strings.TrimSpace(lines[i]))
	}

	return strings.Join(contextLines, "\n")
}

// removeDuplicates removes duplicate endpoints while keeping the first occurrence
func (p *Parser) removeDuplicates(endpoints []Endpoint) []Endpoint {
	seen := make(map[string]bool)
	var unique []Endpoint

	for _, ep := range endpoints {
		if !seen[ep.Link] {
			seen[ep.Link] = true
			unique = append(unique, ep)
		}
	}

	return unique
}

// SetContextLines sets the number of context lines to extract
func (p *Parser) SetContextLines(lines int) {
	if lines >= 0 {
		p.contextLines = lines
	}
}
