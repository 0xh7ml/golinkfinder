package output

import (
	"encoding/json"
	"fmt"
	"golinkfinder/internal/finder"
	"golinkfinder/pkg/config"
	"html/template"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"golang.org/x/term"
)

// Handler manages different output formats
type Handler struct {
	config config.Config
}

// New creates a new output handler
func New(cfg config.Config) *Handler {
	return &Handler{
		config: cfg,
	}
}

// Generate creates output based on configuration
func (h *Handler) Generate(result *finder.Result) error {
	if h.config.IsOutputCLI() {
		return h.generateCLIOutput(result)
	}

	return h.generateHTMLOutput(result)
}

// generateCLIOutput outputs results to CLI
func (h *Handler) generateCLIOutput(result *finder.Result) error {
	// Collect all unique endpoints
	endpoints := h.collectUniqueEndpoints(result)

	// Sort endpoints for consistent output
	sort.Strings(endpoints)

	// Print endpoints
	for _, endpoint := range endpoints {
		if h.config.NoColors {
			fmt.Println(endpoint)
		} else {
			h.printColoredEndpoint(endpoint)
		}
	}

	if h.config.Verbose {
		fmt.Fprintf(os.Stderr, "\nFound %d unique endpoints\n", len(endpoints))
	}

	return nil
}

// collectUniqueEndpoints extracts all unique endpoints from results
func (h *Handler) collectUniqueEndpoints(result *finder.Result) []string {
	seen := make(map[string]bool)
	var endpoints []string

	for _, file := range result.Files {
		for _, endpoint := range file.Endpoints {
			// Normalize the endpoint for deduplication
			normalized := h.normalizeEndpoint(endpoint.Link)
			if !seen[normalized] {
				seen[normalized] = true
				endpoints = append(endpoints, normalized)
			}
		}
	}

	return endpoints
}

// normalizeEndpoint normalizes paths for better deduplication
func (h *Handler) normalizeEndpoint(endpoint string) string {
	// Don't normalize full URLs or data URLs
	if strings.HasPrefix(endpoint, "http://") || strings.HasPrefix(endpoint, "https://") ||
		strings.HasPrefix(endpoint, "data:") || strings.HasPrefix(endpoint, "ftp://") ||
		strings.HasPrefix(endpoint, "ws://") || strings.HasPrefix(endpoint, "wss://") {
		return endpoint
	}

	// Don't normalize content types
	if strings.Contains(endpoint, "/") && (strings.HasPrefix(endpoint, "application/") ||
		strings.HasPrefix(endpoint, "text/") || strings.HasPrefix(endpoint, "image/") ||
		strings.HasPrefix(endpoint, "audio/") || strings.HasPrefix(endpoint, "video/")) {
		return endpoint
	}

	// For paths, ensure they start with / for consistency
	if strings.HasPrefix(endpoint, "api/") {
		return "/" + endpoint
	}

	// Remove trailing slashes for consistency (except root)
	if len(endpoint) > 1 && strings.HasSuffix(endpoint, "/") {
		return endpoint[:len(endpoint)-1]
	}

	return endpoint
}

// printColoredEndpoint prints an endpoint with color coding
func (h *Handler) printColoredEndpoint(endpoint string) {
	// Check if output is to a terminal (TTY)
	if !h.isTerminal() {
		// If not a terminal (e.g., redirected to file), print without colors
		fmt.Println(endpoint)
		return
	}

	// Color codes
	const (
		colorReset = "\033[0m"
		colorBlue  = "\033[34m"
		colorCyan  = "\033[36m"
	)

	// Determine color based on endpoint characteristics
	color := colorReset

	if strings.HasPrefix(endpoint, "http://") || strings.HasPrefix(endpoint, "https://") {
		color = colorBlue // External URLs
	} else if strings.HasPrefix(endpoint, "data:") {
		color = colorCyan // Data URLs
	}

	fmt.Printf("%s%s%s\n", color, endpoint, colorReset)
}

// isTerminal checks if stdout is a terminal (TTY)
func (h *Handler) isTerminal() bool {
	return term.IsTerminal(int(os.Stdout.Fd()))
}

// generateHTMLOutput creates an HTML report
func (h *Handler) generateHTMLOutput(result *finder.Result) error {
	// Generate HTML content
	htmlContent, err := h.generateHTML(result)
	if err != nil {
		return fmt.Errorf("failed to generate HTML: %w", err)
	}

	// Write to file
	file, err := os.Create(h.config.Output)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()

	if _, err := file.WriteString(htmlContent); err != nil {
		return fmt.Errorf("failed to write HTML content: %w", err)
	}

	// Get absolute path for URL
	absPath, err := filepath.Abs(h.config.Output)
	if err != nil {
		absPath = h.config.Output
	}

	fileURL := fmt.Sprintf("file://%s", absPath)
	fmt.Printf("Output saved to: %s\n", fileURL)

	// Open in browser if possible
	if h.config.Verbose {
		h.openInBrowser(fileURL)
	}

	return nil
}

// generateHTML creates the HTML content
func (h *Handler) generateHTML(result *finder.Result) (string, error) {
	// HTML template
	htmlTemplate := `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>golinkfinder Results - {{.Timestamp}}</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      line-height: 1.6;
      margin: 0;
      padding: 20px;
      background-color: #f5f5f5;
    }
    .header {
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
      padding: 30px;
      border-radius: 10px;
      margin-bottom: 30px;
      box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }
    .header h1 {
      margin: 0 0 10px 0;
      font-size: 2.5em;
    }
    .header .subtitle {
      opacity: 0.9;
      font-size: 1.1em;
    }
    .stats {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 20px;
      margin-bottom: 30px;
    }
    .stat-card {
      background: white;
      padding: 20px;
      border-radius: 10px;
      box-shadow: 0 2px 4px rgba(0,0,0,0.1);
      text-align: center;
    }
    .stat-number {
      font-size: 2em;
      font-weight: bold;
      color: #667eea;
      display: block;
    }
    .stat-label {
      color: #666;
      margin-top: 5px;
    }
    .file-section {
      background: white;
      margin-bottom: 20px;
      border-radius: 10px;
      box-shadow: 0 2px 4px rgba(0,0,0,0.1);
      overflow: hidden;
    }
    .file-header {
      background: #f8f9fa;
      padding: 15px 20px;
      border-bottom: 1px solid #e9ecef;
    }
    .file-title {
      font-size: 1.2em;
      font-weight: bold;
      margin: 0;
      word-break: break-all;
    }
    .file-stats {
      font-size: 0.9em;
      color: #666;
      margin-top: 5px;
    }
    .endpoints {
      padding: 0;
    }
    .endpoint {
      padding: 15px 20px;
      border-bottom: 1px solid #f1f3f4;
      transition: background-color 0.2s;
    }
    .endpoint:hover {
      background-color: #f8f9fa;
    }
    .endpoint:last-child {
      border-bottom: none;
    }
    .endpoint-link {
      font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
      font-size: 0.95em;
      color: #2563eb;
      text-decoration: none;
      display: block;
      margin-bottom: 8px;
      word-break: break-all;
    }
    .endpoint-link:hover {
      text-decoration: underline;
    }
    .endpoint-context {
      background: #f8f9fa;
      border-left: 4px solid #e5e7eb;
      padding: 10px;
      font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
      font-size: 0.85em;
      line-height: 1.4;
      white-space: pre-wrap;
      color: #374151;
      border-radius: 4px;
    }
    .endpoint-meta {
      display: flex;
      gap: 15px;
      font-size: 0.8em;
      color: #6b7280;
      margin-bottom: 8px;
    }
    .endpoint-type {
      background: #dbeafe;
      color: #1e40af;
      padding: 2px 8px;
      border-radius: 12px;
      font-weight: 500;
    }
    .no-endpoints {
      padding: 40px;
      text-align: center;
      color: #666;
    }
    .error {
      background: #fef2f2;
      color: #dc2626;
      padding: 15px 20px;
      border-left: 4px solid #fecaca;
      margin: 10px 20px;
      border-radius: 4px;
    }
    .footer {
      text-align: center;
      margin-top: 40px;
      padding: 20px;
      color: #666;
      font-size: 0.9em;
    }
    .search-box {
      background: white;
      padding: 20px;
      border-radius: 10px;
      box-shadow: 0 2px 4px rgba(0,0,0,0.1);
      margin-bottom: 20px;
    }
    .search-input {
      width: 100%;
      padding: 12px;
      border: 1px solid #d1d5db;
      border-radius: 6px;
      font-size: 16px;
    }
    .search-input:focus {
      outline: none;
      border-color: #667eea;
      box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
    }
  </style>
</head>
<body>
  <div class="header">
    <h1>🔗 golinkfinder Results</h1>
    <div class="subtitle">Generated on {{.Timestamp}} with {{.Summary.TotalFiles}} files processed</div>
  </div>

  <div class="stats">
    <div class="stat-card">
      <span class="stat-number">{{.Summary.TotalFiles}}</span>
      <div class="stat-label">Files Processed</div>
    </div>
    <div class="stat-card">
      <span class="stat-number">{{.TotalUniqueEndpoints}}</span>
      <div class="stat-label">Unique Endpoints</div>
    </div>
    <div class="stat-card">
      <span class="stat-number">{{.Summary.ProcessedFiles}}</span>
      <div class="stat-label">Successful</div>
    </div>
    <div class="stat-card">
      <span class="stat-number">{{.Summary.FailedFiles}}</span>
      <div class="stat-label">Failed</div>
    </div>
  </div>

  <div class="search-box">
    <input type="text" class="search-input" placeholder="🔍 Search endpoints..." onkeyup="filterEndpoints(this.value)">
  </div>

  {{range .Files}}
  <div class="file-section" data-source="{{.Source}}">
    <div class="file-header">
      <h2 class="file-title">📁 {{.Source}}</h2>
      <div class="file-stats">
        {{.Stats.EndpointCount}} endpoints • {{.Stats.ProcessTime}} • {{.Stats.Size}} bytes
      </div>
    </div>
    
    {{if .Error}}
    <div class="error">
      ❌ Error: {{.Error}}
    </div>
    {{else if .Endpoints}}
    <div class="endpoints">
      {{range .Endpoints}}
      <div class="endpoint" data-endpoint="{{.Link}}">
        {{if .Type}}
        <div class="endpoint-meta">
          <span class="endpoint-type">{{.Type}}</span>
          {{if .Line}}<span>Line {{.Line}}</span>{{end}}
        </div>
        {{end}}
        <a href="{{.Link}}" class="endpoint-link" target="_blank" rel="noopener noreferrer">{{.Link}}</a>
        {{if .Context}}
        <div class="endpoint-context">{{.Context}}</div>
        {{end}}
      </div>
      {{end}}
    </div>
    {{else}}
    <div class="no-endpoints">
      ℹ️ No endpoints found in this file
    </div>
    {{end}}
  </div>
  {{end}}

  <div class="footer">
    <p>Generated by <strong>golinkfinder v2.0</strong> • {{.Summary.TotalEndpoints}} total endpoints found</p>
    <p><a href="https://github.com/GerbenJavado/golinkfinder" target="_blank">🚀 View on GitHub</a></p>
  </div>

  <script>
    function filterEndpoints(query) {
      const sections = document.querySelectorAll('.file-section');
      const searchQuery = query.toLowerCase();
      
      sections.forEach(section => {
        const endpoints = section.querySelectorAll('.endpoint');
        let hasVisibleEndpoint = false;
        
        endpoints.forEach(endpoint => {
          const endpointText = endpoint.dataset.endpoint.toLowerCase();
          const isVisible = endpointText.includes(searchQuery);
          endpoint.style.display = isVisible ? 'block' : 'none';
          if (isVisible) hasVisibleEndpoint = true;
        });
        
        // Hide entire file section if no endpoints match
        section.style.display = hasVisibleEndpoint ? 'block' : 'none';
      });
    }
    
    // Add click-to-copy functionality
    document.querySelectorAll('.endpoint-link').forEach(link => {
      link.addEventListener('click', function(e) {
        if (e.ctrlKey || e.metaKey) {
          e.preventDefault();
          navigator.clipboard.writeText(this.textContent).then(() => {
            const originalText = this.textContent;
            this.textContent = '✅ Copied!';
            setTimeout(() => {
              this.textContent = originalText;
            }, 1000);
          });
        }
      });
    });
  </script>
</body>
</html>`

	// Prepare template data
	data := struct {
		*finder.Result
		TotalUniqueEndpoints int
	}{
		Result:               result,
		TotalUniqueEndpoints: result.TotalEndpoints(),
	}

	// Parse and execute template
	tmpl, err := template.New("html").Parse(htmlTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to parse template: %w", err)
	}

	var output strings.Builder
	if err := tmpl.Execute(&output, data); err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}

	return output.String(), nil
}

// openInBrowser attempts to open the file in the default browser
func (h *Handler) openInBrowser(url string) {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		return
	}

	if err := cmd.Start(); err != nil {
		// Silently fail if we can't open the browser
		return
	}
}

// GenerateJSON exports results as JSON
func (h *Handler) GenerateJSON(result *finder.Result) (string, error) {
	jsonData, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal JSON: %w", err)
	}

	return string(jsonData), nil
}
