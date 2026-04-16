package scanner

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"secretfinder/internal/pattern"
	"secretfinder/pkg/config"
	"strings"
	"sync"
	"time"
)

// SecretMatch represents a single secret match
type SecretMatch struct {
	PatternName  string
	Description  string
	Category     string
	Severity     string
	Match        string
	LineNumber   int
	Line         string
	ContextBefore []string
	ContextAfter  []string
	FilePath     string
}

// FileResult represents results from scanning a single file
type FileResult struct {
	FilePath  string
	Secrets   []SecretMatch
	Error     string
	ScanTime  time.Duration
}

// Results holds all scan results
type Results struct {
	Files         []FileResult
	FilesScanned  int
	PatternsUsed  int
	StartTime     time.Time
	EndTime       time.Time
}

// Scanner handles the secret scanning process
type Scanner struct {
	config     config.Config
	patternLib  *pattern.PatternLibrary
	httpClient  *http.Client
	activePatterns []pattern.Pattern
}

// New creates a new Scanner instance
func New(cfg config.Config) *Scanner {
	lib := pattern.NewLibrary()

	// Get patterns based on configuration
	activePatterns := lib.GetPatterns(cfg.Patterns)

	return &Scanner{
		config:    cfg,
		patternLib: lib,
		httpClient: &http.Client{
			Timeout: time.Duration(cfg.Timeout) * time.Second,
		},
		activePatterns: activePatterns,
	}
}

// Process starts the scanning process
func (s *Scanner) Process(ctx context.Context) (*Results, error) {
	results := &Results{
		Files:        make([]FileResult, 0),
		StartTime:    time.Now(),
		PatternsUsed: len(s.activePatterns),
	}

	// Get list of sources to scan
	sources, err := s.getSources()
	if err != nil {
		return nil, fmt.Errorf("failed to get sources: %w", err)
	}

	if s.config.Verbose {
		fmt.Printf("Found %d sources to scan\n", len(sources))
	}

	// Scan sources concurrently
	resultsChan := s.scanSources(ctx, sources)

	// Collect results
	for result := range resultsChan {
		results.Files = append(results.Files, result)
		if result.Error == "" {
			results.FilesScanned++
		}

		// Print progress if verbose
		if s.config.Verbose && result.Error == "" {
			fmt.Printf("Scanned %s: found %d secrets\n", result.FilePath, len(result.Secrets))
		}
	}

	results.EndTime = time.Now()
	return results, nil
}

// getSources returns a list of sources to scan
func (s *Scanner) getSources() ([]string, error) {
	input := strings.TrimSpace(s.config.Input)

	// Check if it's a URL
	if s.isURL(input) {
		return []string{input}, nil
	}

	// Check if it's a file containing URLs
	if s.config.IsURLList() {
		return s.readURLList(input)
	}

	// Otherwise treat as a single file path
	return []string{input}, nil
}

// isURL checks if the input is a URL
func (s *Scanner) isURL(input string) bool {
	return strings.HasPrefix(input, "http://") || strings.HasPrefix(input, "https://")
}

// readURLList reads URLs from a file
func (s *Scanner) readURLList(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open URL list file: %w", err)
	}
	defer file.Close()

	var urls []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			urls = append(urls, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading URL list: %w", err)
	}

	if len(urls) == 0 {
		return nil, fmt.Errorf("no URLs found in file")
	}

	return urls, nil
}

// scanSources scans multiple sources concurrently
func (s *Scanner) scanSources(ctx context.Context, sources []string) <-chan FileResult {
	resultChan := make(chan FileResult, len(sources))

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, s.config.Workers)

	for _, source := range sources {
		wg.Add(1)
		go func(src string) {
			defer wg.Done()

			// Acquire semaphore
			select {
			case semaphore <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-semaphore }()

			result := s.scanSource(ctx, src)

			select {
			case resultChan <- result:
			case <-ctx.Done():
			}
		}(source)
	}

	// Close result channel when all workers are done
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	return resultChan
}

// scanSource scans a single source
func (s *Scanner) scanSource(ctx context.Context, source string) FileResult {
	startTime := time.Now()

	result := FileResult{
		FilePath: source,
	}

	// Get content
	content, err := s.fetchContent(ctx, source)
	if err != nil {
		result.Error = fmt.Sprintf("failed to fetch content: %v", err)
		return result
	}

	// Scan for secrets
	secrets := s.scanContent(content, source)
	result.Secrets = secrets
	result.ScanTime = time.Since(startTime)

	return result
}

// fetchContent fetches content from a URL or file
func (s *Scanner) fetchContent(ctx context.Context, source string) (string, error) {
	if s.isURL(source) {
		return s.fetchURLContent(ctx, source)
	}
	return s.readFileContent(source)
}

// fetchURLContent fetches content from a URL
func (s *Scanner) fetchURLContent(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("User-Agent", s.config.UserAgent)

	// Add cookies if provided
	if s.config.Cookies != "" {
		req.Header.Set("Cookie", s.config.ParseCookieHeader())
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch URL: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	return string(content), nil
}

// readFileContent reads content from a file
func (s *Scanner) readFileContent(filename string) (string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	content, err := io.ReadAll(file)
	if err != nil {
		return "", fmt.Errorf("failed to read file: %w", err)
	}

	return string(content), nil
}

// scanContent scans content for secrets
func (s *Scanner) scanContent(content, filePath string) []SecretMatch {
	lines := strings.Split(content, "\n")
	var secrets []SecretMatch

	for lineNum, line := range lines {
		for _, pat := range s.activePatterns {
			matches := pat.Regex.FindAllStringSubmatchIndex(line, -1)
			for _, match := range matches {
				if len(match) >= 2 {
					// Extract the matched secret
					start, end := match[0], match[1]

					// For patterns with capture groups, try to get the captured group
					var matchedSecret string
					if len(match) > 2 && match[2] != -1 && match[3] != -1 {
						matchedSecret = line[match[2]:match[3]]
					} else {
						matchedSecret = line[start:end]
					}

					secret := SecretMatch{
						PatternName: pat.Name,
						Description: pat.Description,
						Category:    pat.Category,
						Severity:    pat.Severity,
						Match:       matchedSecret,
						LineNumber:  lineNum + 1,
						Line:        strings.TrimSpace(line),
						FilePath:    filePath,
					}

					// Add context if requested
					if s.config.IncludeContext {
						contextStart := lineNum - s.config.ContextLines
						if contextStart < 0 {
							contextStart = 0
						}
						contextEnd := lineNum + s.config.ContextLines + 1
						if contextEnd > len(lines) {
							contextEnd = len(lines)
						}

						secret.ContextBefore = lines[contextStart:lineNum]
						secret.ContextAfter = lines[lineNum+1:contextEnd]
					}

					secrets = append(secrets, secret)
				}
			}
		}
	}

	return secrets
}

// TotalSecrets returns the total number of secrets found
func (r *Results) TotalSecrets() int {
	count := 0
	for _, file := range r.Files {
		count += len(file.Secrets)
	}
	return count
}

// GetSecretsBySeverity returns secrets grouped by severity
func (r *Results) GetSecretsBySeverity() map[string][]SecretMatch {
	result := make(map[string][]SecretMatch)
	for _, file := range r.Files {
		for _, secret := range file.Secrets {
			result[secret.Severity] = append(result[secret.Severity], secret)
		}
	}
	return result
}

// GetSecretsByCategory returns secrets grouped by category
func (r *Results) GetSecretsByCategory() map[string][]SecretMatch {
	result := make(map[string][]SecretMatch)
	for _, file := range r.Files {
		for _, secret := range file.Secrets {
			result[secret.Category] = append(result[secret.Category], secret)
		}
	}
	return result
}

// Write writes the results to a file or stdout
func (r *Results) Write(outputPath string, noColors bool) error {
	var output io.Writer

	if strings.ToLower(outputPath) == "cli" {
		output = os.Stdout
	} else {
		file, err := os.Create(outputPath)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer file.Close()
		output = file
	}

	// Write results
	writer := bufio.NewWriter(output)
	defer writer.Flush()

	// Header
	fmt.Fprintf(writer, "Secret Scan Results\n")
	fmt.Fprintf(writer, "==================\n\n")
	fmt.Fprintf(writer, "Scan Time: %s to %s\n", r.StartTime.Format(time.RFC3339), r.EndTime.Format(time.RFC3339))
	fmt.Fprintf(writer, "Files Scanned: %d\n", r.FilesScanned)
	fmt.Fprintf(writer, "Patterns Used: %d\n", r.PatternsUsed)
	fmt.Fprintf(writer, "Total Secrets Found: %d\n\n", r.TotalSecrets())

	// Group by severity
	bySeverity := r.GetSecretsBySeverity()

	// Order of severity display
	severityOrder := []string{"critical", "high", "medium", "low"}

	for _, severity := range severityOrder {
		secrets := bySeverity[severity]
		if len(secrets) == 0 {
			continue
		}

		// Print severity header
		if !noColors && outputPath == "cli" {
			severityColor := getSeverityColor(severity)
			fmt.Fprintf(writer, "\n%s[%s] %d secrets%s\n", severityColor, strings.ToUpper(severity), len(secrets), "\x1b[0m")
		} else {
			fmt.Fprintf(writer, "\n[%s] %d secrets\n", strings.ToUpper(severity), len(secrets))
		}

		// Print secrets
		for _, secret := range secrets {
			fmt.Fprintf(writer, "\n  File: %s\n", secret.FilePath)
			fmt.Fprintf(writer, "    Pattern: %s (%s)\n", secret.PatternName, secret.Description)
			fmt.Fprintf(writer, "    Category: %s\n", secret.Category)

			if !noColors && outputPath == "cli" {
				severityColor := getSeverityColor(severity)
				fmt.Fprintf(writer, "    Severity: %s%s%s\n", severityColor, strings.ToUpper(severity), "\x1b[0m")
			} else {
				fmt.Fprintf(writer, "    Severity: %s\n", strings.ToUpper(severity))
			}

			fmt.Fprintf(writer, "    Match: %s\n", secret.Match)

			// Print context if available
			if len(secret.ContextBefore) > 0 || len(secret.ContextAfter) > 0 {
				fmt.Fprintf(writer, "    Context:\n")
				for _, ctxLine := range secret.ContextBefore {
					fmt.Fprintf(writer, "      %s\n", strings.TrimSpace(ctxLine))
				}
				if !noColors && outputPath == "cli" {
					fmt.Fprintf(writer, "      \x1b[1;33m>> %s\x1b[0m\n", strings.TrimSpace(secret.Line))
				} else {
					fmt.Fprintf(writer, "    >> %s\n", strings.TrimSpace(secret.Line))
				}
				for _, ctxLine := range secret.ContextAfter {
					fmt.Fprintf(writer, "      %s\n", strings.TrimSpace(ctxLine))
				}
			}
		}
	}

	// Summary
	fmt.Fprintf(writer, "\n\nSummary:\n")
	fmt.Fprintf(writer, "-------\n")
	for _, severity := range severityOrder {
		if count := len(bySeverity[severity]); count > 0 {
			fmt.Fprintf(writer, "  %s: %d\n", strings.ToUpper(severity), count)
		}
	}

	return nil
}

// getSeverityColor returns ANSI color code for severity
func getSeverityColor(severity string) string {
	switch severity {
	case "critical":
		return "\x1b[1;31m" // Red
	case "high":
		return "\x1b[1;33m" // Yellow
	case "medium":
		return "\x1b[1;36m" // Cyan
	case "low":
		return "\x1b[1;34m" // Blue
	default:
		return "\x1b[0m" // Reset
	}
}
