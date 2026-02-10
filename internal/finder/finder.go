package finder

import (
	"context"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"golinkfinder/internal/client"
	"golinkfinder/internal/jsprocessor"
	"golinkfinder/internal/parser"
	"golinkfinder/pkg/config"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Result represents the complete result set
type Result struct {
	Files     []FileResult  `json:"files"`
	Summary   Summary       `json:"summary"`
	Config    config.Config `json:"config,omitempty"`
	Timestamp string        `json:"timestamp"`
}

// FileResult represents results from a single file/URL
type FileResult struct {
	Source    string            `json:"source"`
	Endpoints []parser.Endpoint `json:"endpoints"`
	Error     string            `json:"error,omitempty"`
	Stats     FileStats         `json:"stats"`
}

// FileStats contains statistics about file processing
type FileStats struct {
	Size          int64  `json:"size"`
	ProcessTime   string `json:"process_time"`
	EndpointCount int    `json:"endpoint_count"`
}

// Summary contains overall processing statistics
type Summary struct {
	TotalFiles     int `json:"total_files"`
	TotalEndpoints int `json:"total_endpoints"`
	ProcessedFiles int `json:"processed_files"`
	FailedFiles    int `json:"failed_files"`
}

// BurpItem represents an item in a Burp Suite export
type BurpItem struct {
	URL      string `xml:"url"`
	Response string `xml:"response"`
}

// BurpExport represents a Burp Suite export file
type BurpExport struct {
	Items []BurpItem `xml:"item"`
}

// Finder orchestrates the link finding process
type Finder struct {
	config      config.Config
	httpClient  *client.Client
	jsProcessor *jsprocessor.Processor
	parser      *parser.Parser
	filterRegex *regexp.Regexp
}

// New creates a new Finder instance
func New(cfg config.Config) *Finder {
	f := &Finder{
		config:      cfg,
		httpClient:  client.New(cfg.Workers, time.Duration(cfg.Timeout)*time.Second),
		jsProcessor: jsprocessor.New(),
		parser:      parser.New(),
	}

	// Compile filter regex if provided
	if cfg.Regex != "" {
		if regex, err := regexp.Compile(cfg.Regex); err == nil {
			f.filterRegex = regex
		}
	}

	return f
}

// Process starts the main processing workflow
func (f *Finder) Process(ctx context.Context) (*Result, error) {
	result := &Result{
		Config:    f.config,
		Timestamp: time.Now().Format(time.RFC3339),
	}

	// Parse input to get list of sources
	sources, err := f.parseInput()
	if err != nil {
		return nil, fmt.Errorf("failed to parse input: %w", err)
	}

	if f.config.Verbose {
		fmt.Printf("Processing %d sources\n", len(sources))
	}

	// Start HTTP client
	f.httpClient.Start(ctx)
	defer f.httpClient.Stop()

	// Process sources concurrently
	results := f.processSources(ctx, sources)

	// Collect results
	for fileResult := range results {
		result.Files = append(result.Files, fileResult)
		result.Summary.TotalEndpoints += fileResult.Stats.EndpointCount

		if fileResult.Error == "" {
			result.Summary.ProcessedFiles++
		} else {
			result.Summary.FailedFiles++
		}
	}

	result.Summary.TotalFiles = len(result.Files)

	return result, nil
}

// parseInput parses the input configuration and returns a list of sources to process
func (f *Finder) parseInput() ([]string, error) {
	input := strings.TrimSpace(f.config.Input)

	// Handle URLs
	if f.isURL(input) {
		return []string{input}, nil
	}

	// Handle view-source prefix
	if strings.HasPrefix(input, "view-source:") {
		return []string{input[12:]}, nil
	}

	// Handle Burp file
	if f.config.Burp {
		return f.parseBurpFile(input)
	}

	// Handle wildcard patterns
	if strings.Contains(input, "*") {
		return f.parseWildcard(input)
	}

	// Handle local file
	return f.parseLocalFile(input)
}

// isURL checks if the input is a URL
func (f *Finder) isURL(input string) bool {
	schemes := []string{"http://", "https://", "file://", "ftp://", "ftps://"}
	for _, scheme := range schemes {
		if strings.HasPrefix(input, scheme) {
			return true
		}
	}
	return false
}

// parseBurpFile parses a Burp Suite export file
func (f *Finder) parseBurpFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open Burp file: %w", err)
	}
	defer file.Close()

	var burpExport BurpExport
	if err := xml.NewDecoder(file).Decode(&burpExport); err != nil {
		return nil, fmt.Errorf("failed to parse Burp file: %w", err)
	}

	var sources []string
	for _, item := range burpExport.Items {
		// Decode base64 response
		if decoded, err := base64.StdEncoding.DecodeString(item.Response); err == nil {
			// Store as data URL for processing
			dataURL := fmt.Sprintf("data:text/javascript;base64,%s", base64.StdEncoding.EncodeToString(decoded))
			sources = append(sources, dataURL)
		}
	}

	if len(sources) == 0 {
		return nil, fmt.Errorf("no valid items found in Burp file")
	}

	return sources, nil
}

// parseWildcard handles wildcard patterns
func (f *Finder) parseWildcard(pattern string) ([]string, error) {
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, fmt.Errorf("failed to expand wildcard: %w", err)
	}

	var sources []string
	for _, match := range matches {
		if info, err := os.Stat(match); err == nil && !info.IsDir() {
			absPath, _ := filepath.Abs(match)
			sources = append(sources, "file://"+absPath)
		}
	}

	if len(sources) == 0 {
		return nil, fmt.Errorf("wildcard pattern matched no files")
	}

	return sources, nil
}

// parseLocalFile handles local file input
func (f *Finder) parseLocalFile(filename string) ([]string, error) {
	absPath, err := filepath.Abs(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path: %w", err)
	}

	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("file not found: %s", filename)
	}

	return []string{"file://" + absPath}, nil
}

// processSources processes multiple sources concurrently
func (f *Finder) processSources(ctx context.Context, sources []string) <-chan FileResult {
	resultChan := make(chan FileResult, len(sources))

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, f.config.Workers)

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

			result := f.processSource(ctx, src)

			select {
			case resultChan <- result:
			case <-ctx.Done():
				return
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

// processSource processes a single source (URL or file)
func (f *Finder) processSource(ctx context.Context, source string) FileResult {
	startTime := time.Now()

	result := FileResult{
		Source: source,
	}

	// Get content
	content, err := f.getContent(ctx, source)
	if err != nil {
		result.Error = err.Error()
		return result
	}

	// Process JavaScript
	if f.jsProcessor.IsJavaScript(content) {
		content = f.jsProcessor.Beautify(content)
	}

	// Extract endpoints
	includeContext := !f.config.IsOutputCLI()
	endpoints, err := f.parser.ParseContent(content, source, includeContext, f.filterRegex)
	if err != nil {
		result.Error = err.Error()
		return result
	}

	result.Endpoints = endpoints
	result.Stats = FileStats{
		Size:          int64(len(content)),
		ProcessTime:   time.Since(startTime).String(),
		EndpointCount: len(endpoints),
	}

	// Domain crawling if enabled
	if f.config.Domain && f.isURL(source) {
		additionalEndpoints := f.crawlDomain(ctx, source, endpoints)
		result.Endpoints = append(result.Endpoints, additionalEndpoints...)
		result.Stats.EndpointCount = len(result.Endpoints)
	}

	return result
}

// getContent retrieves content from a source
func (f *Finder) getContent(ctx context.Context, source string) (string, error) {
	if strings.HasPrefix(source, "file://") {
		return f.getFileContent(source[7:])
	}

	if strings.HasPrefix(source, "data:") {
		return f.getDataContent(source)
	}

	if f.isURL(source) {
		return f.httpClient.FetchSingle(ctx, source, f.config.Cookies)
	}

	return "", fmt.Errorf("unsupported source format: %s", source)
}

// getFileContent reads content from a local file
func (f *Finder) getFileContent(filename string) (string, error) {
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

// getDataContent extracts content from data URL
func (f *Finder) getDataContent(dataURL string) (string, error) {
	// Simple data URL parsing
	if !strings.HasPrefix(dataURL, "data:") {
		return "", fmt.Errorf("invalid data URL")
	}

	parts := strings.SplitN(dataURL[5:], ",", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("malformed data URL")
	}

	// Check if base64 encoded
	if strings.Contains(parts[0], "base64") {
		decoded, err := base64.StdEncoding.DecodeString(parts[1])
		if err != nil {
			return "", fmt.Errorf("failed to decode base64: %w", err)
		}
		return string(decoded), nil
	}

	return parts[1], nil
}

// crawlDomain performs domain crawling to find additional JavaScript files
func (f *Finder) crawlDomain(ctx context.Context, baseURL string, initialEndpoints []parser.Endpoint) []parser.Endpoint {
	if f.config.MaxDepth <= 0 {
		return nil
	}

	var additionalEndpoints []parser.Endpoint
	visited := make(map[string]bool)
	visited[baseURL] = true

	// Extract potential JS URLs from initial endpoints
	jsURLs := f.extractJSURLs(baseURL, initialEndpoints)

	// Process JS URLs concurrently
	var wg sync.WaitGroup
	var mu sync.Mutex
	semaphore := make(chan struct{}, f.config.Workers)

	for _, jsURL := range jsURLs {
		if visited[jsURL] {
			continue
		}
		visited[jsURL] = true

		wg.Add(1)
		go func(url string) {
			defer wg.Done()

			select {
			case semaphore <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-semaphore }()

			if f.config.Verbose {
				fmt.Printf("Crawling: %s\n", url)
			}

			result := f.processSource(ctx, url)
			if result.Error == "" {
				mu.Lock()
				additionalEndpoints = append(additionalEndpoints, result.Endpoints...)
				mu.Unlock()
			}
		}(jsURL)
	}

	wg.Wait()
	return additionalEndpoints
}

// extractJSURLs extracts potential JavaScript URLs from endpoints
func (f *Finder) extractJSURLs(baseURL string, endpoints []parser.Endpoint) []string {
	var jsURLs []string

	baseURLParsed, err := url.Parse(baseURL)
	if err != nil {
		return jsURLs
	}

	for _, endpoint := range endpoints {
		link := endpoint.Link

		// Skip if not a JS file
		if !strings.HasSuffix(link, ".js") {
			continue
		}

		// Skip common libraries
		if f.shouldSkipJS(link) {
			continue
		}

		// Resolve relative URLs
		if normalizedURL, err := client.NormalizeURL(baseURL, link); err == nil {
			// Ensure it's from the same domain or subdomain
			if parsedURL, err := url.Parse(normalizedURL); err == nil {
				if f.isSameDomain(baseURLParsed.Host, parsedURL.Host) {
					jsURLs = append(jsURLs, normalizedURL)
				}
			}
		}
	}

	return jsURLs
}

// shouldSkipJS checks if a JavaScript file should be skipped
func (f *Finder) shouldSkipJS(filename string) bool {
	skipList := []string{
		"jquery.js", "jquery.min.js",
		"bootstrap.js", "bootstrap.min.js",
		"angular.js", "angular.min.js",
		"react.js", "react.min.js",
		"vue.js", "vue.min.js",
		"node_modules",
	}

	filename = strings.ToLower(filename)
	for _, skip := range skipList {
		if strings.Contains(filename, skip) {
			return true
		}
	}
	return false
}

// isSameDomain checks if two hosts are from the same domain
func (f *Finder) isSameDomain(host1, host2 string) bool {
	// Simple domain matching - could be enhanced with proper TLD parsing
	host1 = strings.ToLower(host1)
	host2 = strings.ToLower(host2)

	if host1 == host2 {
		return true
	}

	// Check if one is a subdomain of the other
	if strings.HasSuffix(host1, "."+host2) || strings.HasSuffix(host2, "."+host1) {
		return true
	}

	return false
}

// TotalEndpoints returns the total number of unique endpoints
func (r *Result) TotalEndpoints() int {
	seen := make(map[string]bool)
	count := 0

	for _, file := range r.Files {
		for _, endpoint := range file.Endpoints {
			if !seen[endpoint.Link] {
				seen[endpoint.Link] = true
				count++
			}
		}
	}

	return count
}

// TotalFiles returns the total number of processed files
func (r *Result) TotalFiles() int {
	return len(r.Files)
}
