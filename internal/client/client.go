package client

import (
	"compress/gzip"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Response represents an HTTP response with additional metadata
type Response struct {
	URL        string
	Body       string
	StatusCode int
	Headers    http.Header
	Size       int64
	Duration   time.Duration
	Error      error
}

// Request represents an HTTP request to be processed
type Request struct {
	URL     string
	Cookies string
	Headers map[string]string
}

// Client handles concurrent HTTP requests
type Client struct {
	httpClient *http.Client
	workers    int
	timeout    time.Duration
	userAgent  string

	// Channels for request processing
	requestChan  chan Request
	responseChan chan Response

	// Wait group for worker management
	wg sync.WaitGroup
}

// New creates a new concurrent HTTP client
func New(workers int, timeout time.Duration) *Client {
	// Create HTTP client with sensible defaults
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false,
		},
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		DisableCompression:    false,
		ResponseHeaderTimeout: timeout,
	}

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Allow up to 10 redirects
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	return &Client{
		httpClient:   httpClient,
		workers:      workers,
		timeout:      timeout,
		userAgent:    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 golinkfinder/2.0",
		requestChan:  make(chan Request, workers*2), // Buffered channel
		responseChan: make(chan Response, workers*2),
	}
}

// Start initializes the worker pool
func (c *Client) Start(ctx context.Context) {
	// Start worker goroutines
	for i := 0; i < c.workers; i++ {
		c.wg.Add(1)
		go c.worker(ctx, i)
	}
}

// Stop shuts down the client gracefully
func (c *Client) Stop() {
	close(c.requestChan)
	c.wg.Wait()
	close(c.responseChan)
}

// Submit adds a request to the processing queue
func (c *Client) Submit(req Request) {
	select {
	case c.requestChan <- req:
	default:
		// Channel is full, handle gracefully
		go func() {
			c.requestChan <- req
		}()
	}
}

// Results returns the channel for receiving responses
func (c *Client) Results() <-chan Response {
	return c.responseChan
}

// worker processes requests concurrently
func (c *Client) worker(ctx context.Context, workerID int) {
	defer c.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case req, ok := <-c.requestChan:
			if !ok {
				return // Channel closed
			}

			response := c.processRequest(ctx, req)

			// Send response (non-blocking)
			select {
			case c.responseChan <- response:
			case <-ctx.Done():
				return
			}
		}
	}
}

// processRequest handles a single HTTP request
func (c *Client) processRequest(ctx context.Context, req Request) Response {
	startTime := time.Now()

	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, "GET", req.URL, nil)
	if err != nil {
		return Response{
			URL:      req.URL,
			Error:    fmt.Errorf("failed to create request: %w", err),
			Duration: time.Since(startTime),
		}
	}

	// Set headers
	httpReq.Header.Set("User-Agent", c.userAgent)
	httpReq.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	httpReq.Header.Set("Accept-Language", "en-US,en;q=0.8")
	httpReq.Header.Set("Accept-Encoding", "gzip, deflate")
	httpReq.Header.Set("Connection", "keep-alive")

	// Add cookies if provided
	if req.Cookies != "" {
		httpReq.Header.Set("Cookie", req.Cookies)
	}

	// Add custom headers
	for key, value := range req.Headers {
		httpReq.Header.Set(key, value)
	}

	// Make the request
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return Response{
			URL:      req.URL,
			Error:    fmt.Errorf("request failed: %w", err),
			Duration: time.Since(startTime),
		}
	}
	defer resp.Body.Close()

	// Read response body
	body, err := c.readResponseBody(resp)
	if err != nil {
		return Response{
			URL:        req.URL,
			StatusCode: resp.StatusCode,
			Headers:    resp.Header,
			Error:      fmt.Errorf("failed to read response body: %w", err),
			Duration:   time.Since(startTime),
		}
	}

	return Response{
		URL:        req.URL,
		Body:       body,
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Size:       int64(len(body)),
		Duration:   time.Since(startTime),
	}
}

// readResponseBody reads and decompresses the response body
func (c *Client) readResponseBody(resp *http.Response) (string, error) {
	var reader io.Reader = resp.Body

	// Handle compression
	switch resp.Header.Get("Content-Encoding") {
	case "gzip":
		gzipReader, err := gzip.NewReader(resp.Body)
		if err != nil {
			return "", fmt.Errorf("failed to create gzip reader: %w", err)
		}
		defer gzipReader.Close()
		reader = gzipReader
	}

	// Read with size limit to prevent memory issues
	limitedReader := io.LimitReader(reader, 50*1024*1024) // 50MB limit
	bodyBytes, err := io.ReadAll(limitedReader)
	if err != nil {
		return "", fmt.Errorf("failed to read body: %w", err)
	}

	return string(bodyBytes), nil
}

// FetchSingle fetches a single URL synchronously (for backwards compatibility)
func (c *Client) FetchSingle(ctx context.Context, url, cookies string) (string, error) {
	req := Request{
		URL:     url,
		Cookies: cookies,
	}

	response := c.processRequest(ctx, req)
	if response.Error != nil {
		return "", response.Error
	}

	return response.Body, nil
}

// IsValidURL checks if a URL is valid and reachable
func IsValidURL(urlStr string) bool {
	// Basic URL parsing
	u, err := url.Parse(urlStr)
	if err != nil {
		return false
	}

	// Check scheme
	if u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "file" {
		return false
	}

	// Basic hostname validation for http/https
	if (u.Scheme == "http" || u.Scheme == "https") && u.Host == "" {
		return false
	}

	return true
}

// NormalizeURL normalizes a URL for consistent processing
func NormalizeURL(baseURL, relativePath string) (string, error) {
	if relativePath == "" {
		return "", fmt.Errorf("empty relative path")
	}

	// Handle absolute URLs
	if IsValidURL(relativePath) {
		return relativePath, nil
	}

	// Handle protocol-relative URLs
	if strings.HasPrefix(relativePath, "//") {
		if strings.HasPrefix(baseURL, "https://") {
			return "https:" + relativePath, nil
		}
		return "http:" + relativePath, nil
	}

	// Parse base URL
	base, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("invalid base URL: %w", err)
	}

	// Parse relative path
	rel, err := url.Parse(relativePath)
	if err != nil {
		return "", fmt.Errorf("invalid relative path: %w", err)
	}

	// Resolve relative to base
	resolved := base.ResolveReference(rel)
	return resolved.String(), nil
}
