package main

import (
	"bufio"
	"context"
	"fmt"
	"secretfinder/internal/scanner"
	"secretfinder/pkg/config"
	"io"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

var (
	version   = "1.0.0"
	buildDate = "unknown"
	gitCommit = "unknown"
	cfg       config.Config
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "secretfinder [URL/file]",
		Short: "secretfinder - Discover secrets and API keys in JavaScript files",
		Long: `secretfinder is a security tool that discovers secrets, API keys, and sensitive data in JavaScript files.
It scans for patterns matching common services like Google, AWS, Stripe, Facebook, and many others.

Input can be provided as:
  - Command line argument: secretfinder -i https://example.com/app.js
  - Piped from stdin: echo 'https://example.com/app.js' | secretfinder -o cli
  - Interactive stdin: secretfinder -i - (then enter URLs)
  - Multiple files: secretfinder -i urls.txt (one URL per line)

Features:
  - Pre-built regex patterns for 100+ services
  - Cookie support for authenticated scanning
  - Concurrent processing for speed
  - Output to file or CLI

Build Info:
  Version: ` + version + `
  Build Date: ` + buildDate + `
  Git Commit: ` + gitCommit,
		Version: version,
		RunE:    runSecretFinder,
	}

	// Define flags
	rootCmd.Flags().StringVarP(&cfg.Input, "input", "i", "", "Input: URL, file, or text file with URLs (one per line, use '-' for stdin)")
	rootCmd.Flags().StringVarP(&cfg.Output, "output", "o", "secrets.txt", "Output file ('cli' for stdout)")
	rootCmd.Flags().StringVarP(&cfg.Cookies, "cookies", "c", "", "Cookies for authenticated requests (format: key1=value1; key2=value2)")
	rootCmd.Flags().StringVarP(&cfg.UserAgent, "user-agent", "u", "Mozilla/5.0", "User-Agent header")
	rootCmd.Flags().IntVarP(&cfg.Timeout, "timeout", "t", 10, "Request timeout in seconds")
	rootCmd.Flags().IntVarP(&cfg.Workers, "workers", "w", runtime.NumCPU()*2, "Number of worker goroutines")
	rootCmd.Flags().BoolVarP(&cfg.Verbose, "verbose", "v", false, "Enable verbose output")
	rootCmd.Flags().BoolVarP(&cfg.IncludeContext, "context", "x", false, "Include surrounding context in output")
	rootCmd.Flags().IntVarP(&cfg.ContextLines, "context-lines", "l", 2, "Number of context lines before/after match")
	rootCmd.Flags().StringSliceVarP(&cfg.Patterns, "patterns", "p", []string{"all"}, "Patterns to match (default: all, or specify: aws,google,stripe,etc.)")
	rootCmd.Flags().BoolVarP(&cfg.NoColors, "no-colors", "n", false, "Disable colored output")

	// Execute command
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runSecretFinder(cmd *cobra.Command, args []string) error {
	// Setup graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle SIGINT/SIGTERM
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\nReceived interrupt signal, shutting down gracefully...")
		cancel()
	}()

	// Check if we should read from stdin
	if cfg.Input == "" || cfg.Input == "-" {
		if stdinInput, err := readFromStdin(); err == nil && stdinInput != "" {
			cfg.Input = stdinInput
		}
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("configuration error: %w", err)
	}

	if cfg.Verbose {
		fmt.Printf("secretfinder v%s starting with %d workers\n", version, cfg.Workers)
		fmt.Printf("Input: %s\n", cfg.Input)
		fmt.Printf("Output: %s\n", cfg.Output)
		if len(cfg.Patterns) > 0 && cfg.Patterns[0] != "all" {
			fmt.Printf("Patterns: %v\n", cfg.Patterns)
		}
	}

	// Create scanner instance
	secretScanner := scanner.New(cfg)

	// Start processing
	startTime := time.Now()
	results, err := secretScanner.Process(ctx)
	if err != nil {
		return fmt.Errorf("processing failed: %w", err)
	}

	// Output results
	if err := results.Write(cfg.Output, cfg.NoColors); err != nil {
		return fmt.Errorf("output generation failed: %w", err)
	}

	if cfg.Verbose {
		duration := time.Since(startTime)
		fmt.Printf("Processing completed in %v\n", duration)
		fmt.Printf("Scanned %d files, found %d secrets across %d patterns\n",
			results.FilesScanned, results.TotalSecrets(), results.PatternsUsed)
	}

	return nil
}

// readFromStdin reads input from stdin if available
func readFromStdin() (string, error) {
	// Check if stdin has data
	stat, err := os.Stdin.Stat()
	if err != nil {
		return "", err
	}

	// Check if data is being piped
	if (stat.Mode() & os.ModeCharDevice) != 0 {
		// No pipe, return empty
		return "", nil
	}

	// Read from stdin
	reader := bufio.NewReader(os.Stdin)
	var lines []string

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				if line != "" {
					lines = append(lines, strings.TrimSpace(line))
				}
				break
			}
			return "", err
		}
		line = strings.TrimSpace(line)
		if line != "" {
			lines = append(lines, line)
		}
	}

	if len(lines) == 0 {
		return "", nil
	}

	// If multiple lines, treat as file paths/URLs
	if len(lines) > 1 {
		// Create a temporary file with the URLs
		tmpFile, err := os.CreateTemp("", "secretfinder-stdin-*.txt")
		if err != nil {
			return "", fmt.Errorf("failed to create temp file: %w", err)
		}
		defer tmpFile.Close()

		for _, line := range lines {
			fmt.Fprintln(tmpFile, line)
		}

		return tmpFile.Name(), nil
	}

	return lines[0], nil
}
