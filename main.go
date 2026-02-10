package main

import (
	"bufio"
	"context"
	"fmt"
	"golinkfinder/internal/finder"
	"golinkfinder/internal/output"
	"golinkfinder/pkg/config"
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
	version   = "2.0.0"
	buildDate = "unknown"
	gitCommit = "unknown"
	cfg       config.Config
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "golinkfinder [URL/file/folder]",
		Short: "golinkfinder - Discover endpoints and parameters in JavaScript files",
		Long: `golinkfinder is a high-performance Go tool that discovers endpoints and their parameters in JavaScript files.
This version includes advanced concurrency features for faster processing of multiple files and domains.

Input can be provided as:
  - Command line argument: golinkfinder -i https://example.com/app.js
  - Piped from stdin: echo 'https://example.com/app.js' | golinkfinder -o cli
  - Interactive stdin: golinkfinder -i - (then enter URLs)

Build Info:
  Version: ` + version + `
  Build Date: ` + buildDate + `
  Git Commit: ` + gitCommit,
		Version: version,
		RunE:    rungolinkfinder,
	}

	// Define flags
	rootCmd.Flags().StringVarP(&cfg.Input, "input", "i", "", "Input: URL, file, or folder (use '-' for stdin)")
	rootCmd.Flags().StringVarP(&cfg.Output, "output", "o", "output.html", "Output file ('cli' for stdout)")
	rootCmd.Flags().StringVarP(&cfg.Regex, "regex", "r", "", "RegEx filter for found endpoints (e.g. ^/api/)")
	rootCmd.Flags().BoolVarP(&cfg.Domain, "domain", "d", false, "Crawl entire domain recursively")
	rootCmd.Flags().BoolVarP(&cfg.Burp, "burp", "b", false, "Parse Burp 'Save selected' file")
	rootCmd.Flags().StringVarP(&cfg.Cookies, "cookies", "c", "", "Cookies for authenticated requests")
	rootCmd.Flags().IntVarP(&cfg.Timeout, "timeout", "t", 10, "Request timeout in seconds")
	rootCmd.Flags().IntVarP(&cfg.Workers, "workers", "w", runtime.NumCPU()*2, "Number of worker goroutines")
	rootCmd.Flags().IntVarP(&cfg.MaxDepth, "max-depth", "m", 2, "Maximum crawling depth for domain mode")
	rootCmd.Flags().BoolVarP(&cfg.Verbose, "verbose", "v", false, "Enable verbose output")
	rootCmd.Flags().BoolVar(&cfg.NoColors, "no-colors", false, "Disable colored output")

	// Execute command
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func rungolinkfinder(cmd *cobra.Command, args []string) error {
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
		fmt.Printf("golinkfinder v%s starting with %d workers\n", version, cfg.Workers)
		fmt.Printf("Input: %s\n", cfg.Input)
		fmt.Printf("Output: %s\n", cfg.Output)
	}

	// Create finder instance
	golinkfinder := finder.New(cfg)

	// Start processing
	startTime := time.Now()
	results, err := golinkfinder.Process(ctx)
	if err != nil {
		return fmt.Errorf("processing failed: %w", err)
	}

	// Output results
	outputHandler := output.New(cfg)
	if err := outputHandler.Generate(results); err != nil {
		return fmt.Errorf("output generation failed: %w", err)
	}

	if cfg.Verbose {
		duration := time.Since(startTime)
		fmt.Printf("Processing completed in %v\n", duration)
		fmt.Printf("Found %d unique endpoints across %d files\n",
			results.TotalEndpoints(), results.TotalFiles())
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
		lines = append(lines, strings.TrimSpace(line))
	}

	// Join all lines and return the first non-empty URL
	for _, line := range lines {
		if line != "" {
			return line, nil
		}
	}

	return "", nil
}
