package config

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// Config holds all configuration options for golinkfinder
type Config struct {
	Input    string
	Output   string
	Regex    string
	Domain   bool
	Burp     bool
	Cookies  string
	Timeout  int
	Workers  int
	MaxDepth int
	Verbose  bool
	NoColors bool
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	// Allow empty input only if we might be reading from stdin
	if c.Input == "" {
		return fmt.Errorf("input is required (use '-' for stdin or provide URL/file)")
	}

	if c.Timeout <= 0 {
		return fmt.Errorf("timeout must be positive")
	}

	if c.Workers <= 0 {
		return fmt.Errorf("workers must be positive")
	}

	if c.MaxDepth < 0 {
		return fmt.Errorf("max-depth cannot be negative")
	}

	// Validate input format (skip for stdin input)
	if c.Input != "-" && !c.isValidInput() {
		return fmt.Errorf("invalid input format: %s", c.Input)
	}

	return nil
}

// isValidInput checks if the input is in a valid format
func (c *Config) isValidInput() bool {
	input := strings.TrimSpace(c.Input)

	// Check for URL
	if c.isURL(input) {
		return true
	}

	// Check for file/folder
	if c.isFile(input) {
		return true
	}

	// Check for wildcard pattern
	if strings.Contains(input, "*") {
		return true
	}

	return false
}

// isURL checks if the input is a valid URL
func (c *Config) isURL(input string) bool {
	schemes := []string{"http://", "https://", "file://", "ftp://", "ftps://"}
	for _, scheme := range schemes {
		if strings.HasPrefix(input, scheme) {
			if _, err := url.Parse(input); err == nil {
				return true
			}
		}
	}

	// Handle view-source: prefix (Firefox URL inspector)
	if strings.HasPrefix(input, "view-source:") {
		return c.isURL(input[12:])
	}

	return false
}

// isFile checks if the input points to an existing file or folder
func (c *Config) isFile(input string) bool {
	absPath, err := filepath.Abs(input)
	if err != nil {
		return false
	}

	_, err = os.Stat(absPath)
	return !os.IsNotExist(err)
}

// IsOutputCLI returns true if output should go to CLI
func (c *Config) IsOutputCLI() bool {
	return strings.ToLower(c.Output) == "cli"
}
