package config

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// SecretConfig holds all configuration options for secretfinder
type Config struct {
	Input          string
	Output         string
	Cookies        string
	UserAgent      string
	Timeout        int
	Workers        int
	Verbose        bool
	IncludeContext bool
	ContextLines   int
	Patterns       []string
	NoColors       bool
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

	if c.ContextLines < 0 {
		return fmt.Errorf("context-lines cannot be negative")
	}

	// Validate input format
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

	return false
}

// isURL checks if the input is a valid URL
func (c *Config) isURL(input string) bool {
	schemes := []string{"http://", "https://", "file://"}
	for _, scheme := range schemes {
		if strings.HasPrefix(input, scheme) {
			if _, err := url.Parse(input); err == nil {
				return true
			}
		}
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

// IsURLList checks if input is a file containing URLs
func (c *Config) IsURLList() bool {
	if c.Input == "-" {
		return false
	}

	// Check if it's a file with .txt or .list extension
	if !c.isURL(c.Input) && c.isFile(c.Input) {
		ext := strings.ToLower(filepath.Ext(c.Input))
		return ext == ".txt" || ext == ".list"
	}

	return false
}

// ParseCookieHeader parses a cookie string into a header value
func (c *Config) ParseCookieHeader() string {
	if c.Cookies == "" {
		return ""
	}

	// Basic validation - ensure it looks like cookies
	parts := strings.Split(c.Cookies, ";")
	for i, part := range parts {
		part = strings.TrimSpace(part)
		if !strings.Contains(part, "=") {
			continue
		}
		if i > 0 {
			parts[i] = part
		}
	}

	return strings.Join(parts, "; ")
}
