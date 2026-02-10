package jsprocessor

import (
	"strings"
	"unicode"
)

// Processor handles JavaScript code beautification and processing
type Processor struct {
	indentSize int
	maxLength  int
}

// New creates a new JavaScript processor
func New() *Processor {
	return &Processor{
		indentSize: 2,
		maxLength:  1000000, // 1MB limit for beautification
	}
}

// Beautify formats JavaScript code for better readability
func (p *Processor) Beautify(content string) string {
	// If content is too large, use simple formatting
	if len(content) > p.maxLength {
		return p.simpleFormat(content)
	}

	return p.fullBeautify(content)
}

// simpleFormat applies basic formatting for large files
func (p *Processor) simpleFormat(content string) string {
	// Replace semicolons and commas with newlines for better pattern matching
	content = strings.ReplaceAll(content, ";", ";\r\n")
	content = strings.ReplaceAll(content, ",", ",\r\n")
	content = strings.ReplaceAll(content, "{", "{\r\n")
	content = strings.ReplaceAll(content, "}", "\r\n}")

	return content
}

// fullBeautify applies comprehensive JavaScript beautification
func (p *Processor) fullBeautify(content string) string {
	var result strings.Builder
	var indentLevel int
	inString := false
	inComment := false
	inRegex := false
	stringChar := byte(0)

	length := len(content)
	for i := 0; i < length; i++ {
		char := content[i]

		// Handle string literals
		if !inComment && !inRegex && (char == '"' || char == '\'' || char == '`') {
			if !inString {
				inString = true
				stringChar = char
			} else if char == stringChar {
				// Check if escaped
				if i > 0 && content[i-1] != '\\' {
					inString = false
					stringChar = 0
				}
			}
			result.WriteByte(char)
			continue
		}

		if inString {
			result.WriteByte(char)
			continue
		}

		// Handle comments
		if !inRegex && i < length-1 && content[i] == '/' && content[i+1] == '/' {
			inComment = true
			result.WriteString("//")
			i++ // Skip next character
			continue
		}

		if inComment && char == '\n' {
			inComment = false
			result.WriteByte(char)
			continue
		}

		if inComment {
			result.WriteByte(char)
			continue
		}

		// Handle multi-line comments
		if !inRegex && i < length-1 && content[i] == '/' && content[i+1] == '*' {
			result.WriteString("/*")
			i++ // Skip next character
			// Find end of comment
			for j := i + 1; j < length-1; j++ {
				result.WriteByte(content[j])
				if content[j] == '*' && content[j+1] == '/' {
					result.WriteByte(content[j+1])
					i = j + 1
					break
				}
			}
			continue
		}

		// Handle regex literals (basic detection)
		if !inString && !inComment && char == '/' {
			// Simple regex detection
			if i > 0 && (content[i-1] == '=' || content[i-1] == '(' || content[i-1] == '[' || content[i-1] == ',' || content[i-1] == ':' || content[i-1] == ';' || unicode.IsSpace(rune(content[i-1]))) {
				inRegex = true
				result.WriteByte(char)
				continue
			}
		}

		if inRegex && char == '/' {
			// Check if escaped
			if i > 0 && content[i-1] != '\\' {
				inRegex = false
			}
			result.WriteByte(char)
			continue
		}

		if inRegex {
			result.WriteByte(char)
			continue
		}

		// Handle structural characters
		switch char {
		case '{':
			result.WriteByte(char)
			result.WriteByte('\n')
			indentLevel++
			p.addIndent(&result, indentLevel)

		case '}':
			// Remove trailing whitespace
			str := result.String()
			str = strings.TrimRight(str, " \t")
			result.Reset()
			result.WriteString(str)

			if result.Len() > 0 && result.String()[result.Len()-1] != '\n' {
				result.WriteByte('\n')
			}
			indentLevel--
			p.addIndent(&result, indentLevel)
			result.WriteByte(char)
			result.WriteByte('\n')
			if indentLevel > 0 {
				p.addIndent(&result, indentLevel)
			}

		case ';':
			result.WriteByte(char)
			if i < length-1 && !unicode.IsSpace(rune(content[i+1])) {
				result.WriteByte('\n')
				p.addIndent(&result, indentLevel)
			}

		case ',':
			result.WriteByte(char)
			if i < length-1 && !unicode.IsSpace(rune(content[i+1])) {
				result.WriteByte(' ')
			}

		case '(':
			result.WriteByte(char)

		case ')':
			result.WriteByte(char)

		default:
			// Handle whitespace
			if unicode.IsSpace(rune(char)) {
				// Normalize whitespace
				if char == '\n' {
					result.WriteByte('\n')
					p.addIndent(&result, indentLevel)
					// Skip additional whitespace
					for i+1 < length && unicode.IsSpace(rune(content[i+1])) && content[i+1] != '\n' {
						i++
					}
				} else {
					// Only add space if result doesn't end with space
					str := result.String()
					if len(str) > 0 && !unicode.IsSpace(rune(str[len(str)-1])) {
						result.WriteByte(' ')
					}
				}
			} else {
				result.WriteByte(char)
			}
		}
	}

	return result.String()
}

// addIndent adds indentation to the result
func (p *Processor) addIndent(result *strings.Builder, level int) {
	for i := 0; i < level*p.indentSize; i++ {
		result.WriteByte(' ')
	}
}

// CleanContent removes comments and normalizes whitespace for better parsing
func (p *Processor) CleanContent(content string) string {
	var result strings.Builder
	inString := false
	inSingleComment := false
	inMultiComment := false
	stringChar := byte(0)

	length := len(content)
	for i := 0; i < length; i++ {
		char := content[i]

		// Handle string literals
		if !inSingleComment && !inMultiComment && (char == '"' || char == '\'' || char == '`') {
			if !inString {
				inString = true
				stringChar = char
			} else if char == stringChar {
				// Check if escaped
				if i > 0 && content[i-1] != '\\' {
					inString = false
					stringChar = 0
				}
			}
			result.WriteByte(char)
			continue
		}

		if inString {
			result.WriteByte(char)
			continue
		}

		// Handle single-line comments
		if i < length-1 && content[i] == '/' && content[i+1] == '/' {
			inSingleComment = true
			i++ // Skip next character
			continue
		}

		if inSingleComment && char == '\n' {
			inSingleComment = false
			result.WriteByte('\n')
			continue
		}

		if inSingleComment {
			continue
		}

		// Handle multi-line comments
		if i < length-1 && content[i] == '/' && content[i+1] == '*' {
			inMultiComment = true
			i++ // Skip next character
			continue
		}

		if inMultiComment && i < length-1 && content[i] == '*' && content[i+1] == '/' {
			inMultiComment = false
			i++ // Skip next character
			continue
		}

		if inMultiComment {
			// Preserve newlines in multi-line comments
			if char == '\n' {
				result.WriteByte('\n')
			}
			continue
		}

		result.WriteByte(char)
	}

	return result.String()
}

// ExtractStrings extracts all string literals from JavaScript content
func (p *Processor) ExtractStrings(content string) []string {
	var result []string
	var current strings.Builder
	inString := false
	stringChar := byte(0)

	length := len(content)
	for i := 0; i < length; i++ {
		char := content[i]

		if !inString && (char == '"' || char == '\'' || char == '`') {
			inString = true
			stringChar = char
			current.Reset()
		} else if inString && char == stringChar {
			// Check if escaped
			if i > 0 && content[i-1] != '\\' {
				inString = false
				str := current.String()
				if str != "" {
					result = append(result, str)
				}
				stringChar = 0
			} else {
				current.WriteByte(char)
			}
		} else if inString {
			current.WriteByte(char)
		}
	}

	return result
}

// IsJavaScript attempts to detect if content is JavaScript
func (p *Processor) IsJavaScript(content string) bool {
	// Simple heuristics to detect JavaScript
	jsKeywords := []string{
		"function", "var", "let", "const", "if", "else", "for", "while",
		"return", "document", "window", "console", "jQuery", "$",
		"addEventListener", "setTimeout", "setInterval",
	}

	content = strings.ToLower(content)

	keywordCount := 0
	for _, keyword := range jsKeywords {
		if strings.Contains(content, keyword) {
			keywordCount++
		}
	}

	// If we find multiple JavaScript keywords, likely JS
	return keywordCount >= 3
}
