package database

import (
	"bufio"
	"strings"
)

// parseNamedQueries extracts named queries from SQL content
// Queries are defined with -- name: QueryName format
func parseNamedQueries(content string) map[string]string {
	queries := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(content))
	
	var currentQuery strings.Builder
	var currentName string
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		
		// Check for query name definition
		if strings.HasPrefix(line, "-- name:") {
			// Save previous query if exists
			if currentName != "" && currentQuery.Len() > 0 {
				queries[currentName] = strings.TrimSpace(currentQuery.String())
			}
			
			// Start new query
			currentName = strings.TrimSpace(strings.TrimPrefix(line, "-- name:"))
			currentQuery.Reset()
			continue
		}
		
		// Skip empty lines and comments at the start of files
		if currentName == "" && (line == "" || strings.HasPrefix(line, "--")) {
			continue
		}
		
		// Add line to current query if we have a name
		if currentName != "" {
			// Skip standalone comments within queries
			if strings.HasPrefix(line, "--") && !strings.Contains(line, "name:") {
				continue
			}
			
			// Add non-empty lines to query
			if line != "" {
				if currentQuery.Len() > 0 {
					currentQuery.WriteString("\n")
				}
				currentQuery.WriteString(line)
			}
		}
	}
	
	// Save the last query
	if currentName != "" && currentQuery.Len() > 0 {
		queries[currentName] = strings.TrimSpace(currentQuery.String())
	}
	
	return queries
}

// validateQueryName checks if a query name is valid
func validateQueryName(name string) bool {
	if name == "" {
		return false
	}
	
	// Query names should contain only alphanumeric characters and underscores
	for _, r := range name {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_') {
			return false
		}
	}
	
	return true
}

// normalizeQuery removes excessive whitespace and normalizes SQL formatting
func normalizeQuery(query string) string {
	lines := strings.Split(query, "\n")
	var normalized []string
	
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			normalized = append(normalized, trimmed)
		}
	}
	
	return strings.Join(normalized, "\n")
}