package server

import "strings"

func IsBrowser(userAgent string) bool {
	userAgent = strings.ToLower(userAgent)
	if userAgent != "" {
		// Check for common browser user-agent strings
		return strings.Contains(userAgent, "mozilla") ||
			strings.Contains(userAgent, "chrome") ||
			strings.Contains(userAgent, "safari") ||
			strings.Contains(userAgent, "opera") ||
			strings.Contains(userAgent, "msie") ||
			strings.Contains(userAgent, "edge")
	}

	return false
}
