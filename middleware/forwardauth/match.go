package forwardauth

import "regexp"

// matchString reports whether the string s matches the regex pattern.
func matchString(pattern, s string) (bool, error) {
	return regexp.MatchString(pattern, s)
}
