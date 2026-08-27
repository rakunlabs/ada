package authz

import "strings"

// Match reports whether path matches pattern.
//
// The syntax is the small one people expect from route configuration, and no
// more:
//
//   - matches any run of characters except "/"
//     **  matches any run of characters including "/"
//     ?   matches exactly one character except "/"
//
// Everything else is literal. There are no character classes and no escaping,
// because a pattern that needs them is a regexp wearing a disguise.
//
// A "/**" suffix also matches the prefix itself, so "/api/**" covers "/api".
// That is the rule everybody assumes and the one whose absence produces a
// confusing hole in a deny list.
func Match(pattern, path string) bool {
	if pattern == "" {
		return path == ""
	}

	if pattern == "**" || pattern == "/**" && path == "/" {
		return true
	}

	// "/api/**" should cover "/api" as well as "/api/x".
	if strings.HasSuffix(pattern, "/**") && path == strings.TrimSuffix(pattern, "/**") {
		return true
	}

	return match([]byte(pattern), []byte(path))
}

// match is an iterative backtracking matcher: linear in the common case, and
// bounded by pattern length times path length in the worst one. A recursive
// version is shorter but blows the stack on adversarial input.
func match(pattern, name []byte) bool {
	var (
		px, nx           int
		nextPx, nextNx   int
		hasStar          bool
		starCrossesSlash bool
	)

	for px < len(pattern) || nx < len(name) {
		if px < len(pattern) {
			switch c := pattern[px]; c {
			case '?':
				if nx < len(name) && name[nx] != '/' {
					px++
					nx++

					continue
				}

			case '*':
				crosses := px+1 < len(pattern) && pattern[px+1] == '*'

				// Remember where to resume if the star turns out to have
				// swallowed too little.
				nextPx = px
				nextNx = nx + 1
				hasStar = true
				starCrossesSlash = crosses

				if crosses {
					px += 2
					// "**/" should also match zero segments: "a/**/b" ~ "a/b".
					if px < len(pattern) && pattern[px] == '/' {
						if match(pattern[px+1:], name[nx:]) {
							return true
						}
					}
				} else {
					px++
				}

				continue

			default:
				if nx < len(name) && name[nx] == c {
					px++
					nx++

					continue
				}
			}
		}

		// Mismatch: let the last star consume one more character, unless that
		// character is a "/" and the star was single.
		if hasStar && nextNx <= len(name) {
			if !starCrossesSlash && nextNx > 0 && name[nextNx-1] == '/' {
				return false
			}

			px = nextPx
			nx = nextNx

			continue
		}

		return false
	}

	return true
}

// MatchAny reports whether path matches at least one pattern. An empty list
// matches nothing.
func MatchAny(patterns []string, path string) bool {
	for _, p := range patterns {
		if Match(p, path) {
			return true
		}
	}

	return false
}
