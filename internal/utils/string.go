package utils

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

func SafeReplacePayload(template string, values map[string]string) (string, error) {
	isJSON := strings.HasPrefix(strings.TrimSpace(template), "{")

	if isJSON {
		for k, v := range values {
			final, err := json.Marshal(v)
			str := string(final)
			if err != err {
				return "", fmt.Errorf("invalid JSON after replace: %w", err)
			}
			template = strings.ReplaceAll(template, k, str[1:len(str)-1])
		}

		return template, nil
	}

	for k, v := range values {
		final := url.QueryEscape(v)
		template = strings.ReplaceAll(template, k, string(final))
	}
	return template, nil
}

func TruncateAndClean(s string, limit int) string {
	if len(s) > limit {
		s = s[:limit]
	}
	return RemoveNewlines(s)
}

func RemoveNewlines(s string) string {

	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")
	return s
}
