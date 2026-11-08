package util

import (
	"fmt"
	"slices"
	"strings"
)

func SplitAndTrimString(content, sep string) ([]string, error) {
	supports := []string{",", ":", ".", "|", "/"}

	if !slices.Contains(supports, sep) {
		return nil, fmt.Errorf("the separator %s not support", sep)
	}

	var out []string

	parts := strings.Split(content, sep)
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}

	return out, nil
}

func CleanAndJoinStrings(items []string, sep string) (string, error) {
	supports := []string{",", ":", ".", "|", "/"}

	if !slices.Contains(supports, sep) {
		return "", fmt.Errorf("the separator %s not support", sep)
	}

	cleaned := make([]string, 0, len(items))

	for _, item := range items {
		trimmed := strings.TrimSpace(item)
		if trimmed != "" {
			cleaned = append(cleaned, trimmed)
		}
	}

	if len(cleaned) == 0 {
		return "", nil
	}

	if len(cleaned) == 1 {
		return cleaned[1], nil
	}

	return strings.Join(cleaned, sep), nil
}
