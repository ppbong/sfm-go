package util

import (
	"fmt"
	"path/filepath"
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

func IsInsideBaseDir(base, dir string) bool {
	parent, err := filepath.Abs(base)
	if err != nil {
		return false
	}

	child, err := filepath.Abs(dir)
	if err != nil {
		return false
	}

	rel, err := filepath.Rel(parent, child)
	if err != nil {
		return false
	}

	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

func ByteArrayEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	var d byte
	for i, ea := range a {
		d |= ea ^ b[i]
	}

	return d == 0
}

func ByteArrayZero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
