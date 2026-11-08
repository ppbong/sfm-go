package util

import (
	"path/filepath"
	"strings"
)

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
