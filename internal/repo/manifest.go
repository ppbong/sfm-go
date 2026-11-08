package repo

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"

	"gopkg.in/yaml.v3"
)

type FileEntry struct {
	Name      string    `yaml:"name"`
	Path      string    `yaml:"path"`
	Kind      string    `yaml:"kind"` // "encrypted" / "shared" / "inbox"
	Size      int64     `yaml:"size"`
	FileId    string    `yaml:"file_id,omitempty"`
	CreatedAt time.Time `yaml:"created_at"`
}

type Manifest struct {
	Version string      `yaml:"version"`
	Files   []FileEntry `yaml:"files"`
}

func (r *Repo) LoadManifest() (*Manifest, error) {
	p := r.ManifestPath()
	data, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return &Manifest{Version: "1", Files: nil}, nil
		}
		return nil, err
	}

	var m Manifest
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, err
	}

	return &m, nil
}

func (r *Repo) SaveManifest(m *Manifest) error {
	data, err := yaml.Marshal(m)
	if err != nil {
		return err
	}

	return os.WriteFile(r.ManifestPath(), data, 0o600)
}

func (r *Repo) AppendManifest(e FileEntry) error {
	m, err := r.LoadManifest()
	if err != nil {
		return err
	}

	m.Files = append(m.Files, e)

	return r.SaveManifest(m)
}

func (r *Repo) ListManifest(kind string) ([]FileEntry, error) {
	m, err := r.LoadManifest()
	if err != nil {
		return nil, err
	}

	var out []FileEntry

	for _, f := range m.Files {
		if kind == "all" || f.Kind == kind {
			out = append(out, f)
		}
	}

	return out, nil
}

func (r *Repo) ListStoredFiles(kind string) ([]FileEntry, error) {
	targets := []struct {
		kind string
		dir  string
		ext  string
	}{
		{"encrypted", r.EncPath(), ".sfe"},
		{"shared", r.SharePath(), ".sfx"},
		{"inbox", r.InboxPath(), ".sfx"},
	}

	var out []FileEntry

	for _, t := range targets {
		if kind != "all" && kind != t.kind {
			continue
		}

		root := t.dir
		if _, err := os.Stat(root); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}

		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				if d != nil && d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}

			if d.IsDir() || filepath.Ext(d.Name()) != t.ext {
				return nil
			}

			info, err := d.Info()
			if err != nil {
				return nil
			}

			rel, err := filepath.Rel(root, path)
			if err != nil {
				rel = d.Name()
			}

			out = append(out, FileEntry{
				Name:      filepath.ToSlash(rel),
				Path:      path,
				Kind:      t.kind,
				Size:      info.Size(),
				CreatedAt: info.ModTime(),
			})

			return nil
		})

		if err != nil {
			return nil, err
		}
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}

		return out[i].Name < out[j].Name
	})

	return out, nil
}
