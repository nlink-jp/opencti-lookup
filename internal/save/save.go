// Package save writes a downloaded file into a work directory.
//
// The work directory has already been judged by pathguard (organization
// ADR-021 as amended by ADR-022). pathguard's verdict is a snapshot, so the
// write itself is confined with os.Root: whatever the name, and whatever
// links appear between the check and the write, the file lands inside the
// directory or nowhere. It is written to a temporary name first and renamed
// into place, so a failed download leaves nothing that looks complete.
package save

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"
)

// Saved says where a file went (ADR-021 §6).
type Saved struct {
	WorkDir string `json:"work_dir"`
	Path    string `json:"path"` // relative to WorkDir
	AbsPath string `json:"abs_path"`
}

// maxNameRunes bounds the part of a saved name taken from upstream.
const maxNameRunes = 100

// FileName builds the saved name: the server's identity, the first characters
// of the object id (ADR-021 §5: no workspace concept, so the name carries the
// server and the source), and the upstream name reduced to characters that
// mean nothing to a shell or a filesystem. The upstream name is third-party
// text; nothing of its path survives, and it can never start with a dot.
func FileName(objectID, upstream string) string {
	id := strings.Map(func(r rune) rune {
		if r < 128 && (unicode.IsLetter(r) || unicode.IsDigit(r)) {
			return r
		}
		return -1
	}, objectID)
	if len(id) > 8 {
		id = id[:8]
	}
	if id == "" {
		id = "object"
	}

	base := upstream
	if i := strings.LastIndexAny(base, `/\`); i >= 0 {
		base = base[i+1:]
	}
	var b strings.Builder
	lastUnderscore := false
	for _, r := range base {
		ok := r < 128 && (unicode.IsLetter(r) || unicode.IsDigit(r) || r == '.' || r == '-' || r == '_')
		if !ok {
			r = '_'
		}
		if r == '_' && lastUnderscore {
			continue
		}
		lastUnderscore = r == '_'
		b.WriteRune(r)
	}
	name := strings.Trim(b.String(), "._-")
	if name == "" {
		name = "file"
	}
	if r := []rune(name); len(r) > maxNameRunes {
		ext := filepath.Ext(name)
		if len(ext) > 16 {
			ext = ""
		}
		name = string(r[:maxNameRunes-len([]rune(ext))]) + ext
	}
	return "opencti-lookup-" + id + "-" + name
}

// Save creates name inside dir with what fill writes, replacing a file of the
// same name. dir must be the absolute, already validated work directory.
func Save(dir, name string, fill func(io.Writer) error) (Saved, error) {
	if name == "" || name != filepath.Base(name) || strings.HasPrefix(name, ".") {
		return Saved{}, fmt.Errorf("save: %q is not a plain file name", name)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return Saved{}, fmt.Errorf("open work directory: %w", err)
	}
	defer func() { _ = root.Close() }()

	var rnd [6]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return Saved{}, err
	}
	tmp := ".opencti-lookup-" + hex.EncodeToString(rnd[:]) + ".part"
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return Saved{}, fmt.Errorf("create in work directory: %w", err)
	}
	werr := fill(f)
	cerr := f.Close()
	if err := errors.Join(werr, cerr); err != nil {
		_ = root.Remove(tmp)
		return Saved{}, err
	}
	if err := root.Rename(tmp, name); err != nil {
		_ = root.Remove(tmp)
		return Saved{}, fmt.Errorf("move into place: %w", err)
	}
	return Saved{WorkDir: dir, Path: name, AbsPath: filepath.Join(dir, name)}, nil
}
