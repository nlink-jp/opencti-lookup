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
	"crypto/sha256"
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

// FileName builds the saved name (ADR-021 §5: no workspace concept, so the
// name carries the server and the source):
//
//	opencti-lookup-<first 8 of the object's internal id>-<8 hex of sha256(id, upstream name)>-<stem><ext>
//
// The upstream name is third-party text: its path is dropped and its stem and
// extension are reduced to ASCII letters, digits, dot, hyphen and underscore.
// That reduction can make two names alike (two Japanese names reduce to the
// same stem), so a hash of the object id and the original name keeps them apart: two
// attachments never share a saved name, and the same attachment of the same
// object always gets the same one (a re-download replaces it).
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
	sum := sha256.Sum256([]byte(objectID + "\x00" + upstream))
	tag := hex.EncodeToString(sum[:4])

	base := upstream
	if i := strings.LastIndexAny(base, `/\`); i >= 0 {
		base = base[i+1:]
	}
	ext := filepath.Ext(base)
	if ext == base || len(ext) > 12 || strings.IndexFunc(ext[min(1, len(ext)):], func(r rune) bool { return !isASCIIAlnum(r) }) >= 0 {
		ext = "" // a dot-file, an overlong or a non-plain extension is part of the stem
	}
	stem := reduce(strings.TrimSuffix(base, ext))
	if stem == "" {
		stem = "file"
	}
	if r := []rune(stem); len(r) > maxNameRunes {
		stem = string(r[:maxNameRunes])
	}
	return "opencti-lookup-" + id + "-" + tag + "-" + stem + ext
}

func isASCIIAlnum(r rune) bool {
	return r < 128 && (unicode.IsLetter(r) || unicode.IsDigit(r))
}

// reduce keeps ASCII letters, digits, dot, hyphen and underscore, turns runs
// of anything else into one underscore, and trims dots, hyphens and
// underscores from both ends so that nothing starts with a dot.
func reduce(s string) string {
	var b strings.Builder
	lastUnderscore := false
	for _, r := range s {
		if !(isASCIIAlnum(r) || r == '.' || r == '-' || r == '_') {
			r = '_'
		}
		if r == '_' && lastUnderscore {
			continue
		}
		lastUnderscore = r == '_'
		b.WriteRune(r)
	}
	return strings.Trim(b.String(), "._-")
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
