package save

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestFileName(t *testing.T) {
	id := "84ec431c-fe0f-4b73-b1b1-bdc344fded85"
	shape := regexp.MustCompile(`^opencti-lookup-84ec431c-[0-9a-f]{8}-[A-Za-z0-9._-]+$`)
	cases := map[string]string{ // upstream name -> the stem and extension it keeps
		"fixture-report.pdf":      "fixture-report.pdf",
		"escape attempt.txt":      "escape_attempt.txt",
		"../../etc/passwd":        "passwd",
		`..\..\win.ini`:           "win.ini",
		".env":                    "env",
		"報告書.pdf":                 "file.pdf",
		"a;rm -rf ~;$(x).sh":      "a_rm_-rf_x.sh",
		"":                        "file",
		"name\x00.pdf":            "name.pdf",
		"report.pdf\u202egpj.exe": "report.pdf_gpj.exe",
		"archive.tar.gz":          "archive.tar.gz",
		"report.":                 "report",
		"x.verylongextensionname": "x.verylongextensionname",
		"notes.téxt":              "notes.t_xt",
	}
	for in, keeps := range cases {
		got := FileName(id, in)
		if !shape.MatchString(got) || !strings.HasSuffix(got, "-"+keeps) {
			t.Errorf("FileName(%q) = %q, want the shape ending in -%s", in, got, keeps)
		}
		if got != FileName(id, in) {
			t.Errorf("FileName(%q) is not deterministic", in)
		}
	}

	// Names that reduce alike stay apart (the pre-release review's collisions).
	for _, pair := range [][2]string{
		{"報告書.pdf", "別紙.pdf"},
		{"IOC一覧.csv", "IOCリスト.csv"},
		{"a b.txt", "a_b.txt"},
	} {
		if FileName(id, pair[0]) == FileName(id, pair[1]) {
			t.Errorf("%q and %q share a saved name", pair[0], pair[1])
		}
	}
	// The same name on another object is another file.
	if FileName(id, "r.pdf") == FileName("84ec431c-0000-0000-0000-000000000000", "r.pdf") {
		t.Error("two objects whose ids share 8 characters share a saved name")
	}

	long := FileName(id, strings.Repeat("a", 300)+".pdf")
	if !strings.HasSuffix(long, ".pdf") || len(long) > len("opencti-lookup-84ec431c-01234567-")+maxNameRunes+len(".pdf") {
		t.Fatalf("long name %q (%d)", long, len(long))
	}
	if got := FileName("!!", "x"); !strings.HasPrefix(got, "opencti-lookup-object-") {
		t.Fatalf("%q", got)
	}
}

func TestSave(t *testing.T) {
	dir := t.TempDir()
	saved, err := Save(dir, "opencti-lookup-a-x.txt", func(w io.Writer) error {
		_, err := io.WriteString(w, "body")
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if saved.WorkDir != dir || saved.Path != "opencti-lookup-a-x.txt" || saved.AbsPath != filepath.Join(dir, saved.Path) {
		t.Fatalf("%+v", saved)
	}
	if b, _ := os.ReadFile(saved.AbsPath); string(b) != "body" {
		t.Fatalf("%q", b)
	}
	// Replaces a file of the same name.
	if _, err := Save(dir, saved.Path, func(w io.Writer) error { _, err := io.WriteString(w, "v2"); return err }); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(saved.AbsPath); string(b) != "v2" {
		t.Fatalf("%q", b)
	}
	assertOnly(t, dir, saved.Path)
}

func TestSaveFailureLeavesNothing(t *testing.T) {
	dir := t.TempDir()
	_, err := Save(dir, "opencti-lookup-a-x.txt", func(w io.Writer) error {
		_, _ = io.WriteString(w, "partial")
		return errors.New("connection reset")
	})
	if err == nil || !strings.Contains(err.Error(), "connection reset") {
		t.Fatal(err)
	}
	assertOnly(t, dir)
}

func TestSaveRefusesPathsAndEscapes(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"../x", "sub/x", ".hidden", "", "/abs"} {
		if _, err := Save(dir, name, func(io.Writer) error { return nil }); err == nil {
			t.Errorf("%q accepted", name)
		}
	}
	// A link planted in the work directory under the target name cannot carry
	// the write outside: os.Root replaces the link itself, not what it names.
	outside := t.TempDir()
	victim := filepath.Join(outside, "victim.txt")
	if err := os.WriteFile(victim, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(dir, "opencti-lookup-a-x.txt")); err != nil {
		t.Fatal(err)
	}
	if _, err := Save(dir, "opencti-lookup-a-x.txt", func(w io.Writer) error { _, err := io.WriteString(w, "new"); return err }); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "untouched" {
		t.Fatalf("the write followed a link out of the work directory: %q", b)
	}
	if fi, _ := os.Lstat(filepath.Join(dir, "opencti-lookup-a-x.txt")); fi.Mode()&os.ModeSymlink != 0 {
		t.Fatal("the link is still in place")
	}
}

func assertOnly(t *testing.T, dir string, names ...string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range entries {
		got = append(got, e.Name())
	}
	if strings.Join(got, ",") != strings.Join(names, ",") {
		t.Fatalf("directory holds %v, want %v", got, names)
	}
}
