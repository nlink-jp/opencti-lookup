package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/nlink-jp/opencti-lookup/internal/opencti"
)

// MaxFileBytes is the largest attachment get_report_file saves.
const MaxFileBytes = 100 << 20

// FileRef is one attachment of an object.
type FileRef struct {
	Name         string `json:"name"`
	Size         int64  `json:"size"`
	MimeType     string `json:"mime_type,omitempty"`
	LastModified string `json:"last_modified,omitempty"`
	id           string // the storage id; never shown, rebuilt from the listing
}

type wireFiles struct {
	Edges []struct {
		Node struct {
			ID           string `json:"id"`
			Name         string `json:"name"`
			Size         int64  `json:"size"`
			LastModified string `json:"lastModified"`
			MetaData     *struct {
				Mimetype string `json:"mimetype"`
			} `json:"metaData"`
		} `json:"node"`
	} `json:"edges"`
}

func (w wireFiles) refs() []FileRef {
	out := []FileRef{}
	for _, e := range w.Edges {
		n := e.Node
		f := FileRef{Name: n.Name, Size: n.Size, LastModified: n.LastModified, id: n.ID}
		if n.MetaData != nil {
			f.MimeType = n.MetaData.Mimetype
		}
		out = append(out, f)
	}
	return out
}

// FileInfo describes one attachment saved by GetFile.
type FileInfo struct {
	Of       Ref    `json:"of"`
	Name     string `json:"name"` // as OpenCTI lists it: third-party text
	MimeType string `json:"mime_type,omitempty"`
	Bytes    int64  `json:"bytes"`
	SHA256   string `json:"sha256"`
}

// GetFile writes the attachment named name of object id to w. The name must be
// one the object lists (get_entity's files): the storage id is taken from the
// listing, never built from the caller's string, so no argument can steer the
// request to another path in the instance's storage.
func (e *Engine) GetFile(ctx context.Context, id, name string, w io.Writer) (*FileInfo, error) {
	if strings.TrimSpace(name) == "" {
		return nil, invalid("name is required (the file name as get_entity lists it)")
	}
	of, err := e.exists(ctx, id)
	if err != nil {
		return nil, err
	}
	var out struct {
		Obj *struct {
			ImportFiles wireFiles `json:"importFiles"`
		} `json:"stixCoreObject"`
	}
	q := `query Files($id: String!) { stixCoreObject(id: $id) { importFiles(first: 500) { edges { node { id name size lastModified metaData { mimetype } } } } } }`
	if err := e.query(ctx, q, map[string]any{"id": of.ID}, &out); err != nil {
		return nil, err
	}
	if out.Obj == nil {
		return nil, &Error{Code: CodeNotFound, Message: fmt.Sprintf("no object %q within what this key can see", id)}
	}
	files := out.Obj.ImportFiles.refs()
	var file *FileRef
	for i := range files {
		if files[i].Name == name {
			file = &files[i]
			break
		}
	}
	if file == nil {
		names := make([]string, 0, len(files))
		for _, f := range files {
			names = append(names, fmt.Sprintf("%q", f.Name))
		}
		listed := "it lists none"
		if len(names) > 0 {
			listed = "it lists " + strings.Join(names, ", ")
		}
		return nil, &Error{Code: CodeNotFound, Message: fmt.Sprintf("%s %q has no attachment named %q within what this key can see; %s", of.Type, of.Name, name, listed)}
	}
	if file.Size > MaxFileBytes {
		return nil, &Error{Code: opencti.CodeFileTooLarge, Message: fmt.Sprintf("%q is %d bytes; this tool saves at most %d MB", name, file.Size, MaxFileBytes>>20)}
	}
	if err := e.ready(); err != nil {
		return nil, err
	}
	h := sha256.New()
	n, ctype, err := e.Client.Download(ctx, file.id, io.MultiWriter(w, h), MaxFileBytes)
	if err != nil {
		return nil, err
	}
	mime := file.MimeType
	if mime == "" {
		mime = ctype
	}
	return &FileInfo{Of: of, Name: file.Name, MimeType: mime, Bytes: n, SHA256: hex.EncodeToString(h.Sum(nil))}, nil
}
