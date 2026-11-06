package mcp

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
)

// Vendored from shodan-lookup, which took it from cve-lookup (its correction 23). Every large part of a result
// that was measured gets a cap of its own and a way to be read in full. Those
// caps are written one field at a time, and cve-lookup's implementation review
// still found five fields nobody had capped. Listing fields does not close that
// class; this does. After a tool has built its result, every string in it that
// no cap of its own governs is held to fieldClip characters, and the result
// says which fields were shortened.
//
// A value this long in a field nothing caps is not data this tool understands,
// so there is no section for it: the CLI's --json output is complete, and the
// note says so.

// ownCap names what is carried whole by design: a description (get_entity
// exists to read one in full; a report's runs to many thousands of
// characters), an indicator's pattern (a YARA or Sigma rule is long, and a cut
// rule is a wrong rule), and a note's content, which get_entity returns as its
// description. Struct fields are matched by their Go name and map entries by
// their key, so both spellings are listed. Search rows carry a bounded
// excerpt instead (description_excerpt), which is not exempt.
var ownCap = map[string]bool{"Description": true, "description": true, "Pattern": true, "pattern": true}

// fieldClip is the longest an ungoverned string may be, in characters. The
// fields that exist to carry long text whole (a description, a pattern, a
// note's content) are governed by name in ownCap; anything else this long is
// shortened and named.
const fieldClip = 1000

// capStrings returns v with every ungoverned string held to fieldClip runes,
// and the names of the fields it shortened. v is never modified in place unless
// it is a pointer the tool built for this one answer.
func capStrings(v any) (any, []string) {
	if v == nil {
		return v, nil
	}
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Pointer {
		cp := reflect.New(rv.Type()).Elem()
		cp.Set(rv)
		rv = cp
	}
	seen := map[string]bool{}
	capValue(rv, "", seen)
	if len(seen) == 0 {
		return v, nil
	}
	names := make([]string, 0, len(seen))
	for n := range seen {
		names = append(names, n)
	}
	sort.Strings(names)
	note := fmt.Sprintf("%s: longer than %d characters and shortened here (marked …). A value that long in such a field is unusual; the CLI's --json output holds it whole",
		strings.Join(names, ", "), fieldClip)
	addNote(rv, note)
	return rv.Interface(), names
}

func capValue(v reflect.Value, name string, seen map[string]bool) {
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if !v.IsNil() {
			capValue(v.Elem(), name, seen)
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			f := v.Type().Field(i)
			if !f.IsExported() || ownCap[f.Name] {
				continue
			}
			capValue(v.Field(i), jsonName(f, name), seen)
		}
	case reflect.Slice, reflect.Array:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			return // an embedded JSON document; its size is capped where it is built
		}
		for i := 0; i < v.Len(); i++ {
			capValue(v.Index(i), name, seen)
		}
	case reflect.Map:
		for _, k := range v.MapKeys() {
			if k.Kind() == reflect.String && ownCap[k.String()] {
				continue
			}
			// Map elements are not addressable, and in a map[string]any the
			// element is an interface whose content cannot be set either: take
			// the concrete value out, shorten a copy of it, and store that.
			elem := v.MapIndex(k)
			for elem.Kind() == reflect.Interface && !elem.IsNil() {
				elem = elem.Elem()
			}
			if elem.Kind() == reflect.Interface {
				continue // a nil value
			}
			cp := reflect.New(elem.Type()).Elem()
			cp.Set(elem)
			child := name
			if k.Kind() == reflect.String {
				child = join(name, k.String())
			}
			capValue(cp, child, seen)
			v.SetMapIndex(k, cp)
		}
	case reflect.String:
		if r := []rune(v.String()); len(r) > fieldClip && v.CanSet() {
			v.SetString(string(r[:fieldClip]) + "…")
			seen[name] = true
		}
	}
}

// jsonName is the name the field has in the output, under its parent's.
func jsonName(f reflect.StructField, parent string) string {
	if f.Anonymous {
		return parent // an embedded struct adds no level to the JSON
	}
	name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
	if name == "" {
		name = f.Name
	}
	return join(parent, name)
}

func join(parent, name string) string {
	if parent == "" {
		return name
	}
	return parent + "." + name
}

// addNote appends to the result's notes: a Notes field (its own or a promoted
// one), or the "notes" key of a map-shaped result.
func addNote(v reflect.Value, note string) {
	for v.Kind() == reflect.Pointer || v.Kind() == reflect.Interface {
		if v.IsNil() {
			return
		}
		v = v.Elem()
	}
	switch v.Kind() {
	case reflect.Struct:
		if f := v.FieldByName("Notes"); f.IsValid() && f.CanSet() && f.Type() == reflect.TypeOf([]string(nil)) {
			f.Set(reflect.Append(f, reflect.ValueOf(note)))
		}
	case reflect.Map:
		if v.Type().Key().Kind() != reflect.String || v.Type().Elem().Kind() != reflect.Interface {
			return
		}
		key := reflect.ValueOf("notes")
		var notes []string
		if cur := v.MapIndex(key); cur.IsValid() {
			notes, _ = cur.Interface().([]string)
		}
		v.SetMapIndex(key, reflect.ValueOf(append(notes, note)))
	}
}
