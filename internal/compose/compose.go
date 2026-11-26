// Package compose builds the layered system prompt and splices it into
// Antigravity model requests without disturbing any other bytes.
//
// Layout of the composed prompt:
//
//	<user file, verbatim>
//	<blank line>
//	````harness_prompt          (fence = longest backtick run in harness + 1, min 3)
//	<built-in prompt, verbatim>
//	````
package compose

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Label is the info string on the fence that wraps the built-in prompt.
const Label = "harness_prompt"

// Compose returns the user prompt followed by the fenced harness prompt.
func Compose(user, harness string) string {
	fence := Fence(harness)
	var b strings.Builder
	b.Grow(len(user) + len(harness) + 2*len(fence) + len(Label) + 4)
	b.WriteString(user)
	if !strings.HasSuffix(user, "\n") {
		b.WriteByte('\n')
	}
	b.WriteByte('\n')
	b.WriteString(fence)
	b.WriteString(Label)
	b.WriteByte('\n')
	b.WriteString(harness)
	if !strings.HasSuffix(harness, "\n") {
		b.WriteByte('\n')
	}
	b.WriteString(fence)
	return b.String()
}

// Fence returns a backtick fence strictly longer than any backtick run in s.
func Fence(s string) string {
	return strings.Repeat("`", max(3, LongestRun(s, '`')+1))
}

// LongestRun reports the length of the longest run of c in s.
func LongestRun(s string, c byte) int {
	best, cur := 0, 0
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			cur++
			best = max(best, cur)
		} else {
			cur = 0
		}
	}
	return best
}

// IsComposed reports whether text already has the layered shape for user.
func IsComposed(text, user string) bool {
	rest, ok := strings.CutPrefix(text, user)
	if !ok {
		return false
	}
	rest = strings.TrimLeft(rest, "\n")
	n := len(rest) - len(strings.TrimLeft(rest, "`"))
	return n >= 3 && strings.HasPrefix(rest[n:], Label+"\n")
}

// Options controls which requests are rewritten.
type Options struct {
	// RequestTypes lists the top-level "requestType" values to rewrite (Code
	// Assist envelope). Empty means "agent" only.
	RequestTypes []string
	// MainOnly restricts rewriting to the root conversation (labels.cascade_id
	// == labels.root_cascade_id), skipping subagents.
	MainOnly bool
	// BareAgentOnly applies to bare generateContent bodies (Vertex AI), which
	// carry no requestType. When set, only Antigravity agent turns are
	// rewritten: labels.cascade_id must be present and the built-in prompt must
	// open with an <identity> tag (any case). Monitors and other utility calls
	// are left alone.
	BareAgentOnly bool
}

// Result describes what Apply did.
type Result struct {
	Rewritten   bool
	Reason      string // why it was skipped, or "ok"
	RequestType string
	Shape       string // "codeassist" (enveloped) or "bare" (Vertex AI)
	Lead        string // leading XML-style tag of the built-in prompt, e.g. "<identity>" (structure only, never content)
	HarnessLen  int
	ComposedLen int
	Composed    string // the new system prompt text (only when Rewritten)
}

// Prompt is either plain user text or an inline media part placed ahead of harness text.
type Prompt struct{ Text, MIMEType, Data string }

func (p Prompt) Inline() bool { return p.MIMEType != "" }

// Apply rewrites systemInstruction in a generateContent request body with plain user text.
func Apply(body []byte, user string, opt Options) ([]byte, Result, error) {
	return ApplyPrompt(body, Prompt{Text: user}, opt)
}

// ApplyPrompt rewrites systemInstruction in a generateContent request body
// (Code Assist envelope or bare Vertex body), keeping all other bytes identical.
func ApplyPrompt(body []byte, p Prompt, opt Options) ([]byte, Result, error) {
	var res Result
	reqStart, reqEnd, hasReq, err := member(body, 0, "request")
	if err != nil {
		return body, skip(res, "body is not a JSON object"), err
	}
	inner, base := body, 0
	res.Shape = "bare"
	if hasReq {
		res.Shape = "codeassist"
		inner, base = body[reqStart:reqEnd], reqStart
		rt, err := stringMember(body, "requestType")
		if err != nil {
			return body, skip(res, "bad requestType"), err
		}
		res.RequestType = rt
		types := opt.RequestTypes
		if len(types) == 0 {
			types = []string{"agent"}
		}
		if !contains(types, rt) {
			return body, skip(res, fmt.Sprintf("requestType %q not selected", rt)), nil
		}
	}
	if opt.MainOnly {
		if sub, err := isSubagent(inner); err != nil || sub {
			return body, skip(res, "subagent request (main-only scope)"), err
		}
	}
	siStart, siEnd, ok, err := member(inner, 0, "systemInstruction")
	if err != nil {
		return body, skip(res, "request is not a JSON object"), err
	}
	if !ok {
		return body, skip(res, "no systemInstruction"), nil
	}
	si := inner[siStart:siEnd]
	harness, err := textOf(si)
	if err != nil {
		return body, skip(res, err.Error()), nil
	}
	res.HarnessLen = len(harness)
	res.Lead = leadTag(harness)
	if !hasReq && opt.BareAgentOnly {
		if !strings.EqualFold(res.Lead, "<identity>") {
			return body, skip(res, "not an agent prompt (no leading <identity>)"), nil
		}
		if c, err := labelString(inner, "cascade_id"); err != nil || c == "" {
			return body, skip(res, "not an agent turn (no labels.cascade_id)"), err
		}
	}
	var composed string
	var parts any
	if p.Inline() {
		composed = strings.TrimLeft(Compose("", harness), "\n")
		parts = []any{
			map[string]any{"inlineData": map[string]string{"mimeType": p.MIMEType, "data": p.Data}},
			map[string]string{"text": composed},
		}
	} else {
		if IsComposed(harness, p.Text) {
			return body, skip(res, "already composed"), nil
		}
		composed = Compose(p.Text, harness)
		parts = []map[string]string{{"text": composed}}
	}
	newSI, err := replaceParts(si, parts)
	if err != nil {
		return body, skip(res, "cannot rebuild systemInstruction"), err
	}
	abs0, abs1 := base+siStart, base+siEnd
	out := make([]byte, 0, len(body)-len(si)+len(newSI))
	out = append(out, body[:abs0]...)
	out = append(out, newSI...)
	out = append(out, body[abs1:]...)
	res.Rewritten, res.Reason = true, "ok"
	res.ComposedLen, res.Composed = len(p.Data)+len(composed), composed
	return out, res, nil
}

func skip(r Result, why string) Result { r.Reason = why; return r }

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// member finds the byte range of the value of key in the JSON object that
// starts at data[off:]. Only direct members are considered.
func member(data []byte, off int, key string) (start, end int, found bool, err error) {
	dec := json.NewDecoder(bytes.NewReader(data[off:]))
	tok, err := dec.Token()
	if err != nil {
		return 0, 0, false, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return 0, 0, false, errors.New("not an object")
	}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return 0, 0, false, err
		}
		k, _ := kt.(string)
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return 0, 0, false, err
		}
		if k == key {
			e := off + int(dec.InputOffset())
			return e - len(raw), e, true, nil
		}
	}
	return 0, 0, false, nil
}

func stringMember(obj []byte, key string) (string, error) {
	s, e, ok, err := member(obj, 0, key)
	if err != nil || !ok {
		return "", err
	}
	var v string
	err = json.Unmarshal(obj[s:e], &v)
	return v, err
}

// leadTag returns the opening tag on the first line (e.g. "<identity>"), or "".
func leadTag(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	line = strings.TrimSpace(line)
	if len(line) < 3 || len(line) > 48 || line[0] != '<' || line[len(line)-1] != '>' || strings.ContainsAny(line[1:len(line)-1], "<>/") {
		return ""
	}
	return line
}

func labelString(req []byte, key string) (string, error) {
	s, e, ok, err := member(req, 0, "labels")
	if err != nil || !ok {
		return "", err
	}
	return stringMember(req[s:e], key)
}

func isSubagent(req []byte) (bool, error) {
	s, e, ok, err := member(req, 0, "labels")
	if err != nil || !ok {
		return false, err
	}
	var l struct {
		Cascade string `json:"cascade_id"`
		Root    string `json:"root_cascade_id"`
	}
	if err := json.Unmarshal(req[s:e], &l); err != nil {
		return false, err
	}
	return l.Root != "" && l.Cascade != l.Root, nil
}

// textOf concatenates the text parts of a Content object. Any part that is
// not a plain {"text": ...} part makes the instruction ineligible.
func textOf(si []byte) (string, error) {
	var c struct {
		Parts []map[string]json.RawMessage `json:"parts"`
	}
	if err := json.Unmarshal(si, &c); err != nil {
		return "", errors.New("systemInstruction is not a Content object")
	}
	if len(c.Parts) == 0 {
		return "", errors.New("systemInstruction has no parts")
	}
	var b strings.Builder
	for _, p := range c.Parts {
		raw, ok := p["text"]
		if !ok || len(p) != 1 {
			return "", errors.New("systemInstruction has a non-text part")
		}
		var t string
		if err := json.Unmarshal(raw, &t); err != nil {
			return "", errors.New("systemInstruction text is not a string")
		}
		b.WriteString(t)
	}
	return b.String(), nil
}

// replaceParts re-emits the Content object with its members in their original
// order, swapping only "parts" for the given marshaled parts slice.
func replaceParts(si []byte, partsVal any) ([]byte, error) {
	parts, err := marshalNoEscape(partsVal)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(si))
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	out.WriteByte('{')
	first := true
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, err
		}
		k := kt.(string)
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, err
		}
		if !first {
			out.WriteByte(',')
		}
		first = false
		kb, _ := marshalNoEscape(k)
		out.Write(kb)
		out.WriteByte(':')
		if k == "parts" {
			out.Write(parts)
		} else {
			out.Write(raw)
		}
	}
	out.WriteByte('}')
	return out.Bytes(), nil
}

func marshalNoEscape(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(b.Bytes(), "\n"), nil
}
