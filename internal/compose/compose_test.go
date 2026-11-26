package compose

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestComposeLayout(t *testing.T) {
	got := Compose("MINE", "<identity>\nhi\n</identity>")
	want := "MINE\n\n```harness_prompt\n<identity>\nhi\n</identity>\n```"
	if got != want {
		t.Fatalf("got\n%q\nwant\n%q", got, want)
	}
	// user text ending in newline gets exactly one blank line, never edited
	got = Compose("MINE\n", "x\n")
	if want := "MINE\n\n```harness_prompt\nx\n```"; got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestFenceOutrunsHarness(t *testing.T) {
	for _, h := range []string{"", "no ticks", "`a`", "```go\nx\n```", "````\nquad\n````", "x ````````` y"} {
		f := Fence(h)
		if len(f) < 3 || len(f) <= LongestRun(h, '`') {
			t.Errorf("fence %d for harness with run %d", len(f), LongestRun(h, '`'))
		}
		c := Compose("u", h)
		// the closing fence must be the only line of >= len(f) backticks after the opener
		body := strings.TrimPrefix(c, "u\n\n"+f+Label+"\n")
		if strings.Contains(strings.TrimSuffix(body, f), f) {
			t.Errorf("fence %q appears inside harness body for %q", f, h)
		}
	}
}

func TestIsComposed(t *testing.T) {
	u := "be terse"
	c := Compose(u, "````inner````")
	if !IsComposed(c, u) {
		t.Fatal("composed text not recognized")
	}
	if IsComposed("<identity>", u) || IsComposed(u+"\n\n```go\n", u) {
		t.Fatal("false positive")
	}
}

const envelope = `{"project":"p","requestId":"r","request":{"contents":[{"role":"user","parts":[{"text":"hi"}]}],"systemInstruction":{"role":"user","parts":[{"text":"<identity>\nA ` + "````" + ` B\n</identity>"}]},"tools":[{"functionDeclarations":[]}],"labels":{"cascade_id":"c1","root_cascade_id":"c1"}},"model":"m","userAgent":"antigravity","requestType":"agent"}`

func TestApplyEnvelope(t *testing.T) {
	out, res, err := Apply([]byte(envelope), "MY RULES <win> & stay", Options{})
	if err != nil || !res.Rewritten {
		t.Fatalf("not rewritten: %+v %v", res, err)
	}
	var d struct {
		Request struct {
			SI struct {
				Role  string `json:"role"`
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"systemInstruction"`
		} `json:"request"`
	}
	if err := json.Unmarshal(out, &d); err != nil {
		t.Fatal(err)
	}
	want := "MY RULES <win> & stay\n\n`````harness_prompt\n<identity>\nA ```` B\n</identity>\n`````"
	if len(d.Request.SI.Parts) != 1 || d.Request.SI.Parts[0].Text != want || d.Request.SI.Role != "user" {
		t.Fatalf("bad systemInstruction: %+v", d.Request.SI)
	}
	// everything outside systemInstruction is byte-identical
	i := strings.Index(envelope, `"systemInstruction":`)
	j := strings.Index(envelope, `,"tools"`)
	if !bytes.HasPrefix(out, []byte(envelope[:i])) || !bytes.HasSuffix(out, []byte(envelope[j:])) {
		t.Fatal("bytes outside systemInstruction changed")
	}
	if bytes.Contains(out, []byte(`\u003c`)) {
		t.Fatal("HTML-escaped output")
	}
	// idempotent
	again, res2, _ := Apply(out, "MY RULES <win> & stay", Options{})
	if res2.Rewritten || !bytes.Equal(again, out) {
		t.Fatalf("second pass changed body: %+v", res2)
	}
}

func TestApplyPromptInlineAudio(t *testing.T) {
	p := Prompt{MIMEType: "audio/pcm;rate=16000", Data: "AQID"}
	out, res, err := ApplyPrompt([]byte(envelope), p, Options{})
	if err != nil || !res.Rewritten || !bytes.Contains(out, []byte(`"data":"AQID","mimeType":"audio/pcm;rate=16000"`)) {
		t.Fatalf("bad inline rewrite: %+v %v", res, err)
	}
	if again, res2, _ := ApplyPrompt(out, p, Options{}); res2.Rewritten || !bytes.Equal(again, out) {
		t.Fatalf("inline pass not idempotent: %+v", res2)
	}
}

func TestApplySkips(t *testing.T) {
	cases := map[string]string{
		"other requestType": strings.Replace(envelope, `"requestType":"agent"`, `"requestType":"judge"`, 1),
		"no system":         `{"request":{"contents":[]},"requestType":"agent"}`,
		"non-text part":     `{"request":{"systemInstruction":{"parts":[{"inlineData":{}}]}},"requestType":"agent"}`,
	}
	for name, body := range cases {
		out, res, _ := Apply([]byte(body), "u", Options{})
		if res.Rewritten || string(out) != body {
			t.Errorf("%s: expected untouched, got %+v", name, res)
		}
	}
	sub := strings.Replace(envelope, `"root_cascade_id":"c1"`, `"root_cascade_id":"c0"`, 1)
	if _, res, _ := Apply([]byte(sub), "u", Options{MainOnly: true}); res.Rewritten {
		t.Error("subagent rewritten in main-only scope")
	}
	if _, res, _ := Apply([]byte(sub), "u", Options{}); !res.Rewritten {
		t.Error("subagent skipped in default scope")
	}
}

func TestApplyBareGenerateContent(t *testing.T) {
	body := `{"contents":[],"systemInstruction":{"parts":[{"text":"a"},{"text":"b"}],"role":"user"}}`
	out, res, err := Apply([]byte(body), "U", Options{})
	if err != nil || !res.Rewritten {
		t.Fatalf("%+v %v", res, err)
	}
	if want := `{"contents":[],"systemInstruction":{"parts":[{"text":"U\n\n` + "```" + `harness_prompt\nab\n` + "```" + `"}],"role":"user"}}`; string(out) != want {
		t.Fatalf("got %s", out)
	}
}

// TestApplyCapturedRequest runs against a real captured request when available.
func TestApplyCapturedRequest(t *testing.T) {
	p := os.Getenv("AGY_SP_CAPTURE")
	if p == "" {
		t.Skip("set AGY_SP_CAPTURE to a captured streamGenerateContent body")
	}
	body, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	out, res, err := Apply(body, "USER FILE", Options{})
	if err != nil || !res.Rewritten {
		t.Fatalf("%+v %v", res, err)
	}
	var a, b map[string]any
	json.Unmarshal(body, &a)
	json.Unmarshal(out, &b)
	ra, rb := a["request"].(map[string]any), b["request"].(map[string]any)
	for k := range ra {
		if k == "systemInstruction" {
			continue
		}
		ja, _ := json.Marshal(ra[k])
		jb, _ := json.Marshal(rb[k])
		if !bytes.Equal(ja, jb) {
			t.Errorf("request.%s changed", k)
		}
	}
	t.Logf("harness %d chars -> composed %d chars", res.HarnessLen, res.ComposedLen)
}

func vertexBody(lead, cascade, root string) string {
	labels := ""
	if cascade != "" {
		labels = `,"labels":{"cascade_id":"` + cascade + `","root_cascade_id":"` + root + `","client":"antigravity-cli"}`
	}
	return `{"contents":[{"role":"user","parts":[{"text":"hi"}]}],"systemInstruction":{"role":"user","parts":[{"text":"` + lead + `\nYou are X\n"}]},"tools":[]` + labels + `,"sessionId":"-1"}`
}

func TestApplyVertexAgentGate(t *testing.T) {
	opt := Options{BareAgentOnly: true}
	cases := []struct {
		name, body string
		want       bool
	}{
		{"main agent", vertexBody("<identity>", "c1", "c1"), true},
		{"subagent (capital Identity)", vertexBody("<Identity>", "c2", "c1"), true},
		{"no labels", vertexBody("<identity>", "", ""), false},
		{"monitor-style prompt", vertexBody("You are a safety monitor.", "c1", "c1"), false},
		{"other leading tag", vertexBody("<task>", "c1", "c1"), false},
	}
	for _, c := range cases {
		out, res, err := Apply([]byte(c.body), "U", opt)
		if err != nil || res.Rewritten != c.want {
			t.Errorf("%s: rewritten=%v want %v (%s, %v)", c.name, res.Rewritten, c.want, res.Reason, err)
		}
		if !c.want && string(out) != c.body {
			t.Errorf("%s: skipped body was modified", c.name)
		}
		if res.Shape != "bare" {
			t.Errorf("%s: shape %q", c.name, res.Shape)
		}
	}
	// Subagent detection works on the bare shape too.
	if _, res, _ := Apply([]byte(vertexBody("<Identity>", "c2", "c1")), "U", Options{BareAgentOnly: true, MainOnly: true}); res.Rewritten {
		t.Error("subagent rewritten in main-only scope")
	}
	// Lead is structural only.
	if _, res, _ := Apply([]byte(vertexBody("You are a safety monitor.", "c1", "c1")), "U", opt); res.Lead != "" {
		t.Errorf("lead leaked content: %q", res.Lead)
	}
}
