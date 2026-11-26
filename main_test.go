package main

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestExtractFlag(t *testing.T) {
	cases := []struct {
		in   []string
		val  string
		set  bool
		rest []string
	}{
		{[]string{"-p", "hi"}, "", false, []string{"-p", "hi"}},
		{[]string{"--system-prompt-file", "a.md", "-c"}, "a.md", true, []string{"-c"}},
		{[]string{"--model", "x", "--system-prompt-file=b.md"}, "b.md", true, []string{"--model", "x"}},
		{[]string{"-system-prompt-file", "c.md"}, "c.md", true, []string{}},
		{[]string{"--system-prompt-file="}, "", true, []string{}},
		{[]string{"--", "--system-prompt-file", "z"}, "", false, []string{"--", "--system-prompt-file", "z"}},
	}
	for _, c := range cases {
		val, set, rest, err := extractFlag(c.in)
		if err != nil || val != c.val || set != c.set || !slices.Equal(rest, c.rest) {
			t.Errorf("%v: got %q %v %v %v", c.in, val, set, rest, err)
		}
	}
	if _, _, _, err := extractFlag([]string{"--system-prompt-file"}); err == nil {
		t.Error("missing value accepted")
	}
}

func TestSubcommand(t *testing.T) {
	cases := map[string][]string{
		"mcp":            {"mcp", "list"},
		"":               {"-p", "models"},
		"update":         {"--model", "flash", "update"},
		"remote-control": {"--sandbox", "remote-control", "start"},
		"plugins":        {"--model=x", "plugins"},
	}
	for want, args := range cases {
		if got := subcommand(args); got != want {
			t.Errorf("%v: got %q want %q", args, got, want)
		}
	}
}

func TestLoadPrompt(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "p.md")
	os.WriteFile(p, []byte("\ufeff# Mine\n\nkeep  `this`\n"), 0o600)
	got, err := loadPrompt(p)
	if err != nil || got.Text != "# Mine\n\nkeep  `this`\n" || got.Inline() {
		t.Fatalf("%+v %v", got, err)
	}
	os.WriteFile(p, []byte(" \n\t\n"), 0o600)
	if _, err := loadPrompt(p); err == nil {
		t.Error("blank file accepted")
	}
	pcm := filepath.Join(d, "p.pcm")
	os.WriteFile(pcm, []byte{1, 2, 3, 4}, 0o600)
	gotPCM, err := loadPrompt(pcm)
	if err != nil || gotPCM.MIMEType != "audio/pcm;rate=16000" || gotPCM.Data != "AQIDBA==" {
		t.Fatalf("pcm: %+v %v", gotPCM, err)
	}
}

func TestRunSPConfig(t *testing.T) {
	d := t.TempDir()
	cfg := filepath.Join(d, "agy-sp.json")
	md := filepath.Join(d, "rules.md")
	os.WriteFile(md, []byte("be terse\n"), 0o600)

	if err := runSP([]string{"set", md}, d, d, cfg); err != nil {
		t.Fatalf("set md: %v", err)
	}
	if got, err := configPromptPath(cfg); err != nil || got != md {
		t.Fatalf("config after set: %q %v", got, err)
	}
	if err := runSP([]string{"clear"}, d, d, cfg); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if got, err := configPromptPath(cfg); err != nil || got != "" {
		t.Fatalf("config after clear: %q %v", got, err)
	}
}

func TestVertexHelpers(t *testing.T) {
	if m := vertexModel("/v1/projects/p/locations/global/publishers/google/models/gemini-4-neon:streamGenerateContent"); m != "gemini-4-neon" {
		t.Errorf("model %q", m)
	}
	for h, want := range map[string]bool{"aiplatform.googleapis.com": true, "us-central1-aiplatform.googleapis.com:443": true, "daily-cloudcode-pa.googleapis.com": false} {
		if isVertexHost(h) != want {
			t.Errorf("isVertexHost(%q) != %v", h, want)
		}
	}
	home := t.TempDir()
	t.Setenv("GOOGLE_CLOUD_LOCATION", "global")
	if hs := interceptHosts(home); !slices.Equal(hs, []string{"cloudcode-pa.googleapis.com", "daily-cloudcode-pa.googleapis.com", "aiplatform.googleapis.com"}) {
		t.Errorf("global hosts %v", hs)
	}
	t.Setenv("GOOGLE_CLOUD_LOCATION", "europe-west4")
	if hs := interceptHosts(home); hs[len(hs)-1] != "europe-west4-aiplatform.googleapis.com" {
		t.Errorf("regional hosts %v", hs)
	}
	t.Setenv("GOOGLE_CLOUD_LOCATION", "")
	os.MkdirAll(filepath.Join(home, ".gemini", "antigravity-cli"), 0o700)
	os.WriteFile(filepath.Join(home, ".gemini", "antigravity-cli", "settings.json"), []byte(`{"gcp":{"location":"us-east5"}}`), 0o600)
	if hs := interceptHosts(home); hs[len(hs)-1] != "us-east5-aiplatform.googleapis.com" {
		t.Errorf("settings hosts %v", hs)
	}
}
