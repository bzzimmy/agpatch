// agy-sp wraps the Antigravity CLI so a Markdown file can be layered in front
// of the built-in system prompt.
//
// Without a prompt file it execs the real agy with the original arguments and
// environment, so behaviour is exactly unchanged. With one, it runs a local
// HTTPS proxy that intercepts only Antigravity's model backend
// (cloudcode-pa.googleapis.com) and rewrites systemInstruction in agent
// requests to:
//
//	<your file, verbatim>
//
//	````harness_prompt
//	<the complete built-in prompt>
//	````
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"agpatch/agysp/internal/compose"
	"agpatch/agysp/internal/mitm"
)

const (
	flagName   = "system-prompt-file"
	envPrompt  = "AGY_SYSTEM_PROMPT_FILE"
	envReal    = "AGY_SP_REAL_AGY"
	envScope   = "AGY_SP_SCOPE"         // "all" (default) or "main"
	envTypes   = "AGY_SP_REQUEST_TYPES" // comma list, default "agent"
	envDump    = "AGY_SP_DUMP"          // "1": write the last composed prompt to the state dir
	envMarker  = "AGY_SP_PROXY"         // set in the child; detects our own proxy in HTTPS_PROXY
	configName = "agy-sp.json"
)

// Hosts whose traffic is decrypted (see interceptHosts). Everything else is
// tunnelled untouched.
var codeAssistHosts = []string{
	"cloudcode-pa.googleapis.com",
	"daily-cloudcode-pa.googleapis.com",
}

// Vertex AI's global endpoint. A regional endpoint is added when the GCP
// location (GOOGLE_CLOUD_LOCATION or settings.json gcp.location) is a region.
const vertexGlobalHost = "aiplatform.googleapis.com"

// Only Gemini (Google-published) models are rewritten on Vertex AI.
const vertexGeminiPath = "/publishers/google/models/"

var modelPaths = []string{":streamGenerateContent", ":generateContent"}

// agy subcommands that never run a model session; they bypass the proxy so
// that, e.g., a daemon started by `remote-control start` never inherits a
// proxy address that dies when this wrapper exits.
var passthroughSubcommands = map[string]bool{
	"agent": true, "agents": true, "changelog": true, "help": true, "install": true,
	"mcp": true, "mic-serve": true, "models": true, "plugin": true, "plugins": true,
	"remote-control": true, "update": true,
}

// agy flags that consume the next argument (when not written as --flag=value).
var valueFlags = map[string]bool{
	"add-dir": true, "agent": true, "conversation": true, "effort": true, "i": true,
	"prompt-interactive": true, "input-format": true, "json-schema": true, "log-file": true,
	"mode": true, "model": true, "output-format": true, "p": true, "print": true, "prompt": true,
	"print-timeout": true, "project": true, "settings": true,
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "agy-sp: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	real, err := realAgy()
	if err != nil {
		return err
	}
	flagPath, flagSet, args, err := extractFlag(os.Args[1:])
	if err != nil {
		return err
	}
	home, _ := os.UserHomeDir()
	stateDir := filepath.Join(home, ".gemini", "antigravity-cli", "agy-sp")

	promptPath := ""
	switch {
	case flagSet:
		promptPath = flagPath // an explicit empty value disables the prompt for this run
	case os.Getenv(envPrompt) != "":
		promptPath = os.Getenv(envPrompt)
	default:
		promptPath, err = configPromptPath(filepath.Join(home, ".gemini", "antigravity-cli", configName))
		if err != nil {
			return err
		}
	}
	if promptPath == "" || passthroughSubcommands[subcommand(args)] {
		return execAgy(real, args, os.Environ())
	}

	user, err := loadPrompt(expand(promptPath, home))
	if err != nil {
		return err
	}
	hosts := interceptHosts(home)
	ca, err := mitm.LoadOrCreateCA(stateDir, hosts)
	if err != nil {
		return fmt.Errorf("local CA: %w", err)
	}
	bundle, err := writeTrustBundle(stateDir, ca.CertPEM)
	if err != nil {
		return fmt.Errorf("trust bundle: %w", err)
	}
	logf := openLog(filepath.Join(stateDir, "agy-sp.log"))
	// BareAgentOnly only affects Vertex AI bodies; Code Assist requests are
	// selected by requestType instead.
	opts := compose.Options{MainOnly: os.Getenv(envScope) == "main", BareAgentOnly: true}
	if t := os.Getenv(envTypes); t != "" {
		opts.RequestTypes = strings.Split(t, ",")
	}
	dump := os.Getenv(envDump) == "1"

	p := &mitm.Proxy{
		CA:       ca,
		Hosts:    toSet(hosts),
		Paths:    modelPaths,
		Upstream: upstreamProxy(),
		Logf:     logf,
		Rewrite: func(r *http.Request, body []byte) ([]byte, string) {
			model := modelOf(body)
			if isVertexHost(r.Host) {
				if !strings.Contains(r.URL.Path, vertexGeminiPath) {
					return body, "" // non-Gemini publisher (e.g. Anthropic): leave alone
				}
				model = vertexModel(r.URL.Path)
			}
			out, res, err := compose.Apply(body, user, opts)
			if !res.Rewritten {
				if err != nil || res.Reason != "no systemInstruction" {
					logf("skip %s shape=%s type=%q model=%s lead=%q: %s %v", r.URL.Path, res.Shape, res.RequestType, model, res.Lead, res.Reason, errOrEmpty(err))
				}
				return body, ""
			}
			if dump {
				mitm.WriteFileAtomic(filepath.Join(stateDir, "last-system-prompt.md"), []byte(res.Composed), 0o600)
			}
			kind := "type=" + res.RequestType
			if res.Shape == "bare" {
				kind = "vertex"
			}
			return out, fmt.Sprintf("rewrote %s model=%s harness=%dB composed=%dB",
				kind, model, res.HarnessLen, res.ComposedLen)
		},
	}
	addr, err := p.Start()
	if err != nil {
		return fmt.Errorf("start proxy: %w", err)
	}
	purl := "http://" + addr
	logf("session start pid=%d proxy=%s prompt=%s (%d bytes) agy=%s", os.Getpid(), purl, promptPath, len(user), real)
	warnNoProxy(hosts)

	env := withEnv(os.Environ(), map[string]string{
		"HTTPS_PROXY":   purl,
		"https_proxy":   purl,
		"SSL_CERT_FILE": bundle,
		envMarker:       purl,
	})
	return superviseAgy(real, args, env, logf)
}

// extractFlag removes --system-prompt-file (also -system-prompt-file, with a
// separate or =value) from args. Scanning stops at a literal "--".
func extractFlag(args []string) (val string, set bool, rest []string, err error) {
	rest = make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			rest = append(rest, args[i:]...)
			break
		}
		name, v, hasEq := strings.Cut(strings.TrimLeft(a, "-"), "=")
		if !strings.HasPrefix(a, "-") || name != flagName {
			rest = append(rest, a)
			continue
		}
		if !hasEq {
			if i+1 >= len(args) {
				return "", false, nil, fmt.Errorf("--%s needs a path", flagName)
			}
			i++
			v = args[i]
		}
		val, set = v, true
	}
	return val, set, rest, nil
}

// subcommand returns the first positional argument, skipping flag values.
func subcommand(args []string) string {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			return ""
		}
		if !strings.HasPrefix(a, "-") {
			return a
		}
		name, _, hasEq := strings.Cut(strings.TrimLeft(a, "-"), "=")
		if valueFlags[name] && !hasEq {
			i++
		}
	}
	return ""
}

func configPromptPath(path string) (string, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	var c struct {
		SystemPromptFile string `json:"systemPromptFile"`
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}
	return c.SystemPromptFile, nil
}

func loadPrompt(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("system prompt file: %w", err)
	}
	b = []byte(strings.TrimPrefix(string(b), "\ufeff"))
	if !utf8.Valid(b) {
		return "", fmt.Errorf("system prompt file %s is not valid UTF-8", path)
	}
	if strings.TrimSpace(string(b)) == "" {
		return "", fmt.Errorf("system prompt file %s is empty", path)
	}
	return string(b), nil
}

func expand(p, home string) string {
	if p == "~" {
		return home
	}
	if rest, ok := strings.CutPrefix(p, "~/"); ok {
		return filepath.Join(home, rest)
	}
	if abs, err := filepath.Abs(p); err == nil {
		return abs
	}
	return p
}

// realAgy finds the actual agy binary, never this wrapper.
func realAgy() (string, error) {
	if p := os.Getenv(envReal); p != "" {
		return p, nil
	}
	self, _ := os.Executable()
	selfInfo, _ := os.Stat(self)
	isSelf := func(p string) bool {
		fi, err := os.Stat(p)
		return err == nil && selfInfo != nil && os.SameFile(fi, selfInfo)
	}
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		c := filepath.Join(dir, "agy")
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0 && !isSelf(c) {
			return c, nil
		}
	}
	home, _ := os.UserHomeDir()
	if c := filepath.Join(home, ".local", "bin", "agy"); !isSelf(c) {
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}
	return "", errors.New("cannot find the real agy binary (set " + envReal + ")")
}

func execAgy(real string, args, env []string) error {
	return syscall.Exec(real, append([]string{"agy"}, args...), env)
}

func superviseAgy(real string, args, env []string, logf func(string, ...any)) error {
	cmd := exec.Command(real, args...)
	cmd.Args[0] = "agy"
	cmd.Env = env
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	// Terminal-generated signals reach agy directly (same process group);
	// catch them here so the wrapper outlives agy, and forward the rest.
	sigs := make(chan os.Signal, 8)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGHUP)
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() {
		for s := range sigs {
			if s == syscall.SIGTERM || s == syscall.SIGHUP {
				cmd.Process.Signal(s)
			}
		}
	}()
	err := cmd.Wait()
	logf("session end pid=%d: %v", os.Getpid(), errOrEmpty(err))
	if err == nil {
		return nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			os.Exit(128 + int(ws.Signal()))
		}
		os.Exit(ee.ExitCode())
	}
	return err
}

// writeTrustBundle writes the roots agy should trust: the existing
// SSL_CERT_FILE if one is set, otherwise the macOS system and admin roots,
// plus the local CA (which can only sign for the intercepted hosts).
func writeTrustBundle(dir string, caPEM []byte) (string, error) {
	var base []byte
	if f := os.Getenv("SSL_CERT_FILE"); f != "" && os.Getenv(envMarker) == "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return "", err
		}
		base = b
	} else {
		for _, kc := range []string{"/System/Library/Keychains/SystemRootCertificates.keychain", "/Library/Keychains/System.keychain"} {
			out, err := exec.Command("/usr/bin/security", "find-certificate", "-a", "-p", kc).Output()
			if err != nil && kc == "/System/Library/Keychains/SystemRootCertificates.keychain" {
				return "", fmt.Errorf("read system roots: %w", err)
			}
			base = append(base, out...)
		}
	}
	b := append(append(base, '\n'), caPEM...)
	path := filepath.Join(dir, "trust-bundle.pem")
	return path, mitm.WriteFileAtomic(path, b, 0o644)
}

// upstreamProxy returns a pre-existing HTTPS proxy to chain through, ignoring
// one of our own (nested agy-sp inside an agy session).
func upstreamProxy() *url.URL {
	v := os.Getenv("HTTPS_PROXY")
	if v == "" {
		v = os.Getenv("https_proxy")
	}
	if v == "" || v == os.Getenv(envMarker) {
		return nil
	}
	if !strings.Contains(v, "://") {
		v = "http://" + v
	}
	u, err := url.Parse(v)
	if err != nil {
		return nil
	}
	return u
}

func warnNoProxy(interceptHosts []string) {
	np := os.Getenv("NO_PROXY") + "," + os.Getenv("no_proxy")
	for _, e := range strings.Split(np, ",") {
		e = strings.TrimPrefix(strings.TrimSpace(strings.ToLower(e)), "*")
		if e == "" {
			continue
		}
		for _, h := range interceptHosts {
			if e == "*" || h == strings.TrimPrefix(e, ".") || strings.HasSuffix(h, "."+strings.TrimPrefix(e, ".")) {
				fmt.Fprintf(os.Stderr, "agy-sp: warning: NO_PROXY entry %q bypasses the proxy for %s; the system prompt will not be applied\n", e, h)
				time.Sleep(1500 * time.Millisecond)
				return
			}
		}
	}
}

func withEnv(env []string, set map[string]string) []string {
	out := make([]string, 0, len(env)+len(set))
	for _, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		if _, ok := set[k]; !ok {
			out = append(out, kv)
		}
	}
	for k, v := range set {
		out = append(out, k+"="+v)
	}
	return out
}

func openLog(path string) func(string, ...any) {
	if fi, err := os.Stat(path); err == nil && fi.Size() > 5<<20 {
		os.Rename(path, path+".1")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return func(string, ...any) {}
	}
	pid := os.Getpid()
	return func(format string, a ...any) {
		fmt.Fprintf(f, "%s [%d] %s\n", time.Now().Format(time.RFC3339), pid, fmt.Sprintf(format, a...))
	}
}

// interceptHosts returns the Code Assist hosts plus the Vertex AI host(s).
func interceptHosts(home string) []string {
	hosts := append(slices.Clone(codeAssistHosts), vertexGlobalHost)
	loc := strings.ToLower(strings.TrimSpace(os.Getenv("GOOGLE_CLOUD_LOCATION")))
	if loc == "" {
		var st struct {
			GCP struct {
				Location string `json:"location"`
			} `json:"gcp"`
		}
		if b, err := os.ReadFile(filepath.Join(home, ".gemini", "antigravity-cli", "settings.json")); err == nil {
			json.Unmarshal(b, &st)
		}
		loc = strings.ToLower(strings.TrimSpace(st.GCP.Location))
	}
	if loc != "" && loc != "global" && validRegion(loc) {
		hosts = append(hosts, loc+"-"+vertexGlobalHost)
	}
	return hosts
}

func validRegion(s string) bool {
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return len(s) <= 40
}

func isVertexHost(hostport string) bool {
	h := strings.ToLower(hostport)
	if i := strings.LastIndexByte(h, ':'); i >= 0 {
		h = h[:i]
	}
	return h == vertexGlobalHost || strings.HasSuffix(h, "-"+vertexGlobalHost)
}

// vertexModel extracts the model id from .../publishers/google/models/<id>:method.
func vertexModel(path string) string {
	_, rest, ok := strings.Cut(path, vertexGeminiPath)
	if !ok {
		return ""
	}
	m, _, _ := strings.Cut(rest, ":")
	return m
}

func modelOf(body []byte) string {
	var v struct {
		Model string `json:"model"`
	}
	json.Unmarshal(body, &v)
	return v.Model
}

func toSet(xs []string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

func errOrEmpty(err error) any {
	if err == nil {
		return ""
	}
	return err
}
