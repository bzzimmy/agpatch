# agy-sp

`agy-sp` wraps the Antigravity CLI (`agy`) so you can put your own system prompt, from a Markdown file, in front of Antigravity's built-in one. The prompt the model receives has two layers:

`````text
<your file, verbatim, no wrapper>

````harness_prompt
<Antigravity's complete built-in prompt, unchanged>
````
`````

The fence is always one backtick longer than the longest backtick run in the built-in text, and never shorter than three, so nothing inside can close it early.

If no prompt file is set, `agy-sp` execs the real `agy` with the same arguments and environment, so behaviour is exactly the same as today.

## Usage

```sh
agy sp set ~/prompts/me.md              # set persistent markdown prompt
agy sp set ~/prompts/me.pcm             # set persistent audio prompt (.pcm/.mp3/.wav/.aiff/...)
agy sp set --audio ~/prompts/me.md      # synthesize verbatim optimized 16kHz PCM from markdown & activate
agy sp status                           # show active prompt
agy sp clear                            # disable custom prompt (run stock agy)

agy-sp --system-prompt-file ~/prompts/me.md            # one-off override (interactive)
agy-sp --system-prompt-file=me.md -p "do the thing"    # one-off override (headless)
```

The prompt file is resolved in this order, first match wins:

1. `--system-prompt-file PATH`. An empty value (`--system-prompt-file=`) turns the prompt off for that run.
2. The `AGY_SYSTEM_PROMPT_FILE` environment variable.
3. `~/.gemini/antigravity-cli/agy-sp.json` containing `{"systemPromptFile": "~/prompts/me.md"}`.

To use it as plain `agy`, add `alias agy=agy-sp` to `~/.zshrc`. With no file configured, the alias changes nothing.

Optional environment variables:

| Variable | Effect |
|---|---|
| `AGY_SP_SCOPE=main` | Apply the prompt only to the main conversation and skip subagents. By default every agent request gets it, subagents included. |
| `AGY_SP_REQUEST_TYPES` | Comma-separated `requestType` values to rewrite. The default is `agent`. Utility calls such as `agent_monitoring` are always left alone unless you list them here. |
| `AGY_SP_DUMP=1` | Write the most recent composed prompt to `~/.gemini/antigravity-cli/agy-sp/last-system-prompt.md` (mode 0600). |
| `AGY_SP_REAL_AGY` | Path to the real `agy`. By default it is the first `agy` on `PATH` that isn't this wrapper. |

## How it works

agy has no setting that can do this (see "Why not something native?" below), so `agy-sp` does it on the wire:

1. It starts a proxy on `127.0.0.1` with a random port and runs `agy` with `HTTPS_PROXY` pointing at it and `SSL_CERT_FILE` pointing at a trust bundle. The bundle is the system roots (or your existing `SSL_CERT_FILE`) plus a local CA.
2. Only Antigravity's model backends are decrypted. For Google sign-in these are `cloudcode-pa.googleapis.com` and `daily-cloudcode-pa.googleapis.com`. For Vertex AI it is `aiplatform.googleapis.com`, plus `<region>-aiplatform.googleapis.com` when `GOOGLE_CLOUD_LOCATION` or `gcp.location` in `settings.json` names a region. Every other connection is relayed as an opaque tunnel.
3. The proxy replaces `systemInstruction` with the layered prompt in `:streamGenerateContent` and `:generateContent` requests that are agent turns:
   - **Google sign-in:** requests with `requestType: "agent"`. Monitoring calls (`agent_monitoring`) are skipped.
   - **Vertex AI, Gemini models only** (`/publishers/google/models/…`): these requests carry no `requestType`, so a request counts as an agent turn when it has `labels.cascade_id` and the built-in prompt opens with `<identity>` (any case, which covers subagents). agy's `gemini-3.5-flash-lite` monitoring call doesn't match, so it is skipped. Claude models on Vertex (`publishers/anthropic`) are never touched.

   In both cases, every other byte of the request is left exactly as it was: contents, tools, labels, generation config, headers, and the chunked transfer encoding. Responses stream straight back without buffering.
4. If a request has an unexpected shape, it is forwarded unchanged and the skip is logged.

The local CA is in `~/.gemini/antigravity-cli/agy-sp/`. Its key is mode 0600. It has critical X.509 name constraints, so it can only sign certificates for the hosts above, and even a leaked key can't impersonate any other site. Nothing is added to your keychain.

The log is `~/.gemini/antigravity-cli/agy-sp/agy-sp.log`. It records one line per model request: rewritten or skipped, the reason, sizes, and the HTTP status. It never records prompt content.

### Why not something native?

The alternatives were checked against agy 1.5.15:

- **Rules (`GEMINI.md`, `AGENTS.md`) and hooks.** Rules are inserted into the middle of the built-in prompt. Hooks can only add conversation messages.
- **Custom agents (`.agents/agents/*.md` with `--agent`).** The body is wrapped in `<System Prompt>` tags and replaces `identity`, `conversation_transcript`, `work_efficiently`, `slash_commands` and `subagents`, and the toolset shrinks. With `excludeDefaultComponents: true`, only the body is sent.
- **`PromptSectionCustomizationConfig`.** This internal add/replace/remove-section system can't be reached from local config, and it renders every section as `<title>…</title>`.
- **Enterprise gateway mode (`AGY_LLM_GATEWAY_URL`).** It works, but it drops your Google sign-in, so you would need a Vertex or API-key backend.
- **Patching the binary.** The binary is a signed, hardened-runtime 229 MB Go executable that auto-updates. A patch would need hand-written ARM64 code, re-signing, and redoing after every update.

## Caveats

- Shell commands run by the agent inherit `HTTPS_PROXY` and `SSL_CERT_FILE`. Their traffic still reaches its destination through the tunnel, and the bundle contains the normal system roots.
- `--remote-agent` sessions build their prompt on Google's side, so the rewrite doesn't apply to them. Subcommands that never run a model session (`mcp`, `plugin`, `update`, `remote-control`, `models`, and so on) bypass the proxy entirely.
- The backend is known to reject some system-prompt content with a 429 that isn't really a rate limit. If you see 429s only with your prompt file, check the log and reword the prompt.
- On Vertex, custom agents (`--agent`) don't get the prompt, because their built-in prompt opens with `<System Prompt>` rather than `<identity>`. With Google sign-in they do.
- Sessions on Claude models via Vertex don't get the prompt.
- This relies on the request formats of Google's internal `v1internal` API and Vertex's `generateContent`. If a future agy release changes it, the proxy falls back to forwarding requests unchanged, and the log will show `skip` lines instead of `rewrote`.

## Build and test

```sh
go test -race ./...
go build -o bin/agy-sp . && cp bin/agy-sp ~/.local/bin/
```
