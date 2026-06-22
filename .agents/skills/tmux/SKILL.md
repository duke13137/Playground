---
name: tmux
description: Control tmux panes and communicate between AI agents. Use this skill whenever the user mentions tmux panes, cross-pane communication, sending messages, reading panes, managing sessions, or interacting with processes running in tmux. Includes a bundled tmux-bridge script for agent-to-agent messaging and raw tmux commands for direct session control.
metadata:
  {
    "openclaw":
      {
        "emoji": "🖥️",
        "os": ["darwin", "linux"],
        "requires": { "bins": ["tmux"] },
      },
  }
---

# Tmux SKILL for pane control and cross-pane agent communication.

## Command Setup

Do not assume `tmux-bridge` is installed in `PATH`. This skill bundles it in
`scripts/tmux-bridge`; add the skill's `scripts/` directory to `PATH` before
using `tmux-bridge`.

```bash
TMUX_SKILL_DIR="${TMUX_SKILL_DIR:-$HOME/.config/agents/skills/tmux}"
export PATH="$TMUX_SKILL_DIR/scripts:$PATH"
tmux-bridge doctor
```

After the `PATH` export, `tmux-bridge` resolves to the bundled helper when it is
not otherwise installed. The bundled helper scripts are:

```text
scripts/tmux-bridge
scripts/find-sessions.sh
scripts/wait-for-text.sh
```

Always use the tmux server socket reported by `tmux display-message -p -F '#{socket_path}'`. Do not synthesize a private fallback socket. The same socket variables are used by raw
tmux commands and by `tmux-bridge`:

```bash
SOCKET="$(tmux display-message -p -F '#{socket_path}' 2>/dev/null)"
export TMUX_BRIDGE_SOCKET="${TMUX_BRIDGE_SOCKET:-$SOCKET}"
tmux-bridge doctor
```

## Reference Map

Read only the reference that matches the task:

- For cross-pane agent messaging, labels, read guards, and `TMUX_BRIDGE_SOCKET`,
  read `references/tmux-bridge.md`.
- For raw tmux sessions, monitoring, and cleanup, use the Raw Tmux Workflow
  section below.

## Core Workflow

1. Run the command setup above so the bundled scripts are in `PATH`.
2. Discover panes before targeting: `tmux-bridge list`, `tmux list-windows -t SESSION`, or `tmux list-panes -a -t SESSION`.
3. Prefer stable pane IDs like `%3` or bridge labels over assuming pane indexes.
4. Use `tmux-bridge` for cross-pane interaction. It enforces read-before-act:
   `read`, then `type` or `keys`; after each action, read again before the next action.
5. Use raw tmux commands only for session/window/pane management or low-level process control.

## Cross-Pane Messaging

Use `tmux-bridge message` only when the sender process is itself inside tmux,
because it reads `$TMUX_PANE` to build the reply header. When the sender is
outside tmux, use `type`, verify with `read`, then submit with `keys Enter`:

```bash
tmux-bridge read codex 20
tmux-bridge type codex '[tmux-bridge from:codex] Please review src/auth.ts'
tmux-bridge read codex 20
tmux-bridge keys codex Enter
```

For the full message workflow and examples, read `references/tmux-bridge.md`.

## Raw Tmux Workflow

Use raw tmux when you need session/window/pane management or low-level control.
Keep the socket explicit so every command targets the same server. Use the live
tmux server socket reported by `tmux display-message -p -F '#{socket_path}'` and reuse it
for `tmux-bridge` when you want bridge commands to reach the same panes.

```bash
SOCKET="$(tmux display-message -p -F '#{socket_path}' 2>/dev/null)"
export TMUX_BRIDGE_SOCKET="${TMUX_BRIDGE_SOCKET:-$SOCKET}"

SESSION=claude-python
tmux -S "$SOCKET" new -d -s "$SESSION" -n shell
tmux -S "$SOCKET" send-keys -t "$SESSION":1.1 -- 'python3 -q' Enter
tmux -S "$SOCKET" capture-pane -p -J -t "$SESSION":1.1 -S -200
tmux -S "$SOCKET" kill-session -t "$SESSION"
```

If you need user config, drop `-f /dev/null`; otherwise keep it clean.

### Targeting And Discovery

- Prefer explicit targets like `SESSION:1.1` or pane IDs from
  `tmux -S "$SOCKET" list-panes -a`.
- Avoid assuming `0`-based indexes. This user's tmux config uses `base-index 1`
  and `pane-base-index 1`.
- Inspect with `tmux -S "$SOCKET" list-sessions`, `tmux -S "$SOCKET" list-panes -a`,
  or `./scripts/find-sessions.sh -S "$SOCKET"`.

### Sending Input Safely

- Prefer literal sends: `tmux -S "$SOCKET" send-keys -t target -l -- "$cmd"`
- For inline commands, use single quotes or ANSI C quoting to avoid expansion.
- Send control keys with `C-c`, `C-d`, `C-z`, `Escape`, or `Enter` as needed.

### Watching Output

- Capture recent history with `tmux -S "$SOCKET" capture-pane -p -J -t target -S -200`.
- For prompt synchronization, use `./scripts/wait-for-text.sh -t target -p 'pattern'`.
- Temporarily attach with `tmux -S "$SOCKET" attach -t "$SESSION"` and detach with `Ctrl+b d`.

### Interactive Recipes

- Python REPL: set `PYTHON_BASIC_REPL=1`, start `python3 -q`, wait for `^>>>`, then send code with `-l`.
- gdb: start `gdb --quiet ./a.out`, run `set pagination off`, and use `C-c` to interrupt.
- Other TTY apps such as `ipdb`, `psql`, `mysql`, `node`, and `bash` follow the same pattern.
- When asked to debug, use `lldb` by default.

### Cleanup

- Kill a session with `tmux -S "$SOCKET" kill-session -t "$SESSION"`.
- Kill all sessions on a socket with `tmux -S "$SOCKET" list-sessions -F '#{session_name}' | xargs -r -n1 tmux -S "$SOCKET" kill-session -t`.
- Remove everything on the socket with `tmux -S "$SOCKET" kill-server`.

## Tips

- **Read guard is enforced** — you MUST read before every `type`/`keys`
- **Every action clears the read mark** — after `type`, read again before `keys`
- **Never wait or poll** — agent panes reply via tmux-bridge into YOUR pane
- **Label panes early** — easier than using `%N` IDs. Bridge labels are stored
  in tmux pane option `@name`; they are distinct from tmux pane titles such as
  `#{pane_title}`. They appear in `tmux-bridge list` and `resolve`, but only
  appear in the tmux UI if pane/status formatting renders `#{@name}`.
- **`type` uses literal mode** — special characters are typed as-is
- **`read` defaults to 50 lines** — pass a higher number for more context
- **Non-agent panes** are the exception — you DO need to read them to see output
- Use `capture-pane -p` to print to stdout (essential for scripting)
- Target format: `session:window.pane` (e.g., `shared:1.1` in 1-indexed tmux configs)
