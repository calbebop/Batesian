# Batesian demo tape
# Render from the repo root on Linux or macOS:
#   pip install starlette uvicorn httpx
#   python testdata/a2a_vulnerable_server.py &
#   go install ./cmd/batesian
#   vhs docs/demo.tape

Output docs/demo.gif

Set Shell "bash"
Set FontSize 13
Set Width 110
Set Height 32
Set Theme "Dracula"
Set Padding 16
Set PlaybackSpeed 1.0
Set TypingSpeed 40ms

# --- intro: show what the tool is ---
Sleep 500ms
Type "batesian --version"
Enter
Sleep 1.5s

# --- probe: map the attack surface ---
Sleep 300ms
Type "batesian probe --target http://127.0.0.1:9998 --protocol a2a"
Enter
Sleep 6s

# --- scan: active exploit engine ---
Sleep 500ms
Type "batesian scan --target http://127.0.0.1:9998 --protocol a2a --timeout 20"
Enter
Sleep 20s

# Hold on final output so viewers can read findings
Sleep 3s
