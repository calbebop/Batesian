# Batesian demo tape
# Requirements:
#   - batesian binary in PATH (go install or go build -o bin/batesian ./cmd/batesian)
#   - python testdata/a2a_vulnerable_server.py running on 127.0.0.1:9998
#
# Render:
#   docker run --rm --network host -v "$PWD:/vhs" ghcr.io/charmbracelet/vhs docs/demo.tape
#   (Linux/macOS) or via WSL on Windows

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

# Give the scan time to run all rules and print findings
Sleep 18s

# Hold on the final output so viewers can read it
Sleep 3s
