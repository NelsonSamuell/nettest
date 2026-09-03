#!/bin/sh
# One time setup. Run this once, then use ./bin/l2check (or just l2check).
# Safe to run again: it skips anything already done.
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
VENV="$HERE/.venv"
LINK="$HOME/.local/bin/l2check"

say() { printf '%s\n' "$*"; }

# 1. A private virtual environment.
#
# --copies gives this environment its own python binary rather than a symlink to
# the system one. That matters for step 3: the capability is granted to this one
# copy, so l2check can read frames and no other python on the machine can.
#
# --system-site-packages reuses scapy and pyyaml if they are already installed,
# so setup works without downloading anything.
if [ -x "$VENV/bin/python3" ]; then
    say "virtual environment already present at $VENV"
else
    say "creating a virtual environment in $VENV"
    python3 -m venv --copies --system-site-packages "$VENV"
fi

# 2. Install l2check into it, editable so edits to the source take effect at once.
say "installing l2check"
"$VENV/bin/pip" install -e "$HERE" --quiet --no-build-isolation

# 3. Permission to read frames.
#
# Reading raw frames needs CAP_NET_RAW. Granting it to this environment's python
# is much narrower than running the whole tool as root, and narrower than
# granting it to the system python, which would give every python script on the
# machine the same access.
NEEDED="cap_net_raw,cap_net_admin+eip"
if getcap "$VENV/bin/python3" 2>/dev/null | grep -q cap_net_raw; then
    say "frame access already granted"
elif ! command -v setcap >/dev/null 2>&1; then
    say "setcap not found. Install it with: sudo apt install libcap2-bin"
    say "then run this script again."
elif sudo setcap "$NEEDED" "$VENV/bin/python3"; then
    say "frame access granted"
else
    # Not fatal: the rest of the setup is still worth finishing, and the tool
    # says clearly what is missing when a capture is attempted.
    say ""
    say "could not grant frame access. Finish that step yourself with:"
    say "  sudo setcap $NEEDED $VENV/bin/python3"
fi

# 4. A launcher on PATH, so the tool works from any directory.
if [ -e "$LINK" ] || [ -L "$LINK" ]; then
    say "launcher already at $LINK"
else
    mkdir -p "$HOME/.local/bin"
    ln -s "$HERE/bin/l2check" "$LINK"
    say "linked $LINK"
fi

say ""
say "Setup done. Check it worked:"
case ":$PATH:" in
    *":$HOME/.local/bin:"*) say "  l2check doctor" ;;
    *) say "  $HERE/bin/l2check doctor"
       say ""
       say "($HOME/.local/bin is not on your PATH, so use the full path above,"
       say " or add it with: echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.bashrc)" ;;
esac
