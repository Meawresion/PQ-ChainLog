"""Write a copy of upstream's `setup_exp.py` that runs all five tiers.

Their driver hardcodes `cnt = 4`, stopping at the 10^5 tier; plan §7 caps us at
their 10^6 tier, which is index 4.

Patched into a **copy** rather than edited in the submodule, so the pin stays
clean and the change is visible in this repository instead of hidden in a dirty
checkout.

⚠️ The assert is the point. If upstream ever stops saying `cnt = 4`, this must
fail loudly rather than quietly run whichever tiers it now defaults to while the
caller reports them as "up to 10^6".

⭐ Lives in a file rather than inline in `run.sh` because a heredoc nested inside
`docker run ... bash -c '...'` mangled itself, and the symptom was an unrelated
`cnt: command not found` several layers from the cause.
"""

import pathlib
import re

SRC = pathlib.Path("setup_exp.py")

# ⚠️ Written to `/results`, **not** next to the source. The working directory is
# the pinned submodule, and a generated file there shows up as untracked content
# in `git status` — which reads as submodule drift and invites someone to
# "clean up" a pin. `/results` is already the gitignored output mount, and the
# upstream tree stays byte-identical to its commit.
OUT = pathlib.Path("/results/setup_exp_all_tiers.py")

src = SRC.read_text(encoding="utf-8")
patched, n = re.subn(r"^    cnt = 4$", "    cnt = 5", src, flags=re.M)

if n != 1:
    raise SystemExit(
        f"expected exactly one `cnt = 4` in {SRC}, found {n}. "
        "Upstream changed; re-read setup_exp.py before assuming the tiers."
    )

OUT.write_text(patched, encoding="utf-8")
print(f"wrote {OUT} (tiers 0..4)")
