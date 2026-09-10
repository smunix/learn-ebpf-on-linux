# Intentionally rejected fixture

`unchecked-xdp` is outside the parent workspace because it intentionally omits a `data_end` proof before reading packet bytes. Compile it explicitly with the BPF target, then load it with `bpftool prog load` or a small Aya loader to capture the verifier's invalid-access diagnostic. Compare `../corrected/src/main.rs`, which establishes `data + size_of::<u16>() <= data_end()` first. Loading either fixture requires BPF privileges; dropping/unpinning the program cleans it up. Never make the rejected crate a default workspace member.
