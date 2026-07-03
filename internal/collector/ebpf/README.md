# eBPF collector

This package is intentionally `cilium/ebpf` only. It does not read `/proc`.

Current attach support:

- `tracepoint/<category>/<name>`
- `kprobe/<symbol>`
- `kretprobe/<symbol>`

Object files may also contain `classifier/...` TC programs. They are loaded by
the kernel collection but skipped by the generic auto-attacher because TC needs
an interface and ingress/egress attach direction. Add that through explicit CLI
options rather than guessing.

Ring buffers whose map name contains `events` are consumed and exposed as raw
hex events through the in-memory event store. Typed decoding should be added per
module as BPF programs become stable.
