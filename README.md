# netdoctor

netdoctor is an eBPF-first Linux network diagnostics toolkit written in Go.

The project is intentionally built on [`github.com/cilium/ebpf`](https://github.com/cilium/ebpf). It does not use `/proc` collectors. The first milestone is a clean, modular runtime that can load eBPF objects, attach supported programs, stream events, expose a CLI, and optionally serve a Web UI.

## Goals

- Diagnose TCP, UDP, ARP, ICMP, routing, drop, retransmit, reset, latency, and socket-level network issues.
- Attribute network behavior to processes, cgroups, namespaces, containers, interfaces, and remote endpoints through eBPF events.
- Provide a command-line workflow for live troubleshooting.
- Provide an optional local Web UI and JSON API for inspection.
- Keep modules independent so TCP, UDP, ICMP, ARP, drop tracing, process attribution, and container attribution can evolve separately.

## Current structure

```text
cmd/netdoctor                 CLI entrypoint
internal/collector/ebpf       cilium/ebpf loader, attach logic, ringbuf event ingestion
internal/doctor               runtime service and snapshot aggregation
internal/model                shared API and event models
internal/web                  optional Web UI and JSON API
bpf                           BPF C program templates for bpf2go
```

## Commands

```bash
go run ./cmd/netdoctor probe
go run ./cmd/netdoctor probe -object ./netdoctor_bpfel.o
go run ./cmd/netdoctor run -object ./netdoctor_bpfel.o
go run ./cmd/netdoctor serve -addr 127.0.0.1:8080 -object ./netdoctor_bpfel.o
```

The same workflows are available through `make`:

```bash
make test
make test-linux
make build
make probe
make run OBJECT=./netdoctor_bpfel.o
make serve ADDR=127.0.0.1:8080 OBJECT=./netdoctor_bpfel.o
```

`probe` checks whether the current Linux host can create eBPF maps with `cilium/ebpf`. With `-object`, it also tries to load and attach the object.

Supported attach sections now:

- `tracepoint/<category>/<name>`
- `kprobe/<symbol>`
- `kretprobe/<symbol>`

Maps whose name contains `events` are read as ring buffers and exposed as raw events through:

- `GET /api/snapshot`
- `GET /api/events`

## BPF program workflow

The starter BPF file is [bpf/netdoctor.bpf.c](./bpf/netdoctor.bpf.c).

It is organized as protocol modules:

- TCP state: `tracepoint/sock/inet_sock_set_state`, records state transitions and time spent in the previous state.
- TCP connect latency: `kprobe/tcp_v4_connect`, `kprobe/tcp_v6_connect`, return probes, and `kprobe/tcp_rcv_state_process`, records successful and failed active connects.
- TCP quality events: `kprobe/tcp_retransmit_skb` and `kprobe/tcp_send_active_reset`, records retransmit/reset signals with cwnd, ssthresh, SRTT, RTO, and total retransmits.
- UDP activity: `kprobe/udp_sendmsg`, `kprobe/udpv6_sendmsg`, `kprobe/udp_recvmsg`, and `kprobe/udpv6_recvmsg`.
- ICMP activity: `kprobe/icmp_send` and `kprobe/icmpv6_send`.
- Packet parser: `classifier/netdoctor_ingress` and `classifier/netdoctor_egress`, parses Ethernet, VLAN, ARP, IPv4, IPv6, TCP, UDP, ICMP, and ICMPv6 packet metadata.

All modules write a shared `struct event` to the `events` ring buffer. The event includes PID/TGID, command name, socket pointer, address family, IPv4/IPv6 endpoints, ports, protocol, direction, TCP states, connect latency, TCP quality fields, ICMP type/code, interface index, and packet size. Runtime knobs live in the `config` map, with PID and port filters in `filter_pids` and `filter_ports`.

Typical generation flow on Linux:

```bash
make bpf-vmlinux
make bpf
```

`make bpf` passes `-D__TARGET_ARCH_<arch>` for libbpf tracing macros. The default is detected from `uname -m`; override it when cross-building:

```bash
make bpf BPF_ARCH=x86
make bpf BPF_ARCH=arm64
```

The current loader can also consume a compiled object path directly, so modules can be developed independently before generated Go wrappers are committed.

## Roadmap

### v0.1

- eBPF runtime, loader, lifecycle, Web UI, JSON API.
- TCP state event stream from `sock/inet_sock_set_state`.
- Interface-oriented ingress/egress event modules through XDP or tc attach paths.
- Basic process attribution from eBPF event payloads.

### v0.2

- TCP connect latency, RTT, retransmit, reset, queue pressure, and socket quality.
- UDP send/receive/error event attribution.
- Network top mode grouped by process, socket, remote endpoint, and protocol.
- Snapshot compare and report output.

### v0.3

- Drop tracing across NIC, tc, XDP, routing, firewall, and socket layers.
- Kernel network stack health, softirq pressure, queue pressure, and offload visibility.
- nftables/iptables and conntrack/NAT modules through eBPF-capable hooks where possible.

### v0.4

- Container and Kubernetes attribution by cgroup and namespace.
- Historical storage, Prometheus exporter, richer HTTP API.
- Production packaging and permission profiles for root/capability/eBPF mode.
