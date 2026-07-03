// SPDX-License-Identifier: GPL-2.0
//
// netdoctor kernel-side probes.
//
// This file is deliberately split into protocol-oriented sections so the Go
// side can enable, attach, and decode modules independently as the project
// grows. It follows the tcpconnlat/tcpstates style: kprobes for active TCP
// connect latency, tracepoint/sock/inet_sock_set_state for TCP state changes,
// and protocol-specific probes for retransmit, reset, UDP, ICMP, plus TC packet
// classifiers for Ethernet/IP/ARP packet visibility.
//
// Generate bindings on Linux:
//   make bpf-vmlinux
//   make bpf

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif

#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP 1
#endif
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif
#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6 58
#endif

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif
#ifndef ETH_P_ARP
#define ETH_P_ARP 0x0806
#endif
#ifndef ETH_P_8021Q
#define ETH_P_8021Q 0x8100
#endif
#ifndef ETH_P_8021AD
#define ETH_P_8021AD 0x88A8
#endif
#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif

#ifndef TC_ACT_OK
#define TC_ACT_OK 0
#endif

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

#ifndef TCP_ESTABLISHED
#define TCP_ESTABLISHED 1
#define TCP_SYN_SENT 2
#define TCP_SYN_RECV 3
#define TCP_FIN_WAIT1 4
#define TCP_FIN_WAIT2 5
#define TCP_TIME_WAIT 6
#define TCP_CLOSE 7
#define TCP_CLOSE_WAIT 8
#define TCP_LAST_ACK 9
#define TCP_LISTEN 10
#define TCP_CLOSING 11
#define TCP_NEW_SYN_RECV 12
#endif

#define ND_MAX_ENTRIES 65536
#define ND_RINGBUF_SIZE (1 << 24)

enum nd_module {
	ND_MODULE_TCP_STATE = 1U << 0,
	ND_MODULE_TCP_CONNLAT = 1U << 1,
	ND_MODULE_TCP_RETRANS = 1U << 2,
	ND_MODULE_TCP_RESET = 1U << 3,
	ND_MODULE_UDP = 1U << 4,
	ND_MODULE_ICMP = 1U << 5,
	ND_MODULE_PACKET = 1U << 6,
};

enum nd_event_type {
	ND_EVENT_TCP_STATE = 1,
	ND_EVENT_TCP_CONNECT = 2,
	ND_EVENT_TCP_CONNECT_FAIL = 3,
	ND_EVENT_TCP_RETRANS = 4,
	ND_EVENT_TCP_RESET = 5,
	ND_EVENT_UDP_SEND = 6,
	ND_EVENT_UDP_RECV = 7,
	ND_EVENT_ICMP_SEND = 8,
	ND_EVENT_PACKET = 9,
	ND_EVENT_ARP_PACKET = 10,
};

enum nd_direction {
	ND_DIR_UNKNOWN = 0,
	ND_DIR_INGRESS = 1,
	ND_DIR_EGRESS = 2,
};

struct nd_config {
	__u64 disabled_modules;
	__u64 min_connect_us;
	__u32 filter_by_pid;
	__u32 filter_by_port;
	__u32 sample_packets;
	__u32 reserved;
};

struct connect_start {
	__u64 ts_ns;
	__u32 pid;
	__u32 tgid;
	char comm[TASK_COMM_LEN];
};

struct event {
	__u64 ts_ns;
	__u64 skaddr;
	__u64 duration_us;
	__u64 bytes;
	__u64 packets;

	__u32 pid;
	__u32 tgid;
	__u32 ifindex;
	__s32 ret;

	__u32 saddr_v4;
	__u32 daddr_v4;
	__u32 saddr_v6[4];
	__u32 daddr_v6[4];

	__u32 snd_cwnd;
	__u32 snd_ssthresh;
	__u32 srtt_us;
	__u32 rto_us;
	__u32 retransmits;

	__u16 sport;
	__u16 dport;
	__u16 family;
	__u16 eth_proto;

	__u8 type;
	__u8 protocol;
	__u8 direction;
	__u8 old_state;
	__u8 new_state;
	__u8 tcp_flags;
	__u8 icmp_type;
	__u8 icmp_code;

	char comm[TASK_COMM_LEN];
};

struct nd_ethhdr {
	__u8 dst[6];
	__u8 src[6];
	__be16 proto;
};

struct nd_vlanhdr {
	__be16 tci;
	__be16 encap_proto;
};

struct nd_iphdr {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	__u8 ihl : 4;
	__u8 version : 4;
#else
	__u8 version : 4;
	__u8 ihl : 4;
#endif
	__u8 tos;
	__be16 tot_len;
	__be16 id;
	__be16 frag_off;
	__u8 ttl;
	__u8 protocol;
	__sum16 check;
	__be32 saddr;
	__be32 daddr;
};

struct nd_ipv6hdr {
	__be32 flow_lbl;
	__be16 payload_len;
	__u8 nexthdr;
	__u8 hop_limit;
	__u8 saddr[16];
	__u8 daddr[16];
};

struct nd_ports {
	__be16 sport;
	__be16 dport;
};

struct nd_icmphdr {
	__u8 type;
	__u8 code;
	__sum16 checksum;
};

struct nd_arphdr {
	__be16 htype;
	__be16 ptype;
	__u8 hlen;
	__u8 plen;
	__be16 oper;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, ND_RINGBUF_SIZE);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct nd_config);
} nd_config SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, ND_MAX_ENTRIES);
	__type(key, struct sock *);
	__type(value, struct connect_start);
} tcp_connect_start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, ND_MAX_ENTRIES);
	__type(key, __u64);
	__type(value, __u64);
} active_connect_by_tid SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, ND_MAX_ENTRIES);
	__type(key, struct sock *);
	__type(value, __u64);
} tcp_state_ts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, __u8);
} filter_pids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u16);
	__type(value, __u8);
} filter_ports SEC(".maps");

static __always_inline struct nd_config *get_config(void)
{
	__u32 key = 0;
	return bpf_map_lookup_elem(&nd_config, &key);
}

static __always_inline bool module_enabled(__u64 module)
{
	struct nd_config *cfg = get_config();

	if (!cfg)
		return true;
	return !(cfg->disabled_modules & module);
}

static __always_inline bool allow_pid(__u32 pid)
{
	struct nd_config *cfg = get_config();
	__u8 *ok;

	if (!cfg || !cfg->filter_by_pid)
		return true;
	ok = bpf_map_lookup_elem(&filter_pids, &pid);
	return ok != 0;
}

static __always_inline bool allow_port(__u16 sport, __u16 dport)
{
	struct nd_config *cfg = get_config();
	__u8 *ok;

	if (!cfg || !cfg->filter_by_port)
		return true;
	ok = bpf_map_lookup_elem(&filter_ports, &sport);
	if (ok)
		return true;
	ok = bpf_map_lookup_elem(&filter_ports, &dport);
	return ok != 0;
}

static __always_inline void fill_process(struct event *event)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	event->pid = pid_tgid >> 32;
	event->tgid = (__u32)pid_tgid;
	bpf_get_current_comm(event->comm, sizeof(event->comm));
}

static __always_inline void fill_tuple_from_sock(struct event *event, struct sock *sk)
{
	__u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
	__u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);
	__be16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);

	event->skaddr = (__u64)sk;
	event->family = family;
	event->sport = sport;
	event->dport = bpf_ntohs(dport);

	if (family == AF_INET) {
		event->saddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
		event->daddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);
	} else if (family == AF_INET6) {
		bpf_probe_read_kernel(event->saddr_v6, sizeof(event->saddr_v6),
				      &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		bpf_probe_read_kernel(event->daddr_v6, sizeof(event->daddr_v6),
				      &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
	}
}

static __always_inline void fill_tcp_quality(struct event *event, struct sock *sk)
{
	struct tcp_sock *tp = (struct tcp_sock *)sk;
	struct inet_connection_sock *icsk = (struct inet_connection_sock *)sk;
	__u32 srtt = 0;
	__u32 rto = 0;

	event->snd_cwnd = BPF_CORE_READ(tp, snd_cwnd);
	event->snd_ssthresh = BPF_CORE_READ(tp, snd_ssthresh);
	event->retransmits = BPF_CORE_READ(tp, total_retrans);

	srtt = BPF_CORE_READ(tp, srtt_us);
	rto = BPF_CORE_READ(icsk, icsk_rto);
	event->srtt_us = srtt >> 3;
	event->rto_us = rto;
}

static __always_inline bool submit_sock_event(__u8 type, __u8 protocol, struct sock *sk)
{
	struct event *event;

	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event)
		return false;

	__builtin_memset(event, 0, sizeof(*event));
	event->ts_ns = bpf_ktime_get_ns();
	event->type = type;
	event->protocol = protocol;
	fill_process(event);
	fill_tuple_from_sock(event, sk);
	if (protocol == IPPROTO_TCP)
		fill_tcp_quality(event, sk);

	if (!allow_pid(event->pid) || !allow_port(event->sport, event->dport)) {
		bpf_ringbuf_discard(event, 0);
		return false;
	}

	bpf_ringbuf_submit(event, 0);
	return true;
}

static __always_inline void submit_connect_event(__u8 type, struct sock *sk,
						 struct connect_start *start,
						 __s32 ret)
{
	struct nd_config *cfg;
	struct event *event;
	__u64 now = bpf_ktime_get_ns();
	__u64 duration_us = 0;

	if (start)
		duration_us = (now - start->ts_ns) / 1000;

	cfg = get_config();
	if (cfg && type == ND_EVENT_TCP_CONNECT &&
	    cfg->min_connect_us && duration_us < cfg->min_connect_us)
		return;

	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event)
		return;

	__builtin_memset(event, 0, sizeof(*event));
	event->ts_ns = now;
	event->type = type;
	event->protocol = IPPROTO_TCP;
	event->duration_us = duration_us;
	event->ret = ret;
	if (start) {
		event->pid = start->pid;
		event->tgid = start->tgid;
		__builtin_memcpy(event->comm, start->comm, sizeof(event->comm));
	} else {
		fill_process(event);
	}
	fill_tuple_from_sock(event, sk);
	fill_tcp_quality(event, sk);

	if (!allow_pid(event->pid) || !allow_port(event->sport, event->dport)) {
		bpf_ringbuf_discard(event, 0);
		return;
	}

	bpf_ringbuf_submit(event, 0);
}

static __always_inline int trace_tcp_connect_start(struct sock *sk)
{
	struct connect_start start = {};
	__u64 pid_tgid;
	__u64 skaddr = (__u64)sk;

	if (!module_enabled(ND_MODULE_TCP_CONNLAT))
		return 0;

	pid_tgid = bpf_get_current_pid_tgid();
	start.ts_ns = bpf_ktime_get_ns();
	start.pid = pid_tgid >> 32;
	start.tgid = (__u32)pid_tgid;
	bpf_get_current_comm(start.comm, sizeof(start.comm));

	if (!allow_pid(start.pid))
		return 0;

	bpf_map_update_elem(&tcp_connect_start, &sk, &start, BPF_ANY);
	bpf_map_update_elem(&active_connect_by_tid, &pid_tgid, &skaddr, BPF_ANY);
	return 0;
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(netdoctor_tcp_v4_connect, struct sock *sk)
{
	return trace_tcp_connect_start(sk);
}

SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(netdoctor_tcp_v6_connect, struct sock *sk)
{
	return trace_tcp_connect_start(sk);
}

static __always_inline int trace_tcp_connect_return(__s32 ret)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct connect_start *start;
	__u64 *skaddr;
	struct sock *sk;

	if (!module_enabled(ND_MODULE_TCP_CONNLAT))
		return 0;

	skaddr = bpf_map_lookup_elem(&active_connect_by_tid, &pid_tgid);
	if (!skaddr)
		return 0;
	sk = (struct sock *)*skaddr;
	bpf_map_delete_elem(&active_connect_by_tid, &pid_tgid);

	if (ret == 0)
		return 0;

	start = bpf_map_lookup_elem(&tcp_connect_start, &sk);
	submit_connect_event(ND_EVENT_TCP_CONNECT_FAIL, sk, start, ret);
	bpf_map_delete_elem(&tcp_connect_start, &sk);
	return 0;
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(netdoctor_tcp_v4_connect_ret, int ret)
{
	return trace_tcp_connect_return(ret);
}

SEC("kretprobe/tcp_v6_connect")
int BPF_KRETPROBE(netdoctor_tcp_v6_connect_ret, int ret)
{
	return trace_tcp_connect_return(ret);
}

SEC("kprobe/tcp_rcv_state_process")
int BPF_KPROBE(netdoctor_tcp_rcv_state_process, struct sock *sk)
{
	struct connect_start *start;
	__u8 state;

	if (!module_enabled(ND_MODULE_TCP_CONNLAT))
		return 0;

	state = BPF_CORE_READ(sk, __sk_common.skc_state);
	if (state != TCP_SYN_SENT)
		return 0;

	start = bpf_map_lookup_elem(&tcp_connect_start, &sk);
	if (!start)
		return 0;

	submit_connect_event(ND_EVENT_TCP_CONNECT, sk, start, 0);
	bpf_map_delete_elem(&tcp_connect_start, &sk);
	return 0;
}

SEC("tracepoint/sock/inet_sock_set_state")
int netdoctor_tcp_set_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
	struct sock *sk = (struct sock *)ctx->skaddr;
	struct event *event;
	__u64 *last_ts;
	__u64 now;

	if (!module_enabled(ND_MODULE_TCP_STATE))
		return 0;
	if (ctx->protocol != IPPROTO_TCP)
		return 0;

	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event)
		return 0;

	__builtin_memset(event, 0, sizeof(*event));
	now = bpf_ktime_get_ns();
	last_ts = bpf_map_lookup_elem(&tcp_state_ts, &sk);

	event->ts_ns = now;
	event->type = ND_EVENT_TCP_STATE;
	event->protocol = IPPROTO_TCP;
	event->old_state = ctx->oldstate;
	event->new_state = ctx->newstate;
	if (last_ts)
		event->duration_us = (now - *last_ts) / 1000;
	fill_process(event);
	fill_tuple_from_sock(event, sk);
	fill_tcp_quality(event, sk);

	if (!allow_pid(event->pid) || !allow_port(event->sport, event->dport)) {
		bpf_ringbuf_discard(event, 0);
		return 0;
	}

	bpf_ringbuf_submit(event, 0);

	if (ctx->newstate == TCP_CLOSE)
		bpf_map_delete_elem(&tcp_state_ts, &sk);
	else
		bpf_map_update_elem(&tcp_state_ts, &sk, &now, BPF_ANY);

	return 0;
}

SEC("kprobe/tcp_retransmit_skb")
int BPF_KPROBE(netdoctor_tcp_retransmit_skb, struct sock *sk)
{
	if (!module_enabled(ND_MODULE_TCP_RETRANS))
		return 0;
	submit_sock_event(ND_EVENT_TCP_RETRANS, IPPROTO_TCP, sk);
	return 0;
}

SEC("kprobe/tcp_send_active_reset")
int BPF_KPROBE(netdoctor_tcp_send_active_reset, struct sock *sk)
{
	if (!module_enabled(ND_MODULE_TCP_RESET))
		return 0;
	submit_sock_event(ND_EVENT_TCP_RESET, IPPROTO_TCP, sk);
	return 0;
}

static __always_inline int trace_udp(struct sock *sk, __u64 len, __u8 type)
{
	struct event *event;

	if (!module_enabled(ND_MODULE_UDP))
		return 0;

	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event)
		return 0;

	__builtin_memset(event, 0, sizeof(*event));
	event->ts_ns = bpf_ktime_get_ns();
	event->type = type;
	event->protocol = IPPROTO_UDP;
	event->bytes = len;
	event->direction = type == ND_EVENT_UDP_SEND ? ND_DIR_EGRESS : ND_DIR_INGRESS;
	fill_process(event);
	fill_tuple_from_sock(event, sk);

	if (!allow_pid(event->pid) || !allow_port(event->sport, event->dport)) {
		bpf_ringbuf_discard(event, 0);
		return 0;
	}

	bpf_ringbuf_submit(event, 0);
	return 0;
}

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(netdoctor_udp_sendmsg, struct sock *sk, struct msghdr *msg, unsigned long len)
{
	return trace_udp(sk, len, ND_EVENT_UDP_SEND);
}

SEC("kprobe/udpv6_sendmsg")
int BPF_KPROBE(netdoctor_udpv6_sendmsg, struct sock *sk, struct msghdr *msg, unsigned long len)
{
	return trace_udp(sk, len, ND_EVENT_UDP_SEND);
}

SEC("kprobe/udp_recvmsg")
int BPF_KPROBE(netdoctor_udp_recvmsg, struct sock *sk, struct msghdr *msg, unsigned long len)
{
	return trace_udp(sk, len, ND_EVENT_UDP_RECV);
}

SEC("kprobe/udpv6_recvmsg")
int BPF_KPROBE(netdoctor_udpv6_recvmsg, struct sock *sk, struct msghdr *msg, unsigned long len)
{
	return trace_udp(sk, len, ND_EVENT_UDP_RECV);
}

SEC("kprobe/icmp_send")
int BPF_KPROBE(netdoctor_icmp_send, struct sk_buff *skb, int type, int code)
{
	struct event *event;

	if (!module_enabled(ND_MODULE_ICMP))
		return 0;

	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event)
		return 0;

	__builtin_memset(event, 0, sizeof(*event));
	event->ts_ns = bpf_ktime_get_ns();
	event->type = ND_EVENT_ICMP_SEND;
	event->protocol = IPPROTO_ICMP;
	event->direction = ND_DIR_EGRESS;
	event->icmp_type = type;
	event->icmp_code = code;
	fill_process(event);
	bpf_ringbuf_submit(event, 0);
	return 0;
}

SEC("kprobe/icmpv6_send")
int BPF_KPROBE(netdoctor_icmpv6_send, struct sk_buff *skb, int type, int code)
{
	struct event *event;

	if (!module_enabled(ND_MODULE_ICMP))
		return 0;

	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event)
		return 0;

	__builtin_memset(event, 0, sizeof(*event));
	event->ts_ns = bpf_ktime_get_ns();
	event->type = ND_EVENT_ICMP_SEND;
	event->protocol = IPPROTO_ICMPV6;
	event->direction = ND_DIR_EGRESS;
	event->icmp_type = type;
	event->icmp_code = code;
	fill_process(event);
	bpf_ringbuf_submit(event, 0);
	return 0;
}

static __always_inline int submit_packet_event(struct __sk_buff *skb, __u8 direction)
{
	struct nd_ethhdr eth;
	struct nd_vlanhdr vlan;
	struct event *event;
	__u16 eth_proto;
	__u32 off = sizeof(eth);
	__u8 protocol = 0;
	__u16 sport = 0;
	__u16 dport = 0;
	__u8 icmp_type = 0;
	__u8 icmp_code = 0;
	__u32 saddr_v4 = 0;
	__u32 daddr_v4 = 0;
	__u32 saddr_v6[4] = {};
	__u32 daddr_v6[4] = {};
	__u8 event_type = ND_EVENT_PACKET;

	if (!module_enabled(ND_MODULE_PACKET))
		return TC_ACT_OK;
	if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)) < 0)
		return TC_ACT_OK;

	eth_proto = bpf_ntohs(eth.proto);
	if (eth_proto == ETH_P_8021Q || eth_proto == ETH_P_8021AD) {
		if (bpf_skb_load_bytes(skb, off, &vlan, sizeof(vlan)) < 0)
			return TC_ACT_OK;
		eth_proto = bpf_ntohs(vlan.encap_proto);
		off += sizeof(vlan);
	}

	if (eth_proto == ETH_P_IP) {
		struct nd_iphdr iph;
		__u32 ihl;

		if (bpf_skb_load_bytes(skb, off, &iph, sizeof(iph)) < 0)
			return TC_ACT_OK;
		protocol = iph.protocol;
		saddr_v4 = iph.saddr;
		daddr_v4 = iph.daddr;
		ihl = iph.ihl * 4;
		if (ihl < sizeof(iph))
			return TC_ACT_OK;

		if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {
			struct nd_ports ports;

			if (bpf_skb_load_bytes(skb, off + ihl, &ports, sizeof(ports)) == 0) {
				sport = bpf_ntohs(ports.sport);
				dport = bpf_ntohs(ports.dport);
			}
		} else if (protocol == IPPROTO_ICMP) {
			struct nd_icmphdr icmp;

			if (bpf_skb_load_bytes(skb, off + ihl, &icmp, sizeof(icmp)) == 0) {
				icmp_type = icmp.type;
				icmp_code = icmp.code;
			}
		}
	} else if (eth_proto == ETH_P_IPV6) {
		struct nd_ipv6hdr ip6h;
		__u32 l4off = off + sizeof(ip6h);

		if (bpf_skb_load_bytes(skb, off, &ip6h, sizeof(ip6h)) < 0)
			return TC_ACT_OK;
		protocol = ip6h.nexthdr;
		__builtin_memcpy(saddr_v6, ip6h.saddr, sizeof(saddr_v6));
		__builtin_memcpy(daddr_v6, ip6h.daddr, sizeof(daddr_v6));

		if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {
			struct nd_ports ports;

			if (bpf_skb_load_bytes(skb, l4off, &ports, sizeof(ports)) == 0) {
				sport = bpf_ntohs(ports.sport);
				dport = bpf_ntohs(ports.dport);
			}
		} else if (protocol == IPPROTO_ICMPV6) {
			struct nd_icmphdr icmp;

			if (bpf_skb_load_bytes(skb, l4off, &icmp, sizeof(icmp)) == 0) {
				icmp_type = icmp.type;
				icmp_code = icmp.code;
			}
		}
	} else if (eth_proto == ETH_P_ARP) {
		struct nd_arphdr arp;

		event_type = ND_EVENT_ARP_PACKET;
		if (bpf_skb_load_bytes(skb, off, &arp, sizeof(arp)) == 0) {
			protocol = 0;
			icmp_type = bpf_ntohs(arp.oper);
		}
	} else {
		return TC_ACT_OK;
	}

	if (!allow_port(sport, dport))
		return TC_ACT_OK;

	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event)
		return TC_ACT_OK;

	__builtin_memset(event, 0, sizeof(*event));
	event->ts_ns = bpf_ktime_get_ns();
	event->type = event_type;
	event->protocol = protocol;
	event->direction = direction;
	event->ifindex = skb->ifindex;
	event->bytes = skb->len;
	event->eth_proto = eth_proto;
	event->sport = sport;
	event->dport = dport;
	event->icmp_type = icmp_type;
	event->icmp_code = icmp_code;
	event->saddr_v4 = saddr_v4;
	event->daddr_v4 = daddr_v4;
	__builtin_memcpy(event->saddr_v6, saddr_v6, sizeof(event->saddr_v6));
	__builtin_memcpy(event->daddr_v6, daddr_v6, sizeof(event->daddr_v6));
	fill_process(event);
	bpf_ringbuf_submit(event, 0);
	return TC_ACT_OK;
}

SEC("classifier/netdoctor_ingress")
int netdoctor_tc_ingress(struct __sk_buff *skb)
{
	return submit_packet_event(skb, ND_DIR_INGRESS);
}

SEC("classifier/netdoctor_egress")
int netdoctor_tc_egress(struct __sk_buff *skb)
{
	return submit_packet_event(skb, ND_DIR_EGRESS);
}
