package model

import "time"

type Snapshot struct {
	GeneratedAt time.Time        `json:"generated_at"`
	Host        HostOverview     `json:"host"`
	Interfaces  []Interface      `json:"interfaces"`
	TCP         TCPStats         `json:"tcp"`
	UDP         UDPStats         `json:"udp"`
	ICMP        ICMPStats        `json:"icmp"`
	Processes   []ProcessNetwork `json:"processes"`
	Connections []Connection     `json:"connections"`
	EBPF        EBPFStatus       `json:"ebpf"`
	Events      []NetworkEvent   `json:"events,omitempty"`
	Findings    []Finding        `json:"findings"`
}

type HostOverview struct {
	Hostname           string   `json:"hostname"`
	Platform           string   `json:"platform"`
	Kernel             string   `json:"kernel,omitempty"`
	DefaultRoutes      []Route  `json:"default_routes,omitempty"`
	DNSServers         []string `json:"dns_servers,omitempty"`
	ListeningPorts     int      `json:"listening_ports"`
	CurrentConnections int      `json:"current_connections"`
	HealthScore        int      `json:"health_score"`
}

type Route struct {
	Destination string `json:"destination"`
	Gateway     string `json:"gateway,omitempty"`
	Interface   string `json:"interface,omitempty"`
	Family      string `json:"family,omitempty"`
}

type Interface struct {
	Name        string         `json:"name"`
	Index       int            `json:"index"`
	Type        string         `json:"type,omitempty"`
	State       string         `json:"state,omitempty"`
	MAC         string         `json:"mac,omitempty"`
	MTU         int            `json:"mtu"`
	IPs         []string       `json:"ips,omitempty"`
	Driver      string         `json:"driver,omitempty"`
	SpeedMbps   int64          `json:"speed_mbps,omitempty"`
	Queues      InterfaceQueue `json:"queues,omitempty"`
	Stats       InterfaceStats `json:"stats"`
	Parent      string         `json:"parent,omitempty"`
	Kind        string         `json:"kind,omitempty"`
	HealthScore int            `json:"health_score"`
}

type InterfaceQueue struct {
	RX int `json:"rx,omitempty"`
	TX int `json:"tx,omitempty"`
}

type InterfaceStats struct {
	RXBytes      uint64 `json:"rx_bytes"`
	RXPackets    uint64 `json:"rx_packets"`
	RXErrors     uint64 `json:"rx_errors"`
	RXDropped    uint64 `json:"rx_dropped"`
	TXBytes      uint64 `json:"tx_bytes"`
	TXPackets    uint64 `json:"tx_packets"`
	TXErrors     uint64 `json:"tx_errors"`
	TXDropped    uint64 `json:"tx_dropped"`
	Collisions   uint64 `json:"collisions,omitempty"`
	RXCompressed uint64 `json:"rx_compressed,omitempty"`
	TXCompressed uint64 `json:"tx_compressed,omitempty"`
}

type TCPStats struct {
	ActiveOpens     uint64         `json:"active_opens,omitempty"`
	PassiveOpens    uint64         `json:"passive_opens,omitempty"`
	AttemptFails    uint64         `json:"attempt_fails,omitempty"`
	EstabResets     uint64         `json:"estab_resets,omitempty"`
	InSegments      uint64         `json:"in_segments,omitempty"`
	OutSegments     uint64         `json:"out_segments,omitempty"`
	RetransSegments uint64         `json:"retrans_segments,omitempty"`
	RetransRate     float64        `json:"retrans_rate,omitempty"`
	States          map[string]int `json:"states,omitempty"`
}

type UDPStats struct {
	InDatagrams    uint64 `json:"in_datagrams,omitempty"`
	NoPorts        uint64 `json:"no_ports,omitempty"`
	InErrors       uint64 `json:"in_errors,omitempty"`
	OutDatagrams   uint64 `json:"out_datagrams,omitempty"`
	RcvbufErrors   uint64 `json:"rcvbuf_errors,omitempty"`
	SndbufErrors   uint64 `json:"sndbuf_errors,omitempty"`
	InCsumErrors   uint64 `json:"in_csum_errors,omitempty"`
	IgnoredMulti   uint64 `json:"ignored_multi,omitempty"`
	SocketCount    int    `json:"socket_count,omitempty"`
	ListeningPorts int    `json:"listening_ports,omitempty"`
}

type ICMPStats struct {
	InMessages  uint64 `json:"in_messages,omitempty"`
	InErrors    uint64 `json:"in_errors,omitempty"`
	OutMessages uint64 `json:"out_messages,omitempty"`
	OutErrors   uint64 `json:"out_errors,omitempty"`
}

type Connection struct {
	Protocol      string `json:"protocol"`
	LocalAddress  string `json:"local_address"`
	LocalPort     uint16 `json:"local_port"`
	RemoteAddress string `json:"remote_address,omitempty"`
	RemotePort    uint16 `json:"remote_port,omitempty"`
	State         string `json:"state,omitempty"`
	UID           uint32 `json:"uid,omitempty"`
	Inode         string `json:"inode,omitempty"`
	PID           int    `json:"pid,omitempty"`
	Process       string `json:"process,omitempty"`
	RecvQ         uint64 `json:"recv_q,omitempty"`
	SendQ         uint64 `json:"send_q,omitempty"`
}

type ProcessNetwork struct {
	PID          int      `json:"pid"`
	PPID         int      `json:"ppid,omitempty"`
	Name         string   `json:"name"`
	CommandLine  string   `json:"command_line,omitempty"`
	UserID       uint32   `json:"user_id,omitempty"`
	CGroup       []string `json:"cgroup,omitempty"`
	SocketCount  int      `json:"socket_count"`
	TCPCount     int      `json:"tcp_count,omitempty"`
	UDPCount     int      `json:"udp_count,omitempty"`
	ListenPorts  []uint16 `json:"listen_ports,omitempty"`
	SocketInodes []string `json:"-"`
}

type EBPFStatus struct {
	Enabled       bool     `json:"enabled"`
	Available     bool     `json:"available"`
	Mode          string   `json:"mode"`
	KernelVersion string   `json:"kernel_version,omitempty"`
	Capabilities  []string `json:"capabilities,omitempty"`
	ObjectPath    string   `json:"object_path,omitempty"`
	Attached      []string `json:"attached,omitempty"`
	Error         string   `json:"error,omitempty"`
}

type NetworkEvent struct {
	Time      time.Time `json:"time"`
	Source    string    `json:"source"`
	Kind      string    `json:"kind"`
	CPU       int       `json:"cpu,omitempty"`
	PID       uint32    `json:"pid,omitempty"`
	Command   string    `json:"command,omitempty"`
	Protocol  string    `json:"protocol,omitempty"`
	Direction string    `json:"direction,omitempty"`
	Local     Endpoint  `json:"local,omitempty"`
	Remote    Endpoint  `json:"remote,omitempty"`
	Bytes     uint64    `json:"bytes,omitempty"`
	Packets   uint64    `json:"packets,omitempty"`
	Reason    string    `json:"reason,omitempty"`
	Raw       string    `json:"raw,omitempty"`
}

type Endpoint struct {
	Address string `json:"address,omitempty"`
	Port    uint16 `json:"port,omitempty"`
}

type Finding struct {
	Severity string `json:"severity"`
	Category string `json:"category"`
	Title    string `json:"title"`
	Detail   string `json:"detail"`
}
