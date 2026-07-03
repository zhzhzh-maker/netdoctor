package ebpfcollector

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"

	"github.com/netdoctor/netdoctor/internal/model"
)

const ndEventSize = 148

const (
	ndEventTCPState       = 1
	ndEventTCPConnect     = 2
	ndEventTCPConnectFail = 3
	ndEventTCPRetrans     = 4
	ndEventTCPReset       = 5
	ndEventUDPSend        = 6
	ndEventUDPRecv        = 7
	ndEventICMPSend       = 8
	ndEventPacket         = 9
	ndEventARPPacket      = 10
	ndEventTCPSend        = 11
	ndEventTCPRecv        = 12
)

const (
	afInet  = 2
	afInet6 = 10
)

func decodeRawEvent(raw []byte) model.NetworkEvent {
	event := model.NetworkEvent{
		Kind: "raw-ebpf-event",
		Raw:  hex.EncodeToString(raw),
	}
	if len(raw) < ndEventSize {
		event.Summary = fmt.Sprintf("raw eBPF event (%d bytes)", len(raw))
		return event
	}

	duration := binary.LittleEndian.Uint64(raw[16:24])
	bytes := binary.LittleEndian.Uint64(raw[24:32])
	packets := binary.LittleEndian.Uint64(raw[32:40])
	pid := binary.LittleEndian.Uint32(raw[40:44])
	tgid := binary.LittleEndian.Uint32(raw[44:48])
	ifindex := binary.LittleEndian.Uint32(raw[48:52])
	ret := int32(binary.LittleEndian.Uint32(raw[52:56]))
	saddr4 := raw[56:60]
	daddr4 := raw[60:64]
	saddr6 := raw[64:80]
	daddr6 := raw[80:96]
	cwnd := binary.LittleEndian.Uint32(raw[96:100])
	ssthresh := binary.LittleEndian.Uint32(raw[100:104])
	srtt := binary.LittleEndian.Uint32(raw[104:108])
	rto := binary.LittleEndian.Uint32(raw[108:112])
	retrans := binary.LittleEndian.Uint32(raw[112:116])
	sport := binary.LittleEndian.Uint16(raw[116:118])
	dport := binary.LittleEndian.Uint16(raw[118:120])
	family := binary.LittleEndian.Uint16(raw[120:122])
	ethProto := binary.LittleEndian.Uint16(raw[122:124])
	eventType := raw[124]
	protocol := raw[125]
	direction := raw[126]
	oldState := raw[127]
	newState := raw[128]
	icmpType := raw[130]
	icmpCode := raw[131]
	comm := cString(raw[132:148])

	event.Kind = eventTypeName(eventType)
	event.PID = pid
	event.TGID = tgid
	event.Command = comm
	event.Protocol = protocolName(protocol)
	event.Direction = directionName(direction)
	event.IfIndex = ifindex
	event.Bytes = bytes
	event.Packets = packets
	event.Duration = duration
	event.Ret = ret
	event.OldState = tcpStateName(oldState)
	event.NewState = tcpStateName(newState)
	event.SRTT = srtt
	event.RTO = rto
	event.CWND = cwnd
	event.SSThresh = ssthresh
	event.Retrans = retrans
	event.ICMPType = icmpType
	event.ICMPCode = icmpCode
	event.EthProto = ethProtoName(ethProto)

	event.Local = model.Endpoint{Address: addressString(family, saddr4, saddr6), Port: sport}
	event.Remote = model.Endpoint{Address: addressString(family, daddr4, daddr6), Port: dport}
	if (event.Local.Address == "" && eventType == ndEventPacket) || eventType == ndEventARPPacket {
		event.Local.Address = addressStringForPacket(ethProto, protocol, saddr4, saddr6)
		event.Remote.Address = addressStringForPacket(ethProto, protocol, daddr4, daddr6)
	}

	event.Summary = eventSummary(event)
	return event
}

func cString(raw []byte) string {
	n := 0
	for n < len(raw) && raw[n] != 0 {
		n++
	}
	return string(raw[:n])
}

func addressString(family uint16, v4 []byte, v6 []byte) string {
	switch family {
	case afInet:
		if isZero(v4) {
			return ""
		}
		return net.IPv4(v4[0], v4[1], v4[2], v4[3]).String()
	case afInet6:
		if isZero(v6) {
			return ""
		}
		return net.IP(v6).String()
	default:
		return ""
	}
}

func addressStringForPacket(ethProto uint16, protocol uint8, v4 []byte, v6 []byte) string {
	switch ethProto {
	case 0x0800:
		if isZero(v4) {
			return ""
		}
		return net.IPv4(v4[0], v4[1], v4[2], v4[3]).String()
	case 0x86dd:
		if isZero(v6) {
			return ""
		}
		return net.IP(v6).String()
	default:
		_ = protocol
		return ""
	}
}

func isZero(raw []byte) bool {
	for _, b := range raw {
		if b != 0 {
			return false
		}
	}
	return true
}

func eventTypeName(value uint8) string {
	switch value {
	case ndEventTCPState:
		return "tcp-state"
	case ndEventTCPConnect:
		return "tcp-connect"
	case ndEventTCPConnectFail:
		return "tcp-connect-fail"
	case ndEventTCPRetrans:
		return "tcp-retransmit"
	case ndEventTCPReset:
		return "tcp-reset"
	case ndEventUDPSend:
		return "udp-send"
	case ndEventUDPRecv:
		return "udp-recv"
	case ndEventICMPSend:
		return "icmp-send"
	case ndEventPacket:
		return "packet"
	case ndEventARPPacket:
		return "arp-packet"
	case ndEventTCPSend:
		return "tcp-send"
	case ndEventTCPRecv:
		return "tcp-recv"
	default:
		return fmt.Sprintf("event-%d", value)
	}
}

func protocolName(value uint8) string {
	switch value {
	case 1:
		return "ICMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 58:
		return "ICMPv6"
	case 0:
		return ""
	default:
		return fmt.Sprintf("IPPROTO-%d", value)
	}
}

func directionName(value uint8) string {
	switch value {
	case 1:
		return "ingress"
	case 2:
		return "egress"
	default:
		return ""
	}
}

func tcpStateName(value uint8) string {
	switch value {
	case 1:
		return "ESTABLISHED"
	case 2:
		return "SYN_SENT"
	case 3:
		return "SYN_RECV"
	case 4:
		return "FIN_WAIT1"
	case 5:
		return "FIN_WAIT2"
	case 6:
		return "TIME_WAIT"
	case 7:
		return "CLOSE"
	case 8:
		return "CLOSE_WAIT"
	case 9:
		return "LAST_ACK"
	case 10:
		return "LISTEN"
	case 11:
		return "CLOSING"
	case 12:
		return "NEW_SYN_RECV"
	default:
		return ""
	}
}

func ethProtoName(value uint16) string {
	switch value {
	case 0x0800:
		return "IPv4"
	case 0x0806:
		return "ARP"
	case 0x8100:
		return "VLAN"
	case 0x86dd:
		return "IPv6"
	case 0x88a8:
		return "QinQ"
	case 0:
		return ""
	default:
		return fmt.Sprintf("0x%04x", value)
	}
}

func eventSummary(event model.NetworkEvent) string {
	var b strings.Builder
	b.WriteString(event.Kind)
	if event.Protocol != "" {
		b.WriteString(" ")
		b.WriteString(event.Protocol)
	}
	if event.Direction != "" {
		b.WriteString(" ")
		b.WriteString(event.Direction)
	}
	if event.Command != "" || event.PID != 0 {
		fmt.Fprintf(&b, " pid=%d", event.PID)
		if event.Command != "" {
			fmt.Fprintf(&b, " comm=%s", event.Command)
		}
	}
	if event.Local.Address != "" || event.Remote.Address != "" || event.Local.Port != 0 || event.Remote.Port != 0 {
		fmt.Fprintf(&b, " %s -> %s", endpointString(event.Local), endpointString(event.Remote))
	}
	if event.OldState != "" || event.NewState != "" {
		fmt.Fprintf(&b, " %s->%s", event.OldState, event.NewState)
	}
	if event.Duration > 0 {
		fmt.Fprintf(&b, " duration=%dus", event.Duration)
	}
	if event.Bytes > 0 {
		fmt.Fprintf(&b, " bytes=%d", event.Bytes)
	}
	if event.Retrans > 0 {
		fmt.Fprintf(&b, " retrans=%d", event.Retrans)
	}
	if event.ICMPType != 0 || event.ICMPCode != 0 {
		fmt.Fprintf(&b, " icmp=%d/%d", event.ICMPType, event.ICMPCode)
	}
	return b.String()
}

func endpointString(endpoint model.Endpoint) string {
	if endpoint.Address == "" {
		if endpoint.Port == 0 {
			return "-"
		}
		return fmt.Sprintf(":%d", endpoint.Port)
	}
	if endpoint.Port == 0 {
		return endpoint.Address
	}
	if strings.Contains(endpoint.Address, ":") {
		return fmt.Sprintf("[%s]:%d", endpoint.Address, endpoint.Port)
	}
	return fmt.Sprintf("%s:%d", endpoint.Address, endpoint.Port)
}
