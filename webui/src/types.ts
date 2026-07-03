export interface Snapshot {
  generated_at?: string
  host?: HostOverview
  ebpf?: EBPFStatus
  process_traffic?: ProcessTrafficStats[]
  system_tcp?: SystemTCPInterfaceStats[]
}

export interface HostOverview {
  hostname?: string
  platform?: string
  health_score?: number
}

export interface EBPFStatus {
  enabled?: boolean
  attached?: string[]
  skipped?: string[]
  interfaces?: string[]
  error?: string
}

export interface ProcessTrafficStats {
  pid: number
  command?: string
  protocol: string
  rx_bytes: number
  tx_bytes: number
  retrans_bytes?: number
  retransmits?: number
  retrans_rate?: number
}

export interface SystemTCPInterfaceStats {
  ifindex: number
  interface?: string
  tx_bytes: number
  rx_bytes: number
  retrans_bytes?: number
  retransmits?: number
  events?: number
  retrans_rate?: number
}
