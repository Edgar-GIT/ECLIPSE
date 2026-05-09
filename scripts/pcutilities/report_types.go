package pcutilities

import "time"

type DiskVol struct {
	Mountpoint string
	Device     string
	Fstype     string
	Total      uint64
	Used       uint64
	Free       uint64
	UsedPct    float64
	Medium     string
}

type NetIface struct {
	Name   string
	Addrs  []string
	IsWifi bool
}

type WiFiNet struct {
	SSID     string
	Signal   string
	Security string
	Active   bool
}

type SystemReport struct {
	CollectedAt time.Time

	Hostname   string
	OS         string
	Platform   string
	OSVersion  string
	Kernel     string
	GoArch     string
	KernelArch string
	HostID     string
	Uptime     string
	BootTime   string
	Virtual    string
	ProcCount  uint64
	UserNames  string

	CPUModel      string
	CPUMhz        string
	CPUPhysical   int
	CPULogical    int
	CPUUsagePct   float64
	LoadAvg       string

	RAMTotal     uint64
	RAMUsed      uint64
	RAMAvail     uint64
	RAMUsedPct   float64
	SwapTotal    uint64
	SwapUsed     uint64
	SwapUsedPct  float64

	Disks          []DiskVol
	DiskTotalBytes uint64
	DiskFreeBytes  uint64
	DiskUsedBytes  uint64

	LocalIPs      []string
	DefaultIface  string
	ActiveConn    string
	PublicIP      string
	PublicIPErr   string
	WiFiNetworks  []WiFiNet
	InterfaceRows []NetIface

	Thermal []struct {
		Label string
		TempC float64
	}

	GPUNames []string

	NetIO []struct {
		Name string
		Rx   uint64
		Tx   uint64
		PRx  uint64
		PTx  uint64
	}

	PID        int
	GoVersion  string
	Goroutines int
	ProcVis    int
}
