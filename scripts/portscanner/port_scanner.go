package portscanner

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"programa/utils"
)

type PortInfo struct {
	Port            int                `json:"port" xml:"port,attr"`
	Protocol        string             `json:"protocol" xml:"protocol,attr"`
	Status          string             `json:"status" xml:"status,attr"`
	Reason          string             `json:"reason,omitempty" xml:"reason,omitempty"`
	Service         string             `json:"service,omitempty" xml:"service,omitempty"`
	Product         string             `json:"product,omitempty" xml:"product,omitempty"`
	Version         string             `json:"version,omitempty" xml:"version,omitempty"`
	ExtraInfo       string             `json:"extra_info,omitempty" xml:"extra_info,omitempty"`
	Banner          string             `json:"banner,omitempty" xml:"banner,omitempty"`
	TLSCertificate  string             `json:"tls_certificate,omitempty" xml:"tls_certificate,omitempty"`
	OSGuess         string             `json:"os_guess,omitempty" xml:"os_guess,omitempty"`
	Scripts         []PortScriptResult `json:"scripts,omitempty" xml:"scripts>script,omitempty"`
	Vulnerabilities []string           `json:"vulnerabilities,omitempty" xml:"vulnerabilities>vulnerability,omitempty"`
	LastScanned     time.Time          `json:"last_scanned" xml:"last_scanned"`
}

type PortScriptResult struct {
	Name     string `json:"name" xml:"name,attr"`
	Status   string `json:"status" xml:"status,attr"`
	Severity string `json:"severity,omitempty" xml:"severity,omitempty"`
	Output   string `json:"output,omitempty" xml:"output,omitempty"`
}

type PortScanResults struct {
	XMLName          xml.Name   `json:"-" xml:"port_scan_results"`
	TargetIP         string     `json:"target_ip" xml:"target_ip,attr"`
	TargetHostname   string     `json:"target_hostname,omitempty" xml:"target_hostname,omitempty"`
	TotalScanned     int        `json:"total_scanned" xml:"total_scanned"`
	Open             int        `json:"open" xml:"open"`
	Closed           int        `json:"closed" xml:"closed"`
	Filtered         int        `json:"filtered,omitempty" xml:"filtered,omitempty"`
	ScanDuration     float64    `json:"scan_duration_seconds" xml:"scan_duration_seconds"`
	ScannedAt        time.Time  `json:"scanned_at" xml:"scanned_at"`
	Ports            []PortInfo `json:"ports" xml:"ports>port"`
	ScanMode         string     `json:"scan_mode,omitempty" xml:"scan_mode,omitempty"`
	RequestedScan    string     `json:"requested_scan,omitempty" xml:"requested_scan,omitempty"`
	OutputFormat     string     `json:"output_format,omitempty" xml:"output_format,omitempty"`
	StartPort        int        `json:"start_port,omitempty" xml:"start_port,omitempty"`
	EndPort          int        `json:"end_port,omitempty" xml:"end_port,omitempty"`
	TimingTemplate   int        `json:"timing_template,omitempty" xml:"timing_template,omitempty"`
	Concurrency      int        `json:"concurrency,omitempty" xml:"concurrency,omitempty"`
	TimeoutMS        int64      `json:"timeout_ms,omitempty" xml:"timeout_ms,omitempty"`
	RateLimit        int        `json:"rate_limit,omitempty" xml:"rate_limit,omitempty"`
	VersionIntensity int        `json:"version_intensity,omitempty" xml:"version_intensity,omitempty"`
	OSGuess          string     `json:"os_guess,omitempty" xml:"os_guess,omitempty"`
	SafetyNotes      []string   `json:"safety_notes,omitempty" xml:"safety_notes>note,omitempty"`
}

type PortScannerOptions struct {
	ScanType         string
	RequestedScan    string
	Concurrency      int
	Timeout          time.Duration
	Retries          int
	RetryBackoff     time.Duration
	Delay            time.Duration
	RateLimit        int
	TimingTemplate   int
	OutputFormat     string
	VersionDetection bool
	VersionIntensity int
	OSDetection      bool
	TopPorts         int
	ExcludePorts     map[int]struct{}
	ScriptNames      []string
	ScriptArgs       map[string]string
	NoScripts        bool
	SourcePort       int
	Bandwidth        string
	LogLevel         slog.Level
	SafetyNotes      []string
}

type VulnerabilityRule struct {
	ID             string
	Severity       string
	Ports          []int
	Keywords       []string
	AffectedBelow  string
	Description    string
	Research       string
	Recommendation string
}

type simpleRateLimiter struct {
	ticker   *time.Ticker
	disabled bool
}

const (
	portResultsFile = "target/port_scan_results.json"
	portXMLFile     = "target/port_scan_results.xml"
	portGrepFile    = "target/port_scan_results.grep"
)

var (
	portLogger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	bannerBufferPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 4096)
			return &buf
		},
	}
)

var commonPortServices = map[int]string{
	7:     "Echo",
	9:     "Discard",
	13:    "Daytime",
	17:    "QOTD",
	19:    "Chargen",
	20:    "FTP-Data",
	21:    "FTP",
	22:    "SSH",
	23:    "Telnet",
	25:    "SMTP",
	37:    "Time",
	49:    "TACACS",
	53:    "DNS",
	67:    "DHCP",
	68:    "DHCP",
	69:    "TFTP",
	79:    "Finger",
	80:    "HTTP",
	88:    "Kerberos",
	106:   "POP3Pw",
	110:   "POP3",
	111:   "RPCBind",
	113:   "Ident",
	119:   "NNTP",
	123:   "NTP",
	135:   "MSRPC",
	137:   "NetBIOS-NS",
	138:   "NetBIOS-DGM",
	139:   "NetBIOS-SSN",
	143:   "IMAP",
	161:   "SNMP",
	162:   "SNMPTrap",
	179:   "BGP",
	389:   "LDAP",
	427:   "SLP",
	443:   "HTTPS",
	445:   "SMB",
	465:   "SMTPS",
	500:   "ISAKMP",
	512:   "Exec",
	513:   "Login",
	514:   "Syslog",
	515:   "Printer",
	548:   "AFP",
	554:   "RTSP",
	587:   "SMTP-Submission",
	623:   "IPMI",
	631:   "IPP",
	636:   "LDAPS",
	873:   "Rsync",
	902:   "VMware",
	989:   "FTPS-Data",
	990:   "FTPS",
	993:   "IMAPS",
	995:   "POP3S",
	1080:  "SOCKS",
	1194:  "OpenVPN",
	1433:  "MSSQL",
	1521:  "Oracle",
	1723:  "PPTP",
	1883:  "MQTT",
	2049:  "NFS",
	2375:  "Docker",
	2376:  "Docker-TLS",
	2483:  "Oracle",
	2484:  "Oracle-TLS",
	3000:  "HTTP-Dev",
	3128:  "HTTP-Proxy",
	3268:  "LDAP-GC",
	3306:  "MySQL",
	3389:  "RDP",
	3690:  "SVN",
	4000:  "HTTP-Alt",
	4369:  "EPMD",
	5000:  "HTTP-Alt",
	5060:  "SIP",
	5061:  "SIPS",
	5432:  "PostgreSQL",
	5601:  "Kibana",
	5672:  "AMQP",
	5900:  "VNC",
	5984:  "CouchDB",
	5985:  "WinRM",
	5986:  "WinRM-TLS",
	6379:  "Redis",
	6443:  "Kubernetes-API",
	6667:  "IRC",
	7001:  "WebLogic",
	8000:  "HTTP-Alt",
	8008:  "HTTP-Alt",
	8080:  "HTTP-Proxy",
	8081:  "HTTP-Alt",
	8088:  "HTTP-Alt",
	8090:  "HTTP-Alt",
	8443:  "HTTPS-Alt",
	8500:  "Consul",
	8888:  "HTTP-Alt",
	9000:  "SonarQube",
	9042:  "Cassandra",
	9092:  "Kafka",
	9200:  "Elasticsearch",
	9300:  "Elasticsearch-Transport",
	9418:  "Git",
	10000: "Webmin",
	11211: "Memcached",
	15672: "RabbitMQ",
	27017: "MongoDB",
	27018: "MongoDB",
	27019: "MongoDB",
	50000: "DB2",
}

var topPortsRanked = []int{
	80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080, 1723,
	111, 995, 993, 5900, 1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001,
	10000, 514, 5060, 179, 1026, 2000, 8443, 8000, 32768, 554, 26, 1433, 49152,
	2001, 515, 8008, 49154, 1027, 5666, 646, 5000, 5631, 631, 49153, 8081, 2049,
	88, 79, 5800, 106, 2121, 1110, 49155, 6000, 513, 990, 5357, 427, 49156, 543,
	544, 5101, 144, 7, 389, 8009, 3128, 444, 9999, 5009, 7070, 5190, 3000, 5432,
	1900, 3986, 13, 1029, 9, 5051, 6646, 49157, 1028, 873, 1755, 2717, 4899, 9100,
	119, 37, 1000, 3001, 5001, 82, 10010, 1030, 9090, 2107, 1024, 2103, 6004, 1801,
	5050, 19, 8031, 1041, 255, 1048, 1049, 1053, 1054, 1056, 1064, 1065, 2967, 3703,
	5901, 8082, 8088, 8994, 9091, 10001, 11211, 16992, 27017,
}

var fastScanPorts = []int{
	20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 123, 135, 137, 138, 139, 143, 161, 389, 443,
	445, 465, 514, 587, 631, 993, 995, 1080, 1433, 1521, 1723, 1883, 2049, 2375, 2376, 3000,
	3128, 3306, 3389, 4000, 5000, 5432, 5672, 5900, 5984, 6379, 6443, 6667, 7001, 8000, 8008,
	8080, 8081, 8088, 8090, 8443, 8888, 9000, 9042, 9092, 9200, 9300, 11211, 15672, 27017,
}

var cveDatabase = map[string][]string{
	"telnet": {
		"Insecure protocol: credentials and session data are sent in cleartext. Disable Telnet or restrict it to a trusted management network.",
	},
	"ftp": {
		"Insecure protocol: FTP exposes credentials and file transfers unless FTPS is enforced. Prefer SFTP/FTPS and source IP allow-lists.",
	},
	"mysql": {
		"MySQL exposed on 3306: verify authentication, TLS, least-privilege accounts, and bind-address restrictions.",
	},
	"smb": {
		"SMB exposed to untrusted networks: validate MS17-010-era patching, disable SMBv1, and restrict 445/TCP to trusted segments.",
	},
	"rdp": {
		"RDP exposed: enforce NLA, MFA, account lockout, and source IP restrictions; review BlueKeep-era patch status.",
	},
	"redis": {
		"Redis exposed: require authentication/TLS, protected-mode, and private bind addresses; never expose unauthenticated Redis externally.",
	},
	"mongodb": {
		"MongoDB exposed: verify authentication, TLS, bindIp, and role separation; review audit logs for unknown reads.",
	},
	"smtp": {
		"SMTP exposed: validate anti-relay controls, STARTTLS, SPF/DKIM/DMARC posture, and abuse monitoring.",
	},
	"imap_pop3": {
		"Mail retrieval service exposed: prefer TLS variants, strong authentication, lockouts, and legacy protocol review.",
	},
	"http": {
		"HTTP service exposed: verify patch baseline, TLS redirection, security headers, and application inventory ownership.",
	},
	"database": {
		"Database listener exposed: place behind private networks or VPN, enforce TLS, and monitor failed authentication attempts.",
	},
}

var vulnerabilityCatalog = []VulnerabilityRule{
	{ID: "CVE-2014-0160", Severity: "Critical 7.5", Ports: []int{443, 8443, 993, 995, 465}, Keywords: []string{"openssl"}, AffectedBelow: "1.0.1g", Description: "OpenSSL Heartbleed information disclosure in affected 1.0.1 builds.", Research: "Verify with NVD and the vendor advisory; review certificate rotation and memory exposure logs.", Recommendation: "Upgrade OpenSSL, rotate keys/certificates, and restart dependent services."},
	{ID: "CVE-2015-0204", Severity: "Medium 4.3", Ports: []int{443, 8443}, Keywords: []string{"openssl"}, AffectedBelow: "1.0.1k", Description: "OpenSSL FREAK downgrade exposure on older TLS stacks.", Research: "Check NVD and TLS scanner results for export cipher support.", Recommendation: "Patch OpenSSL and disable export-grade cipher suites."},
	{ID: "CVE-2016-0800", Severity: "High 7.4", Ports: []int{443, 8443}, Keywords: []string{"openssl"}, AffectedBelow: "1.0.2g", Description: "OpenSSL DROWN risk when SSLv2 and shared keys are present.", Research: "Validate against vendor guidance and review certificate reuse across services.", Recommendation: "Disable SSLv2 everywhere, patch OpenSSL, and avoid key reuse."},
	{ID: "CVE-2016-6210", Severity: "Medium 5.3", Ports: []int{22}, Keywords: []string{"openssh"}, AffectedBelow: "7.4", Description: "OpenSSH username enumeration timing behavior in older releases.", Research: "Verify exact portable/OpenBSD release notes and authentication logs.", Recommendation: "Upgrade OpenSSH and normalize authentication failure handling."},
	{ID: "CVE-2018-15473", Severity: "Medium 5.3", Ports: []int{22}, Keywords: []string{"openssh"}, AffectedBelow: "7.7", Description: "OpenSSH user enumeration in older server versions.", Research: "Confirm patch level with vendor packages and review failed login telemetry.", Recommendation: "Upgrade OpenSSH and rate-limit authentication attempts."},
	{ID: "CVE-2020-14145", Severity: "Low 4.3", Ports: []int{22}, Keywords: []string{"openssh"}, AffectedBelow: "8.4", Description: "OpenSSH information exposure conditions in older deployments.", Research: "Check NVD, vendor backport notes, and SSH client/server versions.", Recommendation: "Upgrade or use vendor-patched packages and enforce modern algorithms."},
	{ID: "CVE-2023-38408", Severity: "High 9.8", Ports: []int{22}, Keywords: []string{"openssh"}, AffectedBelow: "9.3", Description: "OpenSSH agent forwarding risk with specific PKCS#11 provider loading behavior.", Research: "Review NVD and OpenSSH release notes; inspect use of agent forwarding.", Recommendation: "Upgrade OpenSSH and disable agent forwarding where unnecessary."},
	{ID: "CVE-2024-6387", Severity: "Critical 8.1", Ports: []int{22}, Keywords: []string{"openssh"}, AffectedBelow: "9.8", Description: "OpenSSH regreSSHion signal handler race in affected server versions.", Research: "Validate distro backports and review auth logs for anomalous connection patterns.", Recommendation: "Apply vendor patches urgently and restrict SSH exposure."},
	{ID: "CVE-2017-5638", Severity: "Critical 10.0", Ports: []int{80, 443, 8080, 8443}, Keywords: []string{"struts"}, AffectedBelow: "2.3.32", Description: "Apache Struts Jakarta multipart parser remote code execution.", Research: "Check NVD and Apache Struts advisories; review web logs for suspicious Content-Type headers.", Recommendation: "Upgrade Struts and block untrusted access until patched."},
	{ID: "CVE-2018-11776", Severity: "Critical 8.1", Ports: []int{80, 443, 8080, 8443}, Keywords: []string{"struts"}, AffectedBelow: "2.5.17", Description: "Apache Struts namespace/action misconfiguration RCE in affected versions.", Research: "Validate framework version and route configuration against Apache guidance.", Recommendation: "Upgrade Struts and review namespace/action mappings."},
	{ID: "CVE-2021-41773", Severity: "High 7.5", Ports: []int{80, 443, 8080, 8443}, Keywords: []string{"apache"}, AffectedBelow: "2.4.50", Description: "Apache HTTP Server path traversal in vulnerable 2.4.49 deployments.", Research: "Check Apache advisories and access logs for traversal patterns.", Recommendation: "Upgrade Apache HTTP Server to a fixed release and verify directory restrictions."},
	{ID: "CVE-2021-42013", Severity: "Critical 9.8", Ports: []int{80, 443, 8080, 8443}, Keywords: []string{"apache"}, AffectedBelow: "2.4.51", Description: "Apache HTTP Server path traversal and possible RCE after incomplete previous fix.", Research: "Review Apache guidance, access logs, and CGI exposure.", Recommendation: "Upgrade to a fixed Apache release and disable unnecessary CGI handlers."},
	{ID: "CVE-2022-22720", Severity: "Critical 9.8", Ports: []int{80, 443, 8080, 8443}, Keywords: []string{"apache"}, AffectedBelow: "2.4.52", Description: "Apache HTTP Server request smuggling and memory handling issues in older versions.", Research: "Check NVD and Apache changelogs for distro backport status.", Recommendation: "Patch Apache and harden reverse proxy request handling."},
	{ID: "CVE-2023-25690", Severity: "High 9.8", Ports: []int{80, 443, 8080, 8443}, Keywords: []string{"apache"}, AffectedBelow: "2.4.56", Description: "Apache HTTP Server mod_proxy request splitting/smuggling risk.", Research: "Review proxy rules and Apache advisory details.", Recommendation: "Upgrade Apache and simplify unsafe RewriteRule/proxy patterns."},
	{ID: "CVE-2019-20372", Severity: "Medium 5.3", Ports: []int{80, 443, 8080, 8443}, Keywords: []string{"nginx"}, AffectedBelow: "1.17.7", Description: "Nginx HTTP/2 request handling issue in older builds.", Research: "Check Nginx advisories and HTTP/2 exposure.", Recommendation: "Patch Nginx and review HTTP/2 settings."},
	{ID: "CVE-2021-23017", Severity: "High 7.7", Ports: []int{53, 80, 443, 8080, 8443}, Keywords: []string{"nginx"}, AffectedBelow: "1.20.1", Description: "Nginx resolver off-by-one vulnerability when resolver is configured.", Research: "Check NVD and Nginx resolver configuration.", Recommendation: "Upgrade Nginx and verify resolver usage."},
	{ID: "CVE-2022-1388", Severity: "Critical 9.8", Ports: []int{443, 8443}, Keywords: []string{"big-ip", "f5"}, Description: "F5 BIG-IP iControl REST authentication bypass in vulnerable management interfaces.", Research: "Verify against F5 advisory and management-plane exposure logs.", Recommendation: "Patch BIG-IP and restrict management interfaces to trusted networks."},
	{ID: "CVE-2023-3519", Severity: "Critical 9.8", Ports: []int{443, 8443}, Keywords: []string{"citrix", "netscaler", "adc"}, Description: "Citrix ADC/Gateway unauthenticated code execution in affected builds.", Research: "Check Citrix bulletins and appliance indicators of compromise.", Recommendation: "Apply fixed firmware and isolate management and gateway surfaces."},
	{ID: "CVE-2023-4966", Severity: "Critical 9.4", Ports: []int{443, 8443}, Keywords: []string{"citrix", "netscaler", "adc"}, Description: "Citrix Bleed sensitive information disclosure in affected ADC/Gateway versions.", Research: "Review Citrix guidance, session token rotation, and access logs.", Recommendation: "Patch, terminate active sessions, and rotate impacted credentials."},
	{ID: "CVE-2019-19781", Severity: "Critical 9.8", Ports: []int{443, 8443}, Keywords: []string{"citrix", "netscaler", "adc"}, Description: "Citrix ADC/Gateway path traversal leading to code execution in vulnerable builds.", Research: "Validate appliance version and inspect known IOC paths in web logs.", Recommendation: "Patch firmware and apply responder policies only as temporary mitigation."},
	{ID: "CVE-2021-22986", Severity: "Critical 9.8", Ports: []int{443, 8443}, Keywords: []string{"big-ip", "f5"}, Description: "F5 BIG-IP iControl REST unauthenticated RCE on management interfaces.", Research: "Check F5 advisory and management interface ACLs.", Recommendation: "Patch and keep management endpoints off untrusted networks."},
	{ID: "CVE-2020-0796", Severity: "Critical 10.0", Ports: []int{445}, Keywords: []string{"smb", "windows"}, Description: "SMBGhost compression vulnerability in SMBv3 on affected Windows systems.", Research: "Check Microsoft advisory and Windows build/patch inventory.", Recommendation: "Apply patches, disable SMB compression where advised, and restrict SMB."},
	{ID: "CVE-2017-0144", Severity: "Critical 8.1", Ports: []int{445}, Keywords: []string{"smb", "microsoft-ds", "windows"}, Description: "MS17-010 EternalBlue SMBv1 remote code execution risk on unpatched systems.", Research: "Verify Microsoft patch status and review SMBv1 exposure.", Recommendation: "Apply MS17-010 patches, disable SMBv1, and segment SMB access."},
	{ID: "CVE-2020-1472", Severity: "Critical 10.0", Ports: []int{135, 445, 389}, Keywords: []string{"netlogon", "domain controller", "windows"}, Description: "Zerologon Netlogon privilege escalation on domain controllers.", Research: "Check Microsoft patch deployment and domain controller event logs.", Recommendation: "Patch domain controllers and enforce secure RPC."},
	{ID: "CVE-2019-0708", Severity: "Critical 9.8", Ports: []int{3389}, Keywords: []string{"rdp", "terminal services"}, Description: "BlueKeep RDP remote code execution on older Windows hosts.", Research: "Validate Windows patch level and RDP exposure.", Recommendation: "Patch, enforce NLA, and restrict RDP to trusted networks."},
	{ID: "CVE-2021-34527", Severity: "Critical 8.8", Ports: []int{445, 139}, Keywords: []string{"spooler", "windows"}, Description: "PrintNightmare Windows Print Spooler remote code execution/privilege escalation.", Research: "Check Microsoft advisories and print spooler exposure.", Recommendation: "Patch and disable spooler where not required."},
	{ID: "CVE-2021-44228", Severity: "Critical 10.0", Ports: []int{80, 443, 8080, 8443, 8983, 9200}, Keywords: []string{"log4j", "solr", "elasticsearch"}, Description: "Log4Shell JNDI remote code execution in vulnerable Log4j 2 versions.", Research: "Confirm application dependency inventory with NVD/vendor advisories and review outbound LDAP/RMI/DNS logs.", Recommendation: "Upgrade Log4j to a fixed version and remove vulnerable classes from legacy packages."},
	{ID: "CVE-2021-45046", Severity: "Critical 9.0", Ports: []int{80, 443, 8080, 8443}, Keywords: []string{"log4j"}, Description: "Log4j incomplete fix follow-up risk in affected 2.15.0 configurations.", Research: "Check SBOM/package versions and application logs for lookup abuse.", Recommendation: "Upgrade Log4j beyond vulnerable releases and disable message lookups where applicable."},
	{ID: "CVE-2022-22965", Severity: "Critical 9.8", Ports: []int{80, 443, 8080, 8443}, Keywords: []string{"spring", "tomcat"}, Description: "Spring4Shell RCE in affected Spring Framework deployments.", Research: "Validate Spring Framework/JDK/Tomcat combination and web logs.", Recommendation: "Upgrade Spring Framework and harden binding configurations."},
	{ID: "CVE-2022-22963", Severity: "Critical 9.8", Ports: []int{80, 443, 8080, 8443}, Keywords: []string{"spring cloud function"}, Description: "Spring Cloud Function routing-expression RCE in affected versions.", Research: "Check dependency inventory and request logs for function routing headers.", Recommendation: "Upgrade Spring Cloud Function and filter unsafe headers."},
	{ID: "CVE-2017-12615", Severity: "Critical 9.8", Ports: []int{8080, 8443, 8009}, Keywords: []string{"tomcat"}, AffectedBelow: "7.0.82", Description: "Apache Tomcat PUT handling RCE when readonly is disabled in affected releases.", Research: "Check Tomcat version and webdav/readonly configuration.", Recommendation: "Upgrade Tomcat and disable unsafe PUT/WebDAV behavior."},
	{ID: "CVE-2020-1938", Severity: "Critical 9.8", Ports: []int{8009}, Keywords: []string{"tomcat", "ajp"}, AffectedBelow: "9.0.31", Description: "Apache Tomcat Ghostcat AJP file read/include vulnerability.", Research: "Validate AJP connector exposure and Tomcat version.", Recommendation: "Patch Tomcat and bind AJP to trusted interfaces or disable it."},
	{ID: "CVE-2021-22911", Severity: "High 8.1", Ports: []int{8080, 8443}, Keywords: []string{"node.js", "nodejs"}, AffectedBelow: "14.17.1", Description: "Node.js HTTP request smuggling risk in affected versions.", Research: "Check runtime version and reverse proxy behavior.", Recommendation: "Upgrade Node.js and normalize proxy request handling."},
	{ID: "CVE-2019-19774", Severity: "High 7.5", Ports: []int{8080, 8443}, Keywords: []string{"node.js", "nodejs"}, AffectedBelow: "12.14.1", Description: "Node.js HTTP header parsing issue in older versions.", Research: "Review Node.js security releases and service inventory.", Recommendation: "Upgrade Node.js to a supported patched release."},
	{ID: "CVE-2019-16278", Severity: "Critical 9.8", Ports: []int{80, 8080}, Keywords: []string{"nostromo"}, AffectedBelow: "1.9.6", Description: "Nostromo HTTPd remote command execution.", Research: "Check NVD and access logs for suspicious traversal patterns.", Recommendation: "Upgrade or retire Nostromo and restrict exposure."},
	{ID: "CVE-2014-6271", Severity: "Critical 9.8", Ports: []int{80, 443, 8080}, Keywords: []string{"cgi", "bash"}, Description: "Shellshock command injection in CGI/Bash environments.", Research: "Review CGI inventory, Bash package versions, and web logs.", Recommendation: "Patch Bash and remove unnecessary CGI handlers."},
	{ID: "CVE-2012-1823", Severity: "Critical 9.8", Ports: []int{80, 443, 8080}, Keywords: []string{"php-cgi", "php"}, AffectedBelow: "5.4.3", Description: "PHP-CGI query string argument injection in vulnerable configurations.", Research: "Check PHP SAPI and web server configuration.", Recommendation: "Patch PHP and avoid exposed php-cgi execution paths."},
	{ID: "CVE-2019-11043", Severity: "Critical 9.8", Ports: []int{80, 443, 8080}, Keywords: []string{"php-fpm", "nginx"}, Description: "PHP-FPM path info underflow RCE in vulnerable Nginx/PHP-FPM configurations.", Research: "Check NVD, PHP-FPM version, and fastcgi_split_path_info rules.", Recommendation: "Patch PHP-FPM and correct FastCGI path handling."},
	{ID: "CVE-2023-29489", Severity: "Critical 9.8", Ports: []int{80, 443}, Keywords: []string{"cpanel"}, Description: "cPanel XSS in exposed webmail interfaces in affected versions.", Research: "Check cPanel advisory and access logs.", Recommendation: "Patch cPanel and restrict administrative panels."},
	{ID: "CVE-2018-13379", Severity: "High 9.8", Ports: []int{443, 8443}, Keywords: []string{"fortinet", "fortigate", "fortios"}, Description: "Fortinet FortiOS SSL VPN path traversal exposing session files.", Research: "Review Fortinet advisories and VPN access logs for IOC paths.", Recommendation: "Patch FortiOS and rotate affected credentials."},
	{ID: "CVE-2023-27997", Severity: "Critical 9.2", Ports: []int{443, 8443}, Keywords: []string{"fortinet", "fortigate", "fortios"}, Description: "Fortinet FortiOS heap overflow in SSL VPN.", Research: "Check Fortinet advisory and VPN edge version.", Recommendation: "Upgrade FortiOS and restrict SSL VPN exposure."},
	{ID: "CVE-2022-40684", Severity: "Critical 9.8", Ports: []int{443, 8443}, Keywords: []string{"fortinet", "fortigate", "fortios"}, Description: "Fortinet administrative interface authentication bypass.", Research: "Review admin interface exposure and Fortinet IOC guidance.", Recommendation: "Patch and restrict management interfaces immediately."},
	{ID: "CVE-2024-21762", Severity: "Critical 9.6", Ports: []int{443, 8443}, Keywords: []string{"fortinet", "fortigate", "fortios"}, Description: "Fortinet FortiOS SSL VPN out-of-bounds write in affected versions.", Research: "Check Fortinet PSIRT guidance and SSL VPN logs.", Recommendation: "Upgrade FortiOS and apply vendor mitigations."},
	{ID: "CVE-2023-20198", Severity: "Critical 10.0", Ports: []int{80, 443}, Keywords: []string{"cisco ios xe", "web ui"}, Description: "Cisco IOS XE web UI privilege escalation on exposed management interfaces.", Research: "Validate Cisco advisory, management exposure, and created users.", Recommendation: "Patch IOS XE and disable web UI from untrusted networks."},
	{ID: "CVE-2023-20273", Severity: "High 7.2", Ports: []int{80, 443}, Keywords: []string{"cisco ios xe", "web ui"}, Description: "Cisco IOS XE web UI follow-up command injection in affected systems.", Research: "Check Cisco guidance and device integrity indicators.", Recommendation: "Patch and restrict management-plane access."},
	{ID: "CVE-2021-26084", Severity: "Critical 9.8", Ports: []int{80, 443, 8090}, Keywords: []string{"confluence"}, Description: "Atlassian Confluence OGNL injection RCE in affected versions.", Research: "Check Atlassian advisory and application logs for OGNL payloads.", Recommendation: "Upgrade Confluence and rotate secrets if compromise is suspected."},
	{ID: "CVE-2022-26134", Severity: "Critical 9.8", Ports: []int{80, 443, 8090}, Keywords: []string{"confluence"}, Description: "Atlassian Confluence OGNL injection RCE in affected versions.", Research: "Review Atlassian guidance and web logs for suspicious URI patterns.", Recommendation: "Patch Confluence and run vendor IOC checks."},
	{ID: "CVE-2023-22515", Severity: "Critical 10.0", Ports: []int{80, 443, 8090}, Keywords: []string{"confluence"}, Description: "Atlassian Confluence broken access control enabling administrator creation.", Research: "Inspect Confluence users and setup-related access logs.", Recommendation: "Patch immediately and audit administrative accounts."},
	{ID: "CVE-2023-22518", Severity: "Critical 9.1", Ports: []int{80, 443, 8090}, Keywords: []string{"confluence"}, Description: "Atlassian Confluence improper authorization leading to data loss risk.", Research: "Check Atlassian advisory and backup/restore endpoint logs.", Recommendation: "Patch and verify backup integrity."},
	{ID: "CVE-2019-11510", Severity: "Critical 10.0", Ports: []int{443, 8443}, Keywords: []string{"pulse secure"}, Description: "Pulse Secure VPN arbitrary file read in affected gateways.", Research: "Review vendor IOC guidance and VPN authentication logs.", Recommendation: "Patch, rotate credentials, and review sessions."},
	{ID: "CVE-2021-22893", Severity: "Critical 10.0", Ports: []int{443, 8443}, Keywords: []string{"pulse secure"}, Description: "Pulse Secure VPN authentication bypass/RCE chain exposure in affected versions.", Research: "Check Ivanti/Pulse advisories and appliance integrity tools.", Recommendation: "Patch and perform credential/session hygiene."},
	{ID: "CVE-2021-20016", Severity: "Critical 9.8", Ports: []int{80, 443}, Keywords: []string{"sonicwall"}, Description: "SonicWall SSLVPN SQL injection in affected SMA devices.", Research: "Check SonicWall advisory and VPN logs.", Recommendation: "Patch firmware and restrict management surfaces."},
	{ID: "CVE-2021-20038", Severity: "Critical 9.8", Ports: []int{80, 443}, Keywords: []string{"sonicwall"}, Description: "SonicWall SMA stack-based overflow in affected appliances.", Research: "Review SonicWall PSIRT and appliance logs.", Recommendation: "Patch SMA firmware and isolate remote access services."},
	{ID: "CVE-2022-1386", Severity: "High 7.8", Ports: []int{5432}, Keywords: []string{"postgres"}, AffectedBelow: "14.3", Description: "PostgreSQL privilege escalation and extension script risks in older supported branches.", Research: "Verify PostgreSQL minor release against vendor release notes.", Recommendation: "Upgrade to current minor releases and restrict extension installation."},
	{ID: "CVE-2021-32027", Severity: "High 8.8", Ports: []int{5432}, Keywords: []string{"postgres"}, AffectedBelow: "13.3", Description: "PostgreSQL memory disclosure risk in affected versions.", Research: "Check PostgreSQL security releases and database audit logs.", Recommendation: "Patch PostgreSQL and enforce TLS/authentication controls."},
	{ID: "CVE-2016-6662", Severity: "Critical 9.8", Ports: []int{3306}, Keywords: []string{"mysql", "mariadb"}, AffectedBelow: "5.7.15", Description: "MySQL/MariaDB configuration injection leading to code execution under specific privileges.", Research: "Check Oracle/MariaDB advisories and database user privileges.", Recommendation: "Patch database servers and limit FILE/SUPER-like privileges."},
	{ID: "CVE-2021-2307", Severity: "High 8.1", Ports: []int{3306}, Keywords: []string{"mysql"}, AffectedBelow: "8.0.26", Description: "MySQL Server vulnerabilities fixed in Oracle CPU updates.", Research: "Verify Oracle Critical Patch Update baseline.", Recommendation: "Upgrade MySQL and restrict network access."},
	{ID: "CVE-2022-0543", Severity: "Critical 10.0", Ports: []int{6379}, Keywords: []string{"redis"}, AffectedBelow: "5.0.14", Description: "Redis Lua sandbox escape in vulnerable Debian/Ubuntu packages.", Research: "Check distro package changelogs and Redis package origin.", Recommendation: "Patch Redis packages and prevent external access."},
	{ID: "CVE-2015-4335", Severity: "High 7.5", Ports: []int{6379}, Keywords: []string{"redis"}, AffectedBelow: "3.0.2", Description: "Redis Lua sandbox escape in older releases.", Research: "Verify Redis version and package backports.", Recommendation: "Upgrade Redis and require authentication/private bind."},
	{ID: "CVE-2019-11510", Severity: "Critical 10.0", Ports: []int{443}, Keywords: []string{"vpn"}, Description: "VPN gateway class exposure requires vendor-specific verification.", Research: "Use NVD/vendor bulletins for the exact product and version.", Recommendation: "Patch VPN appliances and rotate credentials after suspected exposure."},
	{ID: "CVE-2016-4971", Severity: "High 8.1", Ports: []int{11211}, Keywords: []string{"memcached"}, AffectedBelow: "1.4.33", Description: "Memcached UDP exposure can enable reflection/amplification and data exposure.", Research: "Check memcached version and UDP listener configuration.", Recommendation: "Disable UDP, bind privately, and upgrade."},
	{ID: "CVE-2018-1000115", Severity: "Critical 9.8", Ports: []int{11211}, Keywords: []string{"memcached"}, AffectedBelow: "1.5.6", Description: "Memcached slab item leakage in affected versions.", Research: "Review memcached release notes and exposure.", Recommendation: "Patch and restrict access to trusted hosts."},
	{ID: "CVE-2019-7609", Severity: "Critical 10.0", Ports: []int{5601}, Keywords: []string{"kibana"}, AffectedBelow: "6.6.1", Description: "Kibana Timelion prototype pollution leading to code execution in affected versions.", Research: "Verify Elastic advisory and Kibana logs.", Recommendation: "Upgrade Kibana and restrict administrative access."},
	{ID: "CVE-2015-1427", Severity: "Critical 9.8", Ports: []int{9200, 9300}, Keywords: []string{"elasticsearch"}, AffectedBelow: "1.4.3", Description: "Elasticsearch Groovy scripting sandbox bypass in older releases.", Research: "Check Elastic advisories and script settings.", Recommendation: "Upgrade Elasticsearch and disable unsafe dynamic scripting."},
	{ID: "CVE-2014-3120", Severity: "Critical 9.8", Ports: []int{9200, 9300}, Keywords: []string{"elasticsearch"}, AffectedBelow: "1.2.0", Description: "Elasticsearch dynamic scripting RCE in older exposed clusters.", Research: "Review Elastic guidance and cluster audit logs.", Recommendation: "Upgrade, disable dynamic scripts, and restrict cluster access."},
	{ID: "CVE-2020-9484", Severity: "High 7.0", Ports: []int{8080, 8443}, Keywords: []string{"tomcat"}, AffectedBelow: "9.0.35", Description: "Apache Tomcat session persistence deserialization risk under specific configuration.", Research: "Check Tomcat session persistence settings and version.", Recommendation: "Patch Tomcat and disable unsafe persistent session storage."},
	{ID: "CVE-2021-4178", Severity: "High 7.5", Ports: []int{1883, 8883}, Keywords: []string{"mosquitto", "mqtt"}, AffectedBelow: "2.0.15", Description: "Eclipse Mosquitto memory leak/DoS risk in older versions.", Research: "Check broker version and authentication exposure.", Recommendation: "Upgrade Mosquitto and require authenticated TLS."},
	{ID: "CVE-2020-13949", Severity: "High 7.5", Ports: []int{5672, 15672}, Keywords: []string{"rabbitmq"}, AffectedBelow: "3.8.9", Description: "RabbitMQ management plugin XSS and security fixes in older versions.", Research: "Review RabbitMQ release notes and management UI exposure.", Recommendation: "Upgrade RabbitMQ and restrict management UI."},
	{ID: "CVE-2021-4104", Severity: "High 7.5", Ports: []int{61616, 8161}, Keywords: []string{"activemq"}, Description: "Apache ActiveMQ unsafe deserialization risk in vulnerable configurations.", Research: "Verify ActiveMQ version and transport exposure.", Recommendation: "Patch ActiveMQ, restrict brokers, and disable unsafe object messages."},
	{ID: "CVE-2023-46604", Severity: "Critical 9.8", Ports: []int{61616, 8161}, Keywords: []string{"activemq"}, Description: "Apache ActiveMQ OpenWire remote code execution in affected versions.", Research: "Check Apache advisory and broker logs for suspicious OpenWire traffic.", Recommendation: "Upgrade ActiveMQ and isolate broker ports."},
	{ID: "CVE-2020-14882", Severity: "Critical 9.8", Ports: []int{7001, 7002}, Keywords: []string{"weblogic"}, Description: "Oracle WebLogic console authentication bypass in affected versions.", Research: "Check Oracle CPU advisory and admin console exposure.", Recommendation: "Apply CPU patches and restrict WebLogic console access."},
	{ID: "CVE-2020-14883", Severity: "Critical 7.2", Ports: []int{7001, 7002}, Keywords: []string{"weblogic"}, Description: "Oracle WebLogic authenticated RCE chain in affected versions.", Research: "Review Oracle CPU guidance and console logs.", Recommendation: "Patch WebLogic and minimize console exposure."},
}

func PortScanner() {
	utils.ClearTerminal()
	fmt.Printf("\n%s=== PORT SCANNER ===%s\n\n", utils.Blue, utils.Reset)

	reader := bufio.NewReader(os.Stdin)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	for {
		fmt.Printf("%s[1] Scan my own IP (auto-detect)%s\n", utils.Green, utils.Reset)
		fmt.Printf("%s[2] Scan specific IP + specific port%s\n", utils.Green, utils.Reset)
		fmt.Printf("%s[3] Scan specific IP + all ports (1-65535)%s\n", utils.Green, utils.Reset)
		fmt.Printf("%s[4] Fast scan (common important ports)%s\n", utils.Green, utils.Reset)
		fmt.Printf("%s[5] Advanced scan (Nmap-style safe flags)%s\n", utils.Green, utils.Reset)
		fmt.Printf("%s[6] Complete Mode (safe TCP full + UDP top ports)%s\n", utils.Green, utils.Reset)
		fmt.Printf("%s[7] Flags quick help%s\n", utils.Green, utils.Reset)
		utils.PrintReturnOption("8")
		fmt.Printf("\n%sTip: choose Flags quick help or type help in Advanced options.%s\n", utils.Yellow, utils.Reset)
		fmt.Printf("\n%sOption: %s", utils.Green, utils.Reset)

		option, _ := reader.ReadString('\n')
		option = strings.TrimSpace(option)

		switch option {
		case "1":
			localIP, err := detectLocalIPv4()
			if err != nil {
				fmt.Printf("%sCould not detect local IP: %v%s\n", utils.Red, err, utils.Reset)
				utils.WaitForEnter(reader)
				return
			}

			fmt.Printf("\n%sDetected local IP: %s%s\n", utils.Yellow, localIP, utils.Reset)
			results := runPortListScanWithOptions(ctx, localIP, expandPortRange(1, 65535), true, "local-ip-all", defaultPortScannerOptions())
			savePortResults(results)
			utils.ClearTerminal()
			displayPortResults(&results)
			utils.WaitForEnter(reader)
			return

		case "2":
			fmt.Printf("%sEnter target IP (Enter = my local IP): %s", utils.Green, utils.Reset)
			targetIP, _ := reader.ReadString('\n')
			targetIP = strings.TrimSpace(targetIP)
			if targetIP == "" {
				localIP, err := detectLocalIPv4()
				if err != nil {
					fmt.Printf("%sCould not detect local IP: %v%s\n", utils.Red, err, utils.Reset)
					utils.WaitForEnter(reader)
					return
				}
				targetIP = localIP
				fmt.Printf("%sUsing local IP: %s%s\n", utils.Yellow, targetIP, utils.Reset)
			}
			if !utils.IsValidIPv4(targetIP) {
				fmt.Printf("%sInvalid IPv4 address.%s\n", utils.Red, utils.Reset)
				utils.WaitForEnter(reader)
				return
			}

			fmt.Printf("%sEnter target port (1-65535): %s", utils.Green, utils.Reset)
			portStr, _ := reader.ReadString('\n')
			port, err := strconv.Atoi(strings.TrimSpace(portStr))
			if err != nil || port < 1 || port > 65535 {
				fmt.Printf("%sInvalid port. Must be between 1 and 65535.%s\n", utils.Red, utils.Reset)
				utils.WaitForEnter(reader)
				return
			}

			results := runPortListScanWithOptions(ctx, targetIP, []int{port}, false, "single-port", defaultPortScannerOptions())
			savePortResults(results)
			utils.ClearTerminal()
			displayPortResults(&results)
			utils.WaitForEnter(reader)
			return

		case "3":
			fmt.Printf("%sEnter target IP: %s", utils.Green, utils.Reset)
			targetIP, _ := reader.ReadString('\n')
			targetIP = strings.TrimSpace(targetIP)
			if !utils.IsValidIPv4(targetIP) {
				fmt.Printf("%sInvalid IPv4 address.%s\n", utils.Red, utils.Reset)
				utils.WaitForEnter(reader)
				return
			}

			results := runPortListScanWithOptions(ctx, targetIP, expandPortRange(1, 65535), true, "full-range", defaultPortScannerOptions())
			savePortResults(results)
			utils.ClearTerminal()
			displayPortResults(&results)
			utils.WaitForEnter(reader)
			return

		case "4":
			fmt.Printf("%sEnter target IP (Enter = my local IP): %s", utils.Green, utils.Reset)
			targetIP, _ := reader.ReadString('\n')
			targetIP = strings.TrimSpace(targetIP)
			if targetIP == "" {
				localIP, err := detectLocalIPv4()
				if err != nil {
					fmt.Printf("%sCould not detect local IP: %v%s\n", utils.Red, err, utils.Reset)
					utils.WaitForEnter(reader)
					return
				}
				targetIP = localIP
				fmt.Printf("%sUsing local IP: %s%s\n", utils.Yellow, targetIP, utils.Reset)
			}
			if !utils.IsValidIPv4(targetIP) {
				fmt.Printf("%sInvalid IPv4 address.%s\n", utils.Red, utils.Reset)
				utils.WaitForEnter(reader)
				return
			}

			results := runPortListScanWithOptions(ctx, targetIP, fastScanPorts, true, "fast-scan", defaultPortScannerOptions())
			savePortResults(results)
			utils.ClearTerminal()
			displayPortResults(&results)
			utils.WaitForEnter(reader)
			return

		case "5":
			targetIP, ports, opts, ok := promptAdvancedPortScan(reader)
			if !ok {
				utils.WaitForEnter(reader)
				return
			}
			results := runPortListScanWithOptions(ctx, targetIP, ports, true, "advanced", opts)
			savePortResults(results)
			utils.ClearTerminal()
			displayPortResults(&results)
			utils.WaitForEnter(reader)
			return

		case "6":
			targetIP, ok := promptCompletePortTarget(reader)
			if !ok {
				utils.WaitForEnter(reader)
				return
			}
			results := runCompletePortScan(ctx, targetIP)
			savePortResults(results)
			utils.ClearTerminal()
			displayPortResults(&results)
			utils.WaitForEnter(reader)
			return

		case "7":
			printPortScannerFlagHelp()
			utils.WaitForEnter(reader)
			return

		case "8":
			return

		default:
			fmt.Printf("%sInvalid option!%s\n\n", utils.Red, utils.Reset)
		}
	}
}

func promptAdvancedPortScan(reader *bufio.Reader) (string, []int, PortScannerOptions, bool) {
	fmt.Printf("%sEnter target IPv4: %s", utils.Green, utils.Reset)
	targetIP, _ := reader.ReadString('\n')
	targetIP = strings.TrimSpace(targetIP)
	if !utils.IsValidIPv4(targetIP) {
		fmt.Printf("%sInvalid IPv4 address.%s\n", utils.Red, utils.Reset)
		return "", nil, PortScannerOptions{}, false
	}

	fmt.Printf("%sPorts (Enter = top 100, examples: 22,80,443 | 1-1024 | all): %s", utils.Green, utils.Reset)
	portExpr, _ := reader.ReadString('\n')

	fmt.Printf("\n%sAdvanced options (Enter = defaults). Examples:%s\n", utils.Blue, utils.Reset)
	fmt.Printf("%s  -sT -sV -O -T4 --concurrency 512 --timeout 900ms --rate 1000/s --output-format grep%s\n", utils.Yellow, utils.Reset)
	fmt.Printf("%s  -sU --top-ports 50 --exclude-ports 53,123 --script default,vuln%s\n", utils.Yellow, utils.Reset)
	fmt.Printf("%s  Type help to show all common flags.%s\n", utils.Yellow, utils.Reset)
	fmt.Printf("%sOptions: %s", utils.Green, utils.Reset)
	rawOptions, _ := reader.ReadString('\n')
	if strings.EqualFold(strings.TrimSpace(rawOptions), "help") {
		printPortScannerFlagHelp()
		return promptAdvancedPortScan(reader)
	}

	opts := parsePortScannerOptions(rawOptions)
	ports := parsePortExpression(portExpr, opts)
	if len(ports) == 0 {
		fmt.Printf("%sNo valid ports selected.%s\n", utils.Red, utils.Reset)
		return "", nil, PortScannerOptions{}, false
	}

	return targetIP, ports, opts, true
}

func promptCompletePortTarget(reader *bufio.Reader) (string, bool) {
	fmt.Printf("%sEnter target IPv4 (Enter = my local IP): %s", utils.Green, utils.Reset)
	targetIP, _ := reader.ReadString('\n')
	targetIP = strings.TrimSpace(targetIP)
	if targetIP == "" {
		localIP, err := detectLocalIPv4()
		if err != nil {
			fmt.Printf("%sCould not detect local IP: %v%s\n", utils.Red, err, utils.Reset)
			return "", false
		}
		targetIP = localIP
		fmt.Printf("%sUsing local IP: %s%s\n", utils.Yellow, targetIP, utils.Reset)
	}
	if !utils.IsValidIPv4(targetIP) {
		fmt.Printf("%sInvalid IPv4 address.%s\n", utils.Red, utils.Reset)
		return "", false
	}
	return targetIP, true
}

func printPortScannerFlagHelp() {
	fmt.Printf("\n%sPort Scanner flags:%s\n", utils.Blue, utils.Reset)
	fmt.Printf("  -sT                   TCP connect scan.\n")
	fmt.Printf("  -sU                   UDP scan with safe protocol probes.\n")
	fmt.Printf("  -sV                   Enable service/version detection.\n")
	fmt.Printf("  -O                    Enable passive OS guess from services.\n")
	fmt.Printf("  -T0..-T5              Timing profile, from slow/careful to fast/aggressive.\n")
	fmt.Printf("  --concurrency 512     Number of parallel ports scanned.\n")
	fmt.Printf("  --timeout 900ms       Per-port timeout.\n")
	fmt.Printf("  --rate 1000/s         Maximum probes per second.\n")
	fmt.Printf("  --top-ports 100       Use ranked common ports when no port range is provided.\n")
	fmt.Printf("  --exclude-ports 80    Skip selected ports.\n")
	fmt.Printf("  --version-intensity 9 Number of service probes, 0-9.\n")
	fmt.Printf("  --script default,vuln Run passive built-in scripts.\n")
	fmt.Printf("  --output-format all   Extra output: json, xml, grep, or all.\n")
	fmt.Printf("  --log-level debug     Log level: debug, info, warn, error.\n")
	fmt.Printf("\n%sExample:%s -sT -sV -O -T4 --concurrency 768 --timeout 800ms --rate 2000/s --output-format all\n\n", utils.Yellow, utils.Reset)
}

func runCompletePortScan(ctx context.Context, targetIP string) PortScanResults {
	tcpOpts := completePortScannerOptions("tcp-connect")
	udpOpts := completePortScannerOptions("udp")
	tcpPorts := expandPortRange(1, 65535)
	udpPorts := selectTopPorts(100)

	type scanOut struct {
		results PortScanResults
	}

	start := time.Now()
	ch := make(chan scanOut, 2)
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		ch <- scanOut{results: runPortListScanWithOptions(ctx, targetIP, tcpPorts, false, "complete-tcp", tcpOpts)}
	}()

	go func() {
		defer wg.Done()
		ch <- scanOut{results: runPortListScanWithOptions(ctx, targetIP, udpPorts, false, "complete-udp", udpOpts)}
	}()

	wg.Wait()
	close(ch)

	var scans []PortScanResults
	for item := range ch {
		scans = append(scans, item.results)
	}

	return mergeCompletePortResults(targetIP, scans, time.Since(start))
}

func completePortScannerOptions(scanType string) PortScannerOptions {
	opts := defaultPortScannerOptions()
	opts.TimingTemplate = 4
	applyPortTimingTemplate(&opts)
	opts.ScanType = scanType
	opts.RequestedScan = scanType
	opts.VersionDetection = true
	opts.VersionIntensity = 8
	opts.OSDetection = true
	opts.OutputFormat = "all"
	opts.ScriptNames = []string{"default", "vuln"}
	opts.NoScripts = false
	opts.SafetyNotes = append(opts.SafetyNotes, "Complete Mode runs TCP connect across all ports plus UDP top ports with safe version detection, passive scripts, and output in JSON/XML/grep.")
	return opts
}

func mergeCompletePortResults(targetIP string, scans []PortScanResults, duration time.Duration) PortScanResults {
	merged := PortScanResults{
		TargetIP:         targetIP,
		TargetHostname:   reverseLookup(targetIP),
		ScanMode:         "complete",
		RequestedScan:    "tcp-connect+udp",
		OutputFormat:     "all",
		StartPort:        1,
		EndPort:          65535,
		TimingTemplate:   4,
		Concurrency:      768,
		TimeoutMS:        int64((800 * time.Millisecond).Milliseconds()),
		RateLimit:        2500,
		VersionIntensity: 8,
		ScannedAt:        time.Now(),
		ScanDuration:     duration.Seconds(),
	}

	safetyNotes := map[string]struct{}{}
	for _, scan := range scans {
		merged.Ports = append(merged.Ports, scan.Ports...)
		merged.TotalScanned += scan.TotalScanned
		merged.Open += scan.Open
		merged.Closed += scan.Closed
		merged.Filtered += scan.Filtered
		for _, note := range scan.SafetyNotes {
			safetyNotes[note] = struct{}{}
		}
	}
	for note := range safetyNotes {
		merged.SafetyNotes = append(merged.SafetyNotes, note)
	}
	sort.Strings(merged.SafetyNotes)
	sort.Slice(merged.Ports, func(i, j int) bool {
		if merged.Ports[i].Port == merged.Ports[j].Port {
			return merged.Ports[i].Protocol < merged.Ports[j].Protocol
		}
		return merged.Ports[i].Port < merged.Ports[j].Port
	})
	merged.OSGuess = inferHostOSFromOpenPorts(merged.Ports)
	return merged
}

func defaultPortScannerOptions() PortScannerOptions {
	return PortScannerOptions{
		ScanType:         "tcp-connect",
		RequestedScan:    "tcp-connect",
		Concurrency:      256,
		Timeout:          1200 * time.Millisecond,
		Retries:          0,
		RetryBackoff:     120 * time.Millisecond,
		RateLimit:        1200,
		TimingTemplate:   3,
		OutputFormat:     "json",
		VersionDetection: true,
		VersionIntensity: 5,
		OSDetection:      false,
		TopPorts:         100,
		ExcludePorts:     map[int]struct{}{},
		ScriptArgs:       map[string]string{},
		LogLevel:         slog.LevelWarn,
	}
}

func applyPortTimingTemplate(opts *PortScannerOptions) {
	switch clamp(opts.TimingTemplate, 0, 5) {
	case 0:
		opts.Concurrency = 1
		opts.Timeout = 6 * time.Second
		opts.Retries = 4
		opts.Delay = 5 * time.Second
		opts.RateLimit = 1
	case 1:
		opts.Concurrency = 8
		opts.Timeout = 4 * time.Second
		opts.Retries = 3
		opts.Delay = 1 * time.Second
		opts.RateLimit = 10
	case 2:
		opts.Concurrency = 64
		opts.Timeout = 2200 * time.Millisecond
		opts.Retries = 2
		opts.Delay = 100 * time.Millisecond
		opts.RateLimit = 100
	case 3:
		opts.Concurrency = 256
		opts.Timeout = 1200 * time.Millisecond
		opts.Retries = 0
		opts.Delay = 0
		opts.RateLimit = 1200
	case 4:
		opts.Concurrency = 768
		opts.Timeout = 800 * time.Millisecond
		opts.Retries = 0
		opts.Delay = 0
		opts.RateLimit = 2500
	case 5:
		opts.Concurrency = 1500
		opts.Timeout = 450 * time.Millisecond
		opts.Retries = 0
		opts.Delay = 0
		opts.RateLimit = 5000
	}
	opts.TimingTemplate = clamp(opts.TimingTemplate, 0, 5)
}

func parsePortScannerOptions(raw string) PortScannerOptions {
	base := defaultPortScannerOptions()
	raw = strings.TrimSpace(raw)
	if raw == "" {
		configurePortLogger(base.LogLevel)
		return base
	}

	var (
		scanType         = base.ScanType
		concurrency      = base.Concurrency
		timeout          = base.Timeout
		retries          = base.Retries
		rateRaw          = fmt.Sprintf("%d", base.RateLimit)
		timing           = base.TimingTemplate
		output           = base.OutputFormat
		topPorts         = base.TopPorts
		excludePorts     string
		versionIntensity = base.VersionIntensity
		scriptNames      string
		scriptArgs       string
		bandwidth        string
		sourcePort       int
		logLevel         = "warn"
		sT, sS, sU       bool
		sF, sX, sN       bool
		sA, sI           bool
		sV, osDetect     bool
		noScripts        bool
		badSum           bool
		dataLength       int
		decoy            string
		mtu              int
		spoofIP          string
	)

	fs := flag.NewFlagSet("portscanner", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&scanType, "scan-type", scanType, "")
	fs.BoolVar(&sT, "sT", false, "")
	fs.BoolVar(&sS, "sS", false, "")
	fs.BoolVar(&sU, "sU", false, "")
	fs.BoolVar(&sF, "sF", false, "")
	fs.BoolVar(&sX, "sX", false, "")
	fs.BoolVar(&sN, "sN", false, "")
	fs.BoolVar(&sA, "sA", false, "")
	fs.BoolVar(&sI, "sI", false, "")
	fs.BoolVar(&sV, "sV", false, "")
	fs.BoolVar(&osDetect, "O", false, "")
	fs.IntVar(&concurrency, "concurrency", concurrency, "")
	fs.DurationVar(&timeout, "timeout", timeout, "")
	fs.IntVar(&retries, "retries", retries, "")
	fs.StringVar(&rateRaw, "rate", rateRaw, "")
	fs.IntVar(&timing, "T", timing, "")
	fs.StringVar(&output, "output-format", output, "")
	fs.IntVar(&topPorts, "top-ports", topPorts, "")
	fs.StringVar(&excludePorts, "exclude-ports", "", "")
	fs.IntVar(&versionIntensity, "version-intensity", versionIntensity, "")
	fs.StringVar(&scriptNames, "script", "", "")
	fs.StringVar(&scriptArgs, "script-args", "", "")
	fs.BoolVar(&noScripts, "no-scripts", false, "")
	fs.StringVar(&bandwidth, "bandwidth", "", "")
	fs.IntVar(&sourcePort, "source-port", 0, "")
	fs.StringVar(&logLevel, "log-level", logLevel, "")
	fs.BoolVar(&badSum, "badsum", false, "")
	fs.IntVar(&dataLength, "data-length", 0, "")
	fs.StringVar(&decoy, "decoy", "", "")
	fs.IntVar(&mtu, "mtu", 0, "")
	fs.StringVar(&spoofIP, "spoof-ip", "", "")

	if err := fs.Parse(splitCLIFields(raw)); err != nil {
		portLogger.Warn("invalid port scanner options, using safe defaults", "error", err)
		configurePortLogger(base.LogLevel)
		return base
	}

	opts := base
	if timing != base.TimingTemplate {
		opts.TimingTemplate = timing
		applyPortTimingTemplate(&opts)
	}

	if sT {
		scanType = "tcp-connect"
	}
	if sU {
		scanType = "udp"
	}
	if sS {
		scanType = "syn"
	}
	if sF {
		scanType = "fin"
	}
	if sX {
		scanType = "xmas"
	}
	if sN {
		scanType = "null"
	}
	if sA {
		scanType = "ack"
	}
	if sI {
		scanType = "idle"
	}

	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "scan-type", "sT", "sS", "sU", "sF", "sX", "sN", "sA", "sI":
			opts.RequestedScan = scanType
			opts.ScanType = normalizeScanType(scanType, &opts)
		case "concurrency":
			opts.Concurrency = concurrency
		case "timeout":
			opts.Timeout = timeout
		case "retries":
			opts.Retries = retries
		case "rate":
			opts.RateLimit = parseRateLimit(rateRaw, opts.RateLimit)
		case "output-format":
			opts.OutputFormat = strings.ToLower(strings.TrimSpace(output))
		case "top-ports":
			opts.TopPorts = topPorts
		case "exclude-ports":
			opts.ExcludePorts = portsToSet(parsePorts(excludePorts))
		case "version-intensity":
			opts.VersionIntensity = versionIntensity
		case "sV":
			opts.VersionDetection = sV
		case "O":
			opts.OSDetection = osDetect
		case "script":
			opts.ScriptNames = parseStringList(scriptNames)
		case "script-args":
			opts.ScriptArgs = parseScriptArgs(scriptArgs)
		case "no-scripts":
			opts.NoScripts = noScripts
		case "bandwidth":
			opts.Bandwidth = strings.TrimSpace(bandwidth)
		case "source-port":
			opts.SourcePort = sourcePort
		case "log-level":
			opts.LogLevel = parseSlogLevel(logLevel)
		}
	})

	if opts.RequestedScan == "" {
		opts.RequestedScan = opts.ScanType
	}
	if opts.ScanType == "" {
		opts.ScanType = "tcp-connect"
	}
	if sV {
		opts.VersionDetection = true
	}
	if osDetect {
		opts.OSDetection = true
	}

	if badSum || dataLength > 0 || decoy != "" || mtu > 0 || spoofIP != "" {
		opts.SafetyNotes = append(opts.SafetyNotes, "Bad checksums, data padding, decoys, spoofing, and fragmentation flags were accepted for compatibility but not executed in this defensive scanner build.")
	}
	if opts.SourcePort > 0 && opts.Concurrency > 1 {
		opts.SafetyNotes = append(opts.SafetyNotes, "A fixed source port can conflict under concurrency; reduce --concurrency to 1 if the operating system rejects binds.")
	}

	opts.Concurrency = clamp(opts.Concurrency, 1, 4096)
	opts.Retries = clamp(opts.Retries, 0, 10)
	opts.VersionIntensity = clamp(opts.VersionIntensity, 0, 9)
	opts.TopPorts = clamp(opts.TopPorts, 0, len(topPortsRanked))
	opts.SourcePort = clamp(opts.SourcePort, 0, 65535)
	if opts.Timeout < 100*time.Millisecond {
		opts.Timeout = 100 * time.Millisecond
	}
	if opts.OutputFormat != "json" && opts.OutputFormat != "xml" && opts.OutputFormat != "grep" && opts.OutputFormat != "all" {
		opts.OutputFormat = "json"
	}

	configurePortLogger(opts.LogLevel)
	return opts
}

func normalizeScanType(scanType string, opts *PortScannerOptions) string {
	normalized := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(scanType), "-"))
	switch normalized {
	case "st", "tcp", "connect", "tcp-connect":
		return "tcp-connect"
	case "su", "udp":
		return "udp"
	case "ss", "syn", "sf", "fin", "sx", "xmas", "sn", "null", "sa", "ack", "si", "idle":
		opts.SafetyNotes = append(opts.SafetyNotes, "Requested raw or stealth scan mode "+scanType+" was not executed; the scanner used TCP connect or UDP only.")
		return "tcp-connect"
	default:
		return "tcp-connect"
	}
}

func configurePortLogger(level slog.Level) {
	portLogger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}

func ViewPortScanResults() {
	utils.ClearTerminal()
	fmt.Printf("\n%s=== PORT SCAN RESULTS ===%s\n\n", utils.Blue, utils.Reset)

	results, err := loadPortResults()
	if err != nil {
		fmt.Printf("%sNo port scan results found. Run a scan first!%s\n", utils.Red, utils.Reset)
		reader := bufio.NewReader(os.Stdin)
		utils.WaitForEnter(reader)
		return
	}

	displayPortResults(results)

	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("\n%sOptions:%s\n", utils.Blue, utils.Reset)
	fmt.Printf("%s[1] Refresh scan (re-scan same IP/ports)%s\n", utils.Green, utils.Reset)
	fmt.Printf("%s[2] Delete results%s\n", utils.Red, utils.Reset)
	fmt.Printf("%s[3] Return to menu%s\n", utils.Yellow, utils.Reset)
	fmt.Printf("\n%sChoose option: %s", utils.Green, utils.Reset)

	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	switch input {
	case "1":
		refreshPortResults(results)
	case "2":
		deletePortResults()
	case "3":
		return
	default:
		fmt.Printf("%sInvalid option!%s\n", utils.Red, utils.Reset)
		time.Sleep(2 * time.Second)
	}
}

func runPortScan(targetIP string, startPort, endPort int, showProgress bool, scanMode string) PortScanResults {
	if startPort < 1 {
		startPort = 1
	}
	if endPort > 65535 {
		endPort = 65535
	}
	if startPort > endPort {
		startPort, endPort = endPort, startPort
	}

	return runPortListScan(targetIP, expandPortRange(startPort, endPort), showProgress, scanMode)
}

func runPortListScan(targetIP string, ports []int, showProgress bool, scanMode string) PortScanResults {
	return runPortListScanWithOptions(context.Background(), targetIP, ports, showProgress, scanMode, defaultPortScannerOptions())
}

func runPortListScanWithOptions(ctx context.Context, targetIP string, ports []int, showProgress bool, scanMode string, opts PortScannerOptions) PortScanResults {
	ports = normalizePorts(ports, opts.ExcludePorts)
	total := len(ports)
	if total == 0 {
		return PortScanResults{
			TargetIP:         targetIP,
			TotalScanned:     0,
			ScanDuration:     0,
			ScannedAt:        time.Now(),
			Ports:            []PortInfo{},
			ScanMode:         scanMode,
			RequestedScan:    opts.RequestedScan,
			OutputFormat:     opts.OutputFormat,
			TimingTemplate:   opts.TimingTemplate,
			Concurrency:      opts.Concurrency,
			TimeoutMS:        opts.Timeout.Milliseconds(),
			RateLimit:        opts.RateLimit,
			VersionIntensity: opts.VersionIntensity,
			SafetyNotes:      opts.SafetyNotes,
		}
	}

	startPort := ports[0]
	endPort := ports[len(ports)-1]
	hostname := reverseLookup(targetIP)

	fmt.Printf("\n%sScanning %s on %s (%d ports, scan=%s, T%d)...%s\n\n",
		utils.Yellow, scanMode, targetIP, total, opts.ScanType, opts.TimingTemplate, utils.Reset)

	startTime := time.Now()
	resultsCh := make(chan PortInfo, minInt(total, opts.Concurrency*2))
	semaphore := make(chan struct{}, opts.Concurrency)
	limiter := newSimpleRateLimiter(opts.RateLimit)
	defer limiter.Stop()

	var wg sync.WaitGroup
	var completed int64
	var doneProgress chan struct{}

	if showProgress {
		doneProgress = make(chan struct{})
		go func() {
			ticker := time.NewTicker(2 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-doneProgress:
					return
				case <-ticker.C:
					done := int(atomic.LoadInt64(&completed))
					elapsed := time.Since(startTime).Seconds()
					rate := 0.0
					if elapsed > 0 {
						rate = float64(done) / elapsed
					}
					remaining := 0.0
					if rate > 0 {
						remaining = float64(total-done) / rate
					}
					fmt.Printf("%s[Progress] %d/%d (%.1f%%) | rate %.1f p/s | ETA %.0fs%s\n",
						utils.Blue, done, total, percent(done, total), rate, math.Max(0, remaining), utils.Reset)
				}
			}
		}()
	}

	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()

			select {
			case semaphore <- struct{}{}:
				defer func() { <-semaphore }()
			case <-ctx.Done():
				resultsCh <- cancelledPortInfo(p, opts.ScanType)
				atomic.AddInt64(&completed, 1)
				return
			}

			if opts.Delay > 0 {
				if err := sleepContext(ctx, opts.Delay); err != nil {
					resultsCh <- cancelledPortInfo(p, opts.ScanType)
					atomic.AddInt64(&completed, 1)
					return
				}
			}

			if err := limiter.Wait(ctx); err != nil {
				resultsCh <- cancelledPortInfo(p, opts.ScanType)
				atomic.AddInt64(&completed, 1)
				return
			}

			resultsCh <- scanSinglePortWithOptions(ctx, targetIP, p, opts)
			atomic.AddInt64(&completed, 1)
		}(port)
	}

	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	resultPorts := make([]PortInfo, 0, total)
	for portInfo := range resultsCh {
		resultPorts = append(resultPorts, portInfo)
	}

	if doneProgress != nil {
		close(doneProgress)
	}

	sort.Slice(resultPorts, func(i, j int) bool {
		return resultPorts[i].Port < resultPorts[j].Port
	})

	openCount, closedCount, filteredCount := countPortStates(resultPorts)
	duration := time.Since(startTime).Seconds()

	return PortScanResults{
		TargetIP:         targetIP,
		TargetHostname:   hostname,
		TotalScanned:     total,
		Open:             openCount,
		Closed:           closedCount,
		Filtered:         filteredCount,
		ScanDuration:     duration,
		ScannedAt:        time.Now(),
		Ports:            resultPorts,
		ScanMode:         scanMode,
		RequestedScan:    opts.RequestedScan,
		OutputFormat:     opts.OutputFormat,
		StartPort:        startPort,
		EndPort:          endPort,
		TimingTemplate:   opts.TimingTemplate,
		Concurrency:      opts.Concurrency,
		TimeoutMS:        opts.Timeout.Milliseconds(),
		RateLimit:        opts.RateLimit,
		VersionIntensity: opts.VersionIntensity,
		OSGuess:          inferHostOSFromOpenPorts(resultPorts),
		SafetyNotes:      opts.SafetyNotes,
	}
}

func scanSinglePort(targetIP string, port int) PortInfo {
	return scanSinglePortWithOptions(context.Background(), targetIP, port, defaultPortScannerOptions())
}

func scanSinglePortWithOptions(ctx context.Context, targetIP string, port int, opts PortScannerOptions) PortInfo {
	if opts.ScanType == "udp" {
		return scanSingleUDPPort(ctx, targetIP, port, opts)
	}
	return scanSingleTCPPort(ctx, targetIP, port, opts)
}

func scanSingleTCPPort(ctx context.Context, targetIP string, port int, opts PortScannerOptions) PortInfo {
	info := PortInfo{
		Port:        port,
		Protocol:    "tcp",
		Status:      "closed",
		Reason:      "no-response",
		Service:     detectService(port),
		LastScanned: time.Now(),
	}

	address := net.JoinHostPort(targetIP, strconv.Itoa(port))
	var lastErr error
	for attempt := 0; attempt <= opts.Retries; attempt++ {
		dialer := net.Dialer{Timeout: opts.Timeout}
		if opts.SourcePort > 0 {
			dialer.LocalAddr = &net.TCPAddr{Port: opts.SourcePort}
		}
		conn, err := dialer.DialContext(ctx, "tcp", address)
		if err == nil {
			defer conn.Close()

			info.Status = "open"
			info.Reason = "connect"
			if opts.VersionDetection {
				fingerprint := grabServiceFingerprint(ctx, targetIP, conn, port, info.Service, opts)
				info.Banner = fingerprint.Banner
				info.Version = fingerprint.Version
				info.Product = fingerprint.Product
				info.ExtraInfo = fingerprint.ExtraInfo
				info.TLSCertificate = fingerprint.TLSCertificate
				info.Service = inferServiceFrom(info.Service, info.Banner+" "+info.Product)
				if info.Version == "" {
					info.Version = extractVersion(info.Banner + " " + info.Product)
				}
			}
			if opts.OSDetection {
				info.OSGuess = inferOSFromPortSignals(info)
			}
			info.Vulnerabilities = detectPortVulnerabilities(port, info.Service, info.Version, info.Banner+" "+info.Product+" "+info.ExtraInfo)
			if !opts.NoScripts {
				info.Scripts = runScripts(ctx, targetIP, info, opts)
			}
			return info
		}
		lastErr = err
		if ctx.Err() != nil {
			info.Status = "filtered"
			info.Reason = "cancelled"
			return info
		}
		sleepBackoff(ctx, opts.RetryBackoff, attempt)
	}

	info.Status, info.Reason = classifyTCPError(lastErr)
	return info
}

func scanSingleUDPPort(ctx context.Context, targetIP string, port int, opts PortScannerOptions) PortInfo {
	info := PortInfo{
		Port:        port,
		Protocol:    "udp",
		Status:      "open|filtered",
		Reason:      "udp-no-response",
		Service:     detectService(port),
		LastScanned: time.Now(),
	}

	address := net.JoinHostPort(targetIP, strconv.Itoa(port))
	conn, err := net.DialTimeout("udp", address, opts.Timeout)
	if err != nil {
		info.Status = "filtered"
		info.Reason = sanitizeErrorReason(err)
		return info
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(opts.Timeout))
	_, _ = conn.Write(udpProbe(port, info.Service, opts.VersionIntensity))

	ptr := bannerBufferPool.Get().(*[]byte)
	buffer := *ptr
	defer bannerBufferPool.Put(ptr)

	n, err := conn.Read(buffer)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "refused") {
			info.Status = "closed"
			info.Reason = "icmp-port-unreachable"
		}
		return info
	}

	info.Status = "open"
	info.Reason = "udp-response"
	info.Banner = sanitize(buffer[:n])
	info.Version = extractVersion(info.Banner)
	info.Service = inferServiceFrom(info.Service, info.Banner)
	info.Product = productFromBanner(info.Service, info.Banner)
	info.Vulnerabilities = detectPortVulnerabilities(port, info.Service, info.Version, info.Banner+" "+info.Product)
	if !opts.NoScripts {
		info.Scripts = runScripts(ctx, targetIP, info, opts)
	}
	return info
}

type serviceFingerprint struct {
	Banner         string
	Version        string
	Product        string
	ExtraInfo      string
	TLSCertificate string
}

func grabServiceFingerprint(ctx context.Context, targetIP string, conn net.Conn, port int, baseService string, opts PortScannerOptions) serviceFingerprint {
	if isLikelyTLSService(port, baseService) {
		fp := grabTLSFingerprint(ctx, targetIP, port, opts)
		if fp.Banner != "" || fp.TLSCertificate != "" {
			return fp
		}
	}

	ptr := bannerBufferPool.Get().(*[]byte)
	buffer := *ptr
	defer bannerBufferPool.Put(ptr)

	var banner string
	probes := serviceProbes(port, baseService, opts.VersionIntensity)
	if len(probes) == 0 {
		_ = conn.SetDeadline(time.Now().Add(minDuration(opts.Timeout, 1500*time.Millisecond)))
		if n, _ := conn.Read(buffer); n > 0 {
			banner = sanitize(buffer[:n])
		}
	}

	for _, probe := range probes {
		if banner != "" {
			break
		}
		_ = conn.SetDeadline(time.Now().Add(opts.Timeout))
		_, _ = conn.Write([]byte(probe))
		n, _ := conn.Read(buffer)
		if n > 0 {
			banner = sanitize(buffer[:n])
		}
	}

	version := extractVersion(banner)
	product := productFromBanner(baseService, banner)
	return serviceFingerprint{
		Banner:  banner,
		Version: version,
		Product: product,
	}
}

func grabAndFingerprint(conn net.Conn, port int, baseService string) (string, string) {
	opts := defaultPortScannerOptions()
	fp := grabServiceFingerprint(context.Background(), "target", conn, port, baseService, opts)
	return fp.Banner, fp.Version
}

func grabTLSFingerprint(ctx context.Context, targetIP string, port int, opts PortScannerOptions) serviceFingerprint {
	address := net.JoinHostPort(targetIP, strconv.Itoa(port))
	serverName := ""
	if net.ParseIP(targetIP) == nil {
		serverName = targetIP
	}

	dialer := tls.Dialer{
		NetDialer: &net.Dialer{Timeout: opts.Timeout},
		Config: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         serverName,
			MinVersion:         tls.VersionTLS10,
		},
	}

	rawConn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return serviceFingerprint{}
	}
	defer rawConn.Close()

	tlsConn, ok := rawConn.(*tls.Conn)
	if !ok {
		return serviceFingerprint{}
	}

	state := tlsConn.ConnectionState()
	certInfo := formatCertificateFromState(state)

	ptr := bannerBufferPool.Get().(*[]byte)
	buffer := *ptr
	defer bannerBufferPool.Put(ptr)

	hostHeader := targetIP
	if serverName != "" {
		hostHeader = serverName
	}
	probe := fmt.Sprintf("HEAD / HTTP/1.1\r\nHost: %s\r\nUser-Agent: ECLIPSEScanner/1.0\r\nConnection: close\r\n\r\n", hostHeader)
	_ = tlsConn.SetDeadline(time.Now().Add(opts.Timeout))
	_, _ = tlsConn.Write([]byte(probe))
	n, _ := tlsConn.Read(buffer)

	banner := ""
	if n > 0 {
		banner = sanitize(buffer[:n])
	}

	extra := fmt.Sprintf("tls=%s cipher=0x%04x alpn=%s", tlsVersionName(state.Version), state.CipherSuite, defaultIfEmpty(state.NegotiatedProtocol, "none"))
	return serviceFingerprint{
		Banner:         banner,
		Version:        extractVersion(banner),
		Product:        productFromBanner("HTTPS", banner),
		ExtraInfo:      extra,
		TLSCertificate: certInfo,
	}
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return "unknown"
	}
}

func serviceProbes(port int, service string, intensity int) []string {
	lower := strings.ToLower(service)
	host := "target"
	var probes []string

	if port == 80 || port == 8080 || port == 8000 || strings.Contains(lower, "http") {
		probes = append(probes,
			fmt.Sprintf("HEAD / HTTP/1.1\r\nHost: %s\r\nUser-Agent: ECLIPSEScanner/1.0\r\nConnection: close\r\n\r\n", host),
			fmt.Sprintf("OPTIONS / HTTP/1.1\r\nHost: %s\r\nUser-Agent: ECLIPSEScanner/1.0\r\nConnection: close\r\n\r\n", host),
		)
	}
	if port == 25 || port == 587 || strings.Contains(lower, "smtp") {
		probes = append(probes, "EHLO scanner.local\r\n")
	}
	if port == 21 || strings.Contains(lower, "ftp") {
		probes = append(probes, "FEAT\r\n", "SYST\r\n")
	}
	if port == 110 || strings.Contains(lower, "pop3") {
		probes = append(probes, "CAPA\r\n")
	}
	if port == 143 || strings.Contains(lower, "imap") {
		probes = append(probes, "a001 CAPABILITY\r\n")
	}
	if port == 6379 || strings.Contains(lower, "redis") {
		probes = append(probes, "PING\r\n", "INFO server\r\n")
	}
	if port == 11211 || strings.Contains(lower, "memcached") {
		probes = append(probes, "version\r\n")
	}
	if intensity >= 7 {
		probes = append(probes, "\r\n", "HELP\r\n")
	}
	return dedupeStrings(probes)
}

func serviceProbe(port int, service string) string {
	probes := serviceProbes(port, service, 5)
	if len(probes) == 0 {
		return ""
	}
	return probes[0]
}

func udpProbe(port int, service string, intensity int) []byte {
	switch port {
	case 53:
		return []byte{0x43, 0x21, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01}
	case 123:
		packet := make([]byte, 48)
		packet[0] = 0x1b
		return packet
	case 161:
		return []byte{0x30, 0x26, 0x02, 0x01, 0x01, 0x04, 0x06, 'p', 'u', 'b', 'l', 'i', 'c', 0xa0, 0x19, 0x02, 0x04, 0x70, 0x77, 0x6e, 0x64, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0b, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x05, 0x00}
	default:
		if intensity >= 7 {
			return []byte("\r\n")
		}
		return []byte{0}
	}
}

func isLikelyTLSService(port int, service string) bool {
	lower := strings.ToLower(service)
	return port == 443 || port == 8443 || port == 993 || port == 995 || port == 465 || port == 636 || strings.Contains(lower, "https") || strings.Contains(lower, "tls") || strings.Contains(lower, "ssl")
}

func detectService(port int) string {
	if svc, ok := commonPortServices[port]; ok {
		return svc
	}
	return "Unknown"
}

func sanitize(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}

	clean := strings.Map(func(r rune) rune {
		if r >= 32 && r <= 126 || r == '\n' || r == '\r' || r == '\t' {
			return r
		}
		return -1
	}, string(raw))

	clean = strings.ReplaceAll(clean, "\r\n", "\n")
	clean = strings.ReplaceAll(clean, "\r", "\n")
	clean = strings.TrimSpace(clean)
	if clean == "" {
		return ""
	}

	lines := strings.Split(clean, "\n")
	kept := make([]string, 0, minInt(len(lines), 8))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		kept = append(kept, line)
		if len(kept) >= 8 {
			break
		}
	}
	out := strings.Join(kept, " | ")
	if len(out) > 1200 {
		out = out[:1200]
	}
	return out
}

func extractVersion(banner string) string {
	if banner == "" {
		return ""
	}

	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)OpenSSH[_/ -]?([0-9]+(?:\.[0-9]+){0,3})`),
		regexp.MustCompile(`(?i)Apache(?:/| httpd/| )?([0-9]+(?:\.[0-9]+){0,3})`),
		regexp.MustCompile(`(?i)nginx/?([0-9]+(?:\.[0-9]+){0,3})`),
		regexp.MustCompile(`(?i)Microsoft-IIS/?([0-9]+(?:\.[0-9]+){0,3})`),
		regexp.MustCompile(`(?i)Tomcat/?([0-9]+(?:\.[0-9]+){0,3})`),
		regexp.MustCompile(`(?i)Jetty[(/ -]?([0-9]+(?:\.[0-9]+){0,3})`),
		regexp.MustCompile(`(?i)PostgreSQL[ /-]?([0-9]+(?:\.[0-9]+){0,3})`),
		regexp.MustCompile(`(?i)MySQL[ /-]?([0-9]+(?:\.[0-9]+){0,3})`),
		regexp.MustCompile(`(?i)MariaDB[ /-]?([0-9]+(?:\.[0-9]+){0,3})`),
		regexp.MustCompile(`(?i)Redis server v=?([0-9]+(?:\.[0-9]+){0,3})`),
		regexp.MustCompile(`(?i)MongoDB[ /-]?([0-9]+(?:\.[0-9]+){0,3})`),
		regexp.MustCompile(`(?i)RabbitMQ[ /-]?([0-9]+(?:\.[0-9]+){0,3})`),
		regexp.MustCompile(`(?i)OpenSSL/?([0-9]+(?:\.[0-9]+){0,3}[a-z]?)`),
		regexp.MustCompile(`(?i)(?:Server|X-Powered-By): [^0-9|]*([0-9]+(?:\.[0-9]+){1,3})`),
		regexp.MustCompile(`(?i)\b([0-9]+(?:\.[0-9]+){1,3}[a-z]?)\b`),
	}

	for _, re := range patterns {
		match := re.FindStringSubmatch(banner)
		if len(match) > 1 {
			return match[1]
		}
	}

	return ""
}

func productFromBanner(service, banner string) string {
	text := strings.ToLower(service + " " + banner)
	switch {
	case strings.Contains(text, "openssh"):
		return "OpenSSH"
	case strings.Contains(text, "apache"):
		return "Apache httpd"
	case strings.Contains(text, "nginx"):
		return "Nginx"
	case strings.Contains(text, "microsoft-iis"):
		return "Microsoft IIS"
	case strings.Contains(text, "tomcat"):
		return "Apache Tomcat"
	case strings.Contains(text, "jetty"):
		return "Eclipse Jetty"
	case strings.Contains(text, "mysql"):
		return "MySQL"
	case strings.Contains(text, "mariadb"):
		return "MariaDB"
	case strings.Contains(text, "postgres"):
		return "PostgreSQL"
	case strings.Contains(text, "redis"):
		return "Redis"
	case strings.Contains(text, "mongodb"):
		return "MongoDB"
	case strings.Contains(text, "rabbitmq"):
		return "RabbitMQ"
	case strings.Contains(text, "elasticsearch"):
		return "Elasticsearch"
	case strings.Contains(text, "kibana"):
		return "Kibana"
	default:
		return strings.TrimSpace(service)
	}
}

func detectPortVulnerabilities(port int, service, version, banner string) []string {
	var vulns []string
	serviceLower := strings.ToLower(service + " " + banner)

	if port == 23 || strings.Contains(serviceLower, "telnet") {
		vulns = append(vulns, cveDatabase["telnet"]...)
	}
	if port == 21 || strings.Contains(serviceLower, "ftp") {
		vulns = append(vulns, cveDatabase["ftp"]...)
	}
	if port == 3306 || strings.Contains(serviceLower, "mysql") || strings.Contains(serviceLower, "mariadb") {
		vulns = append(vulns, cveDatabase["mysql"]...)
	}
	if port == 445 || strings.Contains(serviceLower, "smb") {
		vulns = append(vulns, cveDatabase["smb"]...)
	}
	if port == 3389 || strings.Contains(serviceLower, "rdp") {
		vulns = append(vulns, cveDatabase["rdp"]...)
	}
	if port == 6379 || strings.Contains(serviceLower, "redis") {
		vulns = append(vulns, cveDatabase["redis"]...)
	}
	if port == 27017 || strings.Contains(serviceLower, "mongodb") {
		vulns = append(vulns, cveDatabase["mongodb"]...)
	}
	if port == 25 || strings.Contains(serviceLower, "smtp") {
		vulns = append(vulns, cveDatabase["smtp"]...)
	}
	if port == 110 || port == 143 || strings.Contains(serviceLower, "pop3") || strings.Contains(serviceLower, "imap") {
		vulns = append(vulns, cveDatabase["imap_pop3"]...)
	}
	if port == 80 || port == 8080 || port == 443 || strings.Contains(serviceLower, "http") {
		vulns = append(vulns, cveDatabase["http"]...)
	}
	if isDatabasePort(port) {
		vulns = append(vulns, cveDatabase["database"]...)
	}

	for _, rule := range vulnerabilityCatalog {
		if !vulnerabilityRuleMatches(rule, port, serviceLower) {
			continue
		}
		if rule.AffectedBelow != "" {
			ruleVersion := version
			if ruleVersion == "" {
				ruleVersion = extractVersionFromText(serviceLower, `([0-9]+(?:\.[0-9]+){1,3}[a-z]?)`)
			}
			if ruleVersion == "" || compareSemanticVersion(ruleVersion, rule.AffectedBelow) >= 0 {
				continue
			}
		}
		vulns = append(vulns, formatVulnerability(rule))
	}

	return dedupeStrings(vulns)
}

func vulnerabilityRuleMatches(rule VulnerabilityRule, port int, text string) bool {
	portMatch := len(rule.Ports) == 0
	for _, candidate := range rule.Ports {
		if candidate == port {
			portMatch = true
			break
		}
	}
	if !portMatch {
		return false
	}
	if len(rule.Keywords) == 0 {
		return true
	}
	for _, keyword := range rule.Keywords {
		if strings.Contains(text, strings.ToLower(keyword)) {
			return true
		}
	}
	return false
}

func formatVulnerability(rule VulnerabilityRule) string {
	parts := []string{
		fmt.Sprintf("%s [%s]: %s", rule.ID, rule.Severity, rule.Description),
		"Research: " + rule.Research,
		"Recommendation: " + rule.Recommendation,
	}
	return strings.Join(parts, " ")
}

func isDatabasePort(port int) bool {
	switch port {
	case 1433, 1521, 2483, 2484, 3306, 5432, 6379, 9042, 9200, 9300, 11211, 27017, 27018, 27019, 50000:
		return true
	default:
		return false
	}
}

func inferServiceFrom(currentService, banner string) string {
	if strings.TrimSpace(banner) == "" {
		return currentService
	}

	lb := strings.ToLower(banner)
	switch {
	case strings.Contains(lb, "openssh") || strings.HasPrefix(lb, "ssh-"):
		return "SSH"
	case strings.Contains(lb, "apache"):
		return "HTTP (Apache)"
	case strings.Contains(lb, "nginx"):
		return "HTTP (Nginx)"
	case strings.Contains(lb, "microsoft-iis"):
		return "HTTP (Microsoft IIS)"
	case strings.Contains(lb, "tomcat"):
		return "HTTP (Tomcat)"
	case strings.Contains(lb, "jetty"):
		return "HTTP (Jetty)"
	case strings.Contains(lb, "mysql"):
		return "MySQL"
	case strings.Contains(lb, "mariadb"):
		return "MariaDB"
	case strings.Contains(lb, "postgres"):
		return "PostgreSQL"
	case strings.Contains(lb, "redis"):
		return "Redis"
	case strings.Contains(lb, "mongodb"):
		return "MongoDB"
	case strings.Contains(lb, "smtp"):
		return "SMTP"
	case strings.Contains(lb, "pop3"):
		return "POP3"
	case strings.Contains(lb, "imap"):
		return "IMAP"
	case strings.Contains(lb, "elasticsearch"):
		return "Elasticsearch"
	case strings.Contains(lb, "kibana"):
		return "Kibana"
	case strings.Contains(lb, "rabbitmq"):
		return "RabbitMQ"
	case strings.Contains(lb, "memcached"):
		return "Memcached"
	default:
		return currentService
	}
}

func extractVersionFromText(text, pattern string) string {
	re := regexp.MustCompile(pattern)
	match := re.FindStringSubmatch(text)
	if len(match) > 1 {
		return match[1]
	}
	return ""
}

func compareSemanticVersion(a, b string) int {
	parse := func(v string) []int {
		parts := strings.Split(v, ".")
		out := make([]int, 0, len(parts))
		for _, p := range parts {
			numeric := regexp.MustCompile(`^\d+`).FindString(p)
			if numeric == "" {
				out = append(out, 0)
				continue
			}
			n, err := strconv.Atoi(numeric)
			if err != nil {
				out = append(out, 0)
				continue
			}
			out = append(out, n)
		}
		return out
	}

	av := parse(a)
	bv := parse(b)
	maxLen := len(av)
	if len(bv) > maxLen {
		maxLen = len(bv)
	}

	for len(av) < maxLen {
		av = append(av, 0)
	}
	for len(bv) < maxLen {
		bv = append(bv, 0)
	}

	for i := 0; i < maxLen; i++ {
		if av[i] < bv[i] {
			return -1
		}
		if av[i] > bv[i] {
			return 1
		}
	}
	return 0
}

func runScripts(ctx context.Context, targetIP string, info PortInfo, opts PortScannerOptions) []PortScriptResult {
	available := []PortScriptResult{
		passiveServiceScript(info),
		cleartextProtocolScript(info),
		databaseExposureScript(info),
		tlsCertificateScript(info),
		httpSecurityHeaderScript(ctx, targetIP, info, opts),
	}

	filter := map[string]struct{}{}
	for _, name := range opts.ScriptNames {
		if name == "default" || name == "safe" || name == "vuln" {
			return compactScripts(available)
		}
		filter[name] = struct{}{}
	}
	if len(filter) == 0 {
		return compactScripts(available)
	}

	var selected []PortScriptResult
	for _, script := range available {
		if _, ok := filter[script.Name]; ok {
			selected = append(selected, script)
		}
	}
	return compactScripts(selected)
}

func passiveServiceScript(info PortInfo) PortScriptResult {
	return PortScriptResult{
		Name:     "service-summary",
		Status:   "ok",
		Severity: "info",
		Output:   fmt.Sprintf("%s/%s service=%s product=%s version=%s", strconv.Itoa(info.Port), info.Protocol, portFieldOrNA(info.Service), portFieldOrNA(info.Product), portFieldOrNA(info.Version)),
	}
}

func cleartextProtocolScript(info PortInfo) PortScriptResult {
	service := strings.ToLower(info.Service + " " + info.Banner)
	if info.Port == 21 || info.Port == 23 || strings.Contains(service, "telnet") || strings.Contains(service, "ftp") {
		return PortScriptResult{
			Name:     "cleartext-auth-review",
			Status:   "review",
			Severity: "medium",
			Output:   "cleartext management or file-transfer protocol detected; prefer encrypted alternatives and source restrictions",
		}
	}
	return PortScriptResult{}
}

func databaseExposureScript(info PortInfo) PortScriptResult {
	if isDatabasePort(info.Port) {
		return PortScriptResult{
			Name:     "database-exposure",
			Status:   "review",
			Severity: "high",
			Output:   "database-style listener detected; verify private binding, TLS, authentication, and network ACLs",
		}
	}
	return PortScriptResult{}
}

func tlsCertificateScript(info PortInfo) PortScriptResult {
	if strings.TrimSpace(info.TLSCertificate) == "" {
		return PortScriptResult{}
	}
	return PortScriptResult{
		Name:     "tls-cert-summary",
		Status:   "ok",
		Severity: "info",
		Output:   info.TLSCertificate,
	}
}

func httpSecurityHeaderScript(ctx context.Context, targetIP string, info PortInfo, opts PortScannerOptions) PortScriptResult {
	if !strings.Contains(strings.ToLower(info.Service), "http") {
		return PortScriptResult{}
	}
	scheme := "http"
	if isLikelyTLSService(info.Port, info.Service) {
		scheme = "https"
	}
	address := net.JoinHostPort(targetIP, strconv.Itoa(info.Port))
	url := fmt.Sprintf("%s://%s/", scheme, address)

	if ctx.Err() != nil {
		return PortScriptResult{}
	}

	missing := []string{}
	banner := strings.ToLower(info.Banner)
	for _, header := range []string{"strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options"} {
		if !strings.Contains(banner, header) {
			missing = append(missing, header)
		}
	}
	if len(missing) == 0 {
		return PortScriptResult{Name: "http-security-headers", Status: "ok", Severity: "info", Output: "common security headers observed in banner"}
	}
	return PortScriptResult{Name: "http-security-headers", Status: "review", Severity: "low", Output: fmt.Sprintf("%s missing or not visible in %s", strings.Join(missing, ","), url)}
}

func compactScripts(in []PortScriptResult) []PortScriptResult {
	out := make([]PortScriptResult, 0, len(in))
	for _, script := range in {
		if strings.TrimSpace(script.Name) == "" {
			continue
		}
		out = append(out, script)
	}
	return out
}

func savePortResults(results PortScanResults) {
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		fmt.Printf("%sError saving port scan results: %v%s\n", utils.Red, err, utils.Reset)
		return
	}

	if err := os.WriteFile(portResultsFile, data, 0644); err != nil {
		fmt.Printf("%sError writing file: %v%s\n", utils.Red, err, utils.Reset)
		return
	}

	if err := writePortOutputFormat(results); err != nil {
		fmt.Printf("%sError writing %s output: %v%s\n", utils.Red, results.OutputFormat, err, utils.Reset)
		return
	}

	fmt.Printf("%s\nPort scan results saved to %s%s\n", utils.Green, portResultsFile, utils.Reset)
}

func writePortOutputFormat(results PortScanResults) error {
	switch strings.ToLower(strings.TrimSpace(results.OutputFormat)) {
	case "", "json":
		return nil
	case "xml":
		data, err := xml.MarshalIndent(results, "", "  ")
		if err != nil {
			return err
		}
		data = append([]byte(xml.Header), data...)
		return os.WriteFile(portXMLFile, data, 0644)
	case "grep":
		var builder strings.Builder
		fmt.Fprintf(&builder, "Host: %s (%s)\tPorts: ", results.TargetIP, portFieldOrNA(results.TargetHostname))
		parts := make([]string, 0, len(results.Ports))
		for _, p := range results.Ports {
			parts = append(parts, fmt.Sprintf("%d/%s/%s//%s//%s//", p.Port, p.Status, p.Protocol, portFieldOrNA(p.Service), portFieldOrNA(p.Version)))
		}
		builder.WriteString(strings.Join(parts, ", "))
		builder.WriteByte('\n')
		return os.WriteFile(portGrepFile, []byte(builder.String()), 0644)
	case "all":
		data, err := xml.MarshalIndent(results, "", "  ")
		if err != nil {
			return err
		}
		data = append([]byte(xml.Header), data...)
		if err := os.WriteFile(portXMLFile, data, 0644); err != nil {
			return err
		}
		var builder strings.Builder
		fmt.Fprintf(&builder, "Host: %s (%s)\tPorts: ", results.TargetIP, portFieldOrNA(results.TargetHostname))
		parts := make([]string, 0, len(results.Ports))
		for _, p := range results.Ports {
			parts = append(parts, fmt.Sprintf("%d/%s/%s//%s//%s//", p.Port, p.Status, p.Protocol, portFieldOrNA(p.Service), portFieldOrNA(p.Version)))
		}
		builder.WriteString(strings.Join(parts, ", "))
		builder.WriteByte('\n')
		return os.WriteFile(portGrepFile, []byte(builder.String()), 0644)
	default:
		return nil
	}
}

func loadPortResults() (*PortScanResults, error) {
	data, err := os.ReadFile(portResultsFile)
	if err != nil {
		return nil, err
	}

	var results PortScanResults
	if err := json.Unmarshal(data, &results); err != nil {
		return nil, err
	}
	return &results, nil
}

func displayPortResults(results *PortScanResults) {
	fmt.Printf("\n%s======================== PORT SCAN STATISTICS ========================%s\n", utils.Blue, utils.Reset)

	fmt.Printf("\n%s  Target IP:          %s%s%s\n", utils.Green, utils.Yellow, results.TargetIP, utils.Reset)
	fmt.Printf("%s  Hostname:           %s%s%s\n", utils.Green, utils.Yellow, portFieldOrNA(results.TargetHostname), utils.Reset)
	fmt.Printf("%s  Scan Mode:          %s%s%s\n", utils.Green, utils.Yellow, results.ScanMode, utils.Reset)
	fmt.Printf("%s  Requested Scan:     %s%s%s\n", utils.Green, utils.Yellow, portFieldOrNA(results.RequestedScan), utils.Reset)
	fmt.Printf("%s  Total Scanned:      %s%d%s\n", utils.Green, utils.Yellow, results.TotalScanned, utils.Reset)
	fmt.Printf("%s  Open Ports:         %s%d%s\n", utils.Green, utils.Green, results.Open, utils.Reset)
	fmt.Printf("%s  Closed Ports:       %s%d%s\n", utils.Green, utils.Red, results.Closed, utils.Reset)
	fmt.Printf("%s  Filtered Ports:     %s%d%s\n", utils.Green, utils.Yellow, results.Filtered, utils.Reset)
	fmt.Printf("%s  Timing:             %sT%d | concurrency=%d | timeout=%dms | rate=%d/s%s\n",
		utils.Green, utils.Yellow, results.TimingTemplate, results.Concurrency, results.TimeoutMS, results.RateLimit, utils.Reset)
	fmt.Printf("%s  Version Intensity:  %s%d%s\n", utils.Green, utils.Yellow, results.VersionIntensity, utils.Reset)
	fmt.Printf("%s  Host OS Guess:      %s%s%s\n", utils.Green, utils.Yellow, portFieldOrNA(results.OSGuess), utils.Reset)
	fmt.Printf("%s  Output Format:      %s%s%s\n", utils.Green, utils.Yellow, portFieldOrNA(results.OutputFormat), utils.Reset)
	fmt.Printf("%s  Scan Duration:      %s%.2fs%s\n", utils.Green, utils.Yellow, results.ScanDuration, utils.Reset)
	fmt.Printf("%s  Scanned At:         %s%s%s\n\n", utils.Green, utils.Yellow, results.ScannedAt.Format("2006-01-02 15:04:05"), utils.Reset)

	if len(results.SafetyNotes) > 0 {
		fmt.Printf("%sSafety notes:%s\n", utils.Yellow, utils.Reset)
		for _, note := range results.SafetyNotes {
			fmt.Printf("  - %s\n", note)
		}
		fmt.Println()
	}

	fmt.Printf("%s========================== OPEN PORT DETAILS ==========================%s\n\n", utils.Blue, utils.Reset)

	openPorts := make([]PortInfo, 0, results.Open)
	for _, p := range results.Ports {
		if p.Status == "open" || p.Status == "open|filtered" {
			openPorts = append(openPorts, p)
		}
	}

	sort.Slice(openPorts, func(i, j int) bool {
		return openPorts[i].Port < openPorts[j].Port
	})

	if len(openPorts) == 0 {
		fmt.Printf("%sNo open ports found.%s\n\n", utils.Yellow, utils.Reset)
		return
	}

	for _, p := range openPorts {
		statusColor := utils.Green
		if p.Status == "open|filtered" {
			statusColor = utils.Yellow
		}
		fmt.Printf("%s[%s] Port %d/%s%s\n", statusColor, strings.ToUpper(p.Status), p.Port, p.Protocol, utils.Reset)
		fmt.Printf("    %sReason:%s %s\n", utils.Blue, utils.Reset, portFieldOrNA(p.Reason))
		fmt.Printf("    %sService:%s %s\n", utils.Blue, utils.Reset, portFieldOrNA(p.Service))
		if strings.TrimSpace(p.Product) != "" {
			fmt.Printf("    %sProduct:%s %s\n", utils.Blue, utils.Reset, p.Product)
		}
		if strings.TrimSpace(p.Version) != "" {
			fmt.Printf("    %sVersion:%s %s\n", utils.Blue, utils.Reset, p.Version)
		}
		if strings.TrimSpace(p.ExtraInfo) != "" {
			fmt.Printf("    %sExtra:%s %s\n", utils.Blue, utils.Reset, p.ExtraInfo)
		}
		if strings.TrimSpace(p.Banner) != "" {
			fmt.Printf("    %sBanner:%s %s\n", utils.Blue, utils.Reset, p.Banner)
		}
		if strings.TrimSpace(p.TLSCertificate) != "" {
			fmt.Printf("    %sTLS:%s %s\n", utils.Blue, utils.Reset, p.TLSCertificate)
		}
		if len(p.Scripts) > 0 {
			fmt.Printf("    %sScripts:%s\n", utils.Blue, utils.Reset)
			for _, script := range p.Scripts {
				fmt.Printf("      - %s [%s/%s]: %s\n", script.Name, script.Status, script.Severity, script.Output)
			}
		}
		if len(p.Vulnerabilities) > 0 {
			fmt.Printf("    %sPotential Vulnerabilities:%s\n", utils.Yellow, utils.Reset)
			for _, v := range p.Vulnerabilities {
				color := utils.Yellow
				if strings.Contains(strings.ToUpper(v), "CRITICAL") || strings.Contains(strings.ToUpper(v), "CVE-") {
					color = utils.Red
				}
				fmt.Printf("      %s- %s%s\n", color, v, utils.Reset)
			}
		}
		fmt.Println()
	}
}

func refreshPortResults(previous *PortScanResults) {
	utils.ClearTerminal()
	fmt.Printf("\n%s=== REFRESHING PORT SCAN ===%s\n\n", utils.Blue, utils.Reset)

	if !utils.IsValidIPv4(previous.TargetIP) {
		fmt.Printf("%sCannot refresh: invalid saved target IP.%s\n", utils.Red, utils.Reset)
		reader := bufio.NewReader(os.Stdin)
		utils.WaitForEnter(reader)
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	opts := defaultPortScannerOptions()
	if previous.Concurrency > 0 {
		opts.Concurrency = previous.Concurrency
	}
	if previous.TimeoutMS > 0 {
		opts.Timeout = time.Duration(previous.TimeoutMS) * time.Millisecond
	}
	if previous.RateLimit > 0 {
		opts.RateLimit = previous.RateLimit
	}
	if previous.TimingTemplate >= 0 && previous.TimingTemplate <= 5 {
		opts.TimingTemplate = previous.TimingTemplate
	}
	if previous.VersionIntensity > 0 {
		opts.VersionIntensity = previous.VersionIntensity
	}
	if previous.OutputFormat != "" {
		opts.OutputFormat = previous.OutputFormat
	}
	opts.RequestedScan = previous.RequestedScan
	opts.ScanType = normalizeScanType(previous.RequestedScan, &opts)

	ports := make([]int, 0, len(previous.Ports))
	for _, p := range previous.Ports {
		ports = append(ports, p.Port)
	}
	if len(ports) == 0 {
		start := previous.StartPort
		end := previous.EndPort
		if start == 0 || end == 0 {
			start = 1
			end = 65535
		}
		ports = expandPortRange(start, end)
	}

	results := runPortListScanWithOptions(ctx, previous.TargetIP, ports, true, "refresh:"+previous.ScanMode, opts)
	savePortResults(results)

	utils.ClearTerminal()
	displayPortResults(&results)

	reader := bufio.NewReader(os.Stdin)
	utils.WaitForEnter(reader)
}

func deletePortResults() {
	err := os.Remove(portResultsFile)
	if err != nil {
		fmt.Printf("%sError deleting results: %v%s\n", utils.Red, err, utils.Reset)
	} else {
		_ = os.Remove(portXMLFile)
		_ = os.Remove(portGrepFile)
		fmt.Printf("%sPort scan results deleted successfully!%s\n", utils.Green, utils.Reset)
	}
	time.Sleep(2 * time.Second)
}

func detectLocalIPv4() (string, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "", err
	}
	defer conn.Close()

	localAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || localAddr.IP == nil || localAddr.IP.To4() == nil {
		return "", fmt.Errorf("could not determine local IPv4")
	}
	return localAddr.IP.String(), nil
}

func reverseLookup(ip string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 1200*time.Millisecond)
	defer cancel()
	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return "N/A"
	}
	return strings.TrimSuffix(names[0], ".")
}

func classifyTCPError(err error) (string, string) {
	if err == nil {
		return "closed", "unknown"
	}
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return "filtered", "timeout"
	}
	lower := strings.ToLower(err.Error())
	switch {
	case strings.Contains(lower, "refused"):
		return "closed", "conn-refused"
	case strings.Contains(lower, "no route"):
		return "filtered", "no-route"
	case strings.Contains(lower, "i/o timeout"), strings.Contains(lower, "timed out"):
		return "filtered", "timeout"
	default:
		return "closed", sanitizeErrorReason(err)
	}
}

func sanitizeErrorReason(err error) string {
	if err == nil {
		return ""
	}
	reason := strings.ToLower(err.Error())
	if len(reason) > 80 {
		reason = reason[:80]
	}
	return reason
}

func cancelledPortInfo(port int, scanType string) PortInfo {
	protocol := "tcp"
	if scanType == "udp" {
		protocol = "udp"
	}
	return PortInfo{
		Port:        port,
		Protocol:    protocol,
		Status:      "filtered",
		Reason:      "cancelled",
		Service:     detectService(port),
		LastScanned: time.Now(),
	}
}

func countPortStates(ports []PortInfo) (int, int, int) {
	openCount := 0
	closedCount := 0
	filteredCount := 0
	for _, p := range ports {
		switch p.Status {
		case "open":
			openCount++
		case "closed":
			closedCount++
		default:
			filteredCount++
		}
	}
	return openCount, closedCount, filteredCount
}

func inferHostOSFromOpenPorts(ports []PortInfo) string {
	hasWindows := false
	hasUnix := false
	for _, p := range ports {
		if p.Status != "open" {
			continue
		}
		switch p.Port {
		case 135, 139, 445, 3389, 5985, 5986:
			hasWindows = true
		case 22, 111, 2049:
			hasUnix = true
		}
		if strings.Contains(strings.ToLower(p.Banner+" "+p.Product), "microsoft") {
			hasWindows = true
		}
		if strings.Contains(strings.ToLower(p.Banner+" "+p.Product), "openssh") {
			hasUnix = true
		}
	}
	switch {
	case hasWindows && hasUnix:
		return "mixed-signals"
	case hasWindows:
		return "Windows-family"
	case hasUnix:
		return "Linux/Unix-like"
	default:
		return "unknown"
	}
}

func inferOSFromPortSignals(info PortInfo) string {
	text := strings.ToLower(info.Banner + " " + info.Product + " " + info.Service)
	switch {
	case strings.Contains(text, "microsoft") || strings.Contains(text, "windows"):
		return "Windows-family"
	case strings.Contains(text, "openssh") || strings.Contains(text, "ubuntu") || strings.Contains(text, "debian"):
		return "Linux/Unix-like"
	default:
		return "unknown"
	}
}

func expandPortRange(start, end int) []int {
	if start < 1 {
		start = 1
	}
	if end > 65535 {
		end = 65535
	}
	if start > end {
		start, end = end, start
	}
	ports := make([]int, 0, end-start+1)
	for p := start; p <= end; p++ {
		ports = append(ports, p)
	}
	return ports
}

func parsePortExpression(value string, opts PortScannerOptions) []int {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" || value == "top" || value == "top-ports" {
		return normalizePorts(selectTopPorts(opts.TopPorts), opts.ExcludePorts)
	}
	if value == "all" || value == "1-65535" {
		return normalizePorts(expandPortRange(1, 65535), opts.ExcludePorts)
	}
	return normalizePorts(parsePorts(value), opts.ExcludePorts)
}

func parsePorts(value string) []int {
	seen := map[int]struct{}{}
	var ports []int
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			start, errA := strconv.Atoi(strings.TrimSpace(bounds[0]))
			end, errB := strconv.Atoi(strings.TrimSpace(bounds[1]))
			if errA != nil || errB != nil {
				continue
			}
			if start > end {
				start, end = end, start
			}
			for p := start; p <= end; p++ {
				if p < 1 || p > 65535 {
					continue
				}
				if _, ok := seen[p]; !ok {
					seen[p] = struct{}{}
					ports = append(ports, p)
				}
			}
			continue
		}
		port, err := strconv.Atoi(part)
		if err != nil || port < 1 || port > 65535 {
			continue
		}
		if _, ok := seen[port]; !ok {
			seen[port] = struct{}{}
			ports = append(ports, port)
		}
	}
	sort.Ints(ports)
	return ports
}

func normalizePorts(ports []int, excludes map[int]struct{}) []int {
	seen := map[int]struct{}{}
	out := make([]int, 0, len(ports))
	for _, port := range ports {
		if port < 1 || port > 65535 {
			continue
		}
		if _, excluded := excludes[port]; excluded {
			continue
		}
		if _, ok := seen[port]; ok {
			continue
		}
		seen[port] = struct{}{}
		out = append(out, port)
	}
	sort.Ints(out)
	return out
}

func selectTopPorts(n int) []int {
	if n <= 0 {
		n = 100
	}
	if n > len(topPortsRanked) {
		n = len(topPortsRanked)
	}
	out := make([]int, n)
	copy(out, topPortsRanked[:n])
	return out
}

func portsToSet(ports []int) map[int]struct{} {
	out := make(map[int]struct{}, len(ports))
	for _, port := range ports {
		out[port] = struct{}{}
	}
	return out
}

func parseRateLimit(value string, fallback int) int {
	clean := strings.ToLower(strings.TrimSpace(value))
	clean = strings.TrimSuffix(clean, "/sec")
	clean = strings.TrimSuffix(clean, "/s")
	clean = strings.TrimSuffix(clean, "pps")
	clean = strings.TrimSpace(clean)
	rate, err := strconv.Atoi(clean)
	if err != nil || rate < 0 {
		return fallback
	}
	return rate
}

func parseStringList(value string) []string {
	var out []string
	for _, part := range strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ' ' }) {
		part = strings.TrimSpace(strings.ToLower(part))
		if part != "" {
			out = append(out, part)
		}
	}
	return dedupeStrings(out)
}

func parseScriptArgs(value string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		key, val, ok := strings.Cut(part, "=")
		if !ok {
			out[part] = "true"
			continue
		}
		out[strings.TrimSpace(key)] = strings.TrimSpace(val)
	}
	return out
}

func splitCLIFields(raw string) []string {
	fields := make([]string, 0)
	var current strings.Builder
	inQuote := rune(0)
	escaped := false

	for _, r := range raw {
		switch {
		case escaped:
			current.WriteRune(r)
			escaped = false
		case r == '\\':
			escaped = true
		case inQuote != 0:
			if r == inQuote {
				inQuote = 0
			} else {
				current.WriteRune(r)
			}
		case r == '\'' || r == '"':
			inQuote = r
		case r == ' ' || r == '\t' || r == '\n':
			if current.Len() > 0 {
				fields = append(fields, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(r)
		}
	}
	if current.Len() > 0 {
		fields = append(fields, current.String())
	}
	return fields
}

func parseSlogLevel(value string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "error":
		return slog.LevelError
	default:
		return slog.LevelWarn
	}
}

func newSimpleRateLimiter(eventsPerSecond int) *simpleRateLimiter {
	if eventsPerSecond <= 0 {
		return &simpleRateLimiter{disabled: true}
	}
	interval := time.Second / time.Duration(eventsPerSecond)
	if interval < time.Microsecond {
		interval = time.Microsecond
	}
	return &simpleRateLimiter{ticker: time.NewTicker(interval)}
}

func (r *simpleRateLimiter) Wait(ctx context.Context) error {
	if r == nil || r.disabled {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-r.ticker.C:
		return nil
	}
}

func (r *simpleRateLimiter) Stop() {
	if r != nil && r.ticker != nil {
		r.ticker.Stop()
	}
}

func sleepBackoff(ctx context.Context, base time.Duration, attempt int) {
	if base <= 0 || attempt < 0 {
		return
	}
	delay := base * time.Duration(1<<minInt(attempt, 6))
	_ = sleepContext(ctx, delay)
}

func sleepContext(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func formatCertificateFromState(state tls.ConnectionState) string {
	if len(state.PeerCertificates) == 0 {
		return ""
	}
	cert := state.PeerCertificates[0]
	return fmt.Sprintf("subject=%s issuer=%s not_after=%s dns=%s",
		cert.Subject.CommonName,
		cert.Issuer.CommonName,
		cert.NotAfter.Format("2006-01-02"),
		strings.Join(cert.DNSNames, ","))
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func clamp(value, minValue, maxValue int) int {
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}

func percent(done, total int) float64 {
	if total <= 0 {
		return 100
	}
	return (float64(done) / float64(total)) * 100.0
}

func dedupeStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func defaultIfEmpty(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func portFieldOrNA(v string) string {
	if strings.TrimSpace(v) == "" {
		return "N/A"
	}
	return v
}
