//go:build go1.20
// +build go1.20

package main

import (
	"bytes"
	"context"
	"embed"
	_ "embed"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/disk"
	"github.com/shirou/gopsutil/mem"
	gnet "github.com/shirou/gopsutil/net"
	"github.com/shirou/gopsutil/process"
	"gopkg.in/yaml.v3"
)

//go:embed web/*
var webFiles embed.FS
var webFS = http.FS(webFiles)

// -------------- 配置 --------------
type Config struct {
	Interval  time.Duration `yaml:"interval"`
	TemsURLs  []string      `yaml:"tems_urls"`
	Processes []struct {
		Name  string `yaml:"name"`
		PID   int32  `yaml:"pid"`
		Regex string `yaml:"regex"`
	} `yaml:"processes"`
	HooksDir    string        `yaml:"hooks_dir"`
	HookTimeout time.Duration `yaml:"hook_timeout"`
	WatchConfig bool          `yaml:"watch_config"`
	Web         struct {
		Addr string `yaml:"addr"` // 仅监听地址
	} `yaml:"web"`
	//BlacklistFile string `yaml:"blacklist_file"`
}

// -------------- 指标 --------------
type Metric struct {
	Hostname string                 `json:"hostname"`
	IP       string                 `json:"ip"` // 新增
	CPU      float64                `json:"cpu_percent"`
	Mem      float64                `json:"mem_percent"`
	Disk     float64                `json:"disk_percent"`
	Net      NetIO                  `json:"network"`
	Procs    []ProcSnap             `json:"processes"`
	Hooks    map[string]interface{} `json:"custom"`
}

type NetIO struct {
	BytesSent   uint64 `json:"bytes_sent"`
	BytesRecv   uint64 `json:"bytes_recv"`
	PacketsSent uint64 `json:"packets_sent"`
	PacketsRecv uint64 `json:"packets_recv"`
}

// gems健康监测
type temsHealth struct {
	url        string
	failCount  int
	blackUntil time.Time
	sync.Mutex
}

const maxFail = 3                 // 连续失败次数上限
const blackDur = 30 * time.Second // 黑名单时长

type ProcSnap struct {
	PID    int32   `json:"pid"`
	Name   string  `json:"name"`
	CPUPct float64 `json:"cpu_percent"`
	MemPct float32 `json:"mem_percent"`
}

var (
	cfg     Config
	cfgLock sync.RWMutex
)

// -------------- 配置热加载 --------------
func loadConfig(path string) {
	b, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("read config: %v", err)
	}
	cfgLock.Lock()
	defer cfgLock.Unlock()
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		log.Fatalf("parse yaml: %v", err)
	}
	log.Println("config reloaded")
}

func watch(path string) {
	w, _ := fsnotify.NewWatcher()
	go func() {
		for e := range w.Events {
			if e.Op&fsnotify.Write == fsnotify.Write {
				loadConfig(path)
			}
		}
	}()
	_ = w.Add(path)
}

// -------------- 采集 --------------
func hostname() string {
	h, _ := os.Hostname()
	return h
}

// ---获取本地IP---
func getOutboundIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}

func collectOnce() Metric {
	cfgLock.RLock()
	defer cfgLock.RUnlock()

	cpuPct, _ := cpu.Percent(time.Second, false)
	vm, _ := mem.VirtualMemory()
	du, _ := disk.Usage("/")

	io, _ := gnet.IOCounters(false)
	var netIO NetIO
	if len(io) > 0 {
		netIO = NetIO{
			BytesSent:   io[0].BytesSent,
			BytesRecv:   io[0].BytesRecv,
			PacketsSent: io[0].PacketsSent,
			PacketsRecv: io[0].PacketsRecv,
		}
	}

	all, _ := process.Processes()
	var snaps []ProcSnap
	for _, p := range all {
		for _, r := range cfg.Processes {
			match := false
			if r.PID != 0 && p.Pid == r.PID {
				match = true
			}
			name, _ := p.Name()
			if r.Name != "" && name == r.Name {
				match = true
			}
			if r.Regex != "" {
				if ok, _ := regexp.MatchString(r.Regex, name); ok {
					match = true
				}
			}
			if match {
				cpu, _ := p.CPUPercent()
				mem, _ := p.MemoryPercent()
				snaps = append(snaps, ProcSnap{
					PID:    p.Pid,
					Name:   name,
					CPUPct: cpu,
					MemPct: mem,
				})
				break
			}
		}
	}
	sort.Slice(snaps, func(i, j int) bool { return snaps[i].CPUPct > snaps[j].CPUPct })
	return Metric{
		Hostname: hostname(),
		IP:       getOutboundIP(),
		CPU:      cpuPct[0],
		Mem:      vm.UsedPercent,
		Disk:     du.UsedPercent,
		Net:      netIO,
		Procs:    snaps,
	}
}

// -------------- 异步 hooks --------------
func runHooks(ctx context.Context) map[string]interface{} {
	cfgLock.RLock()
	dir := cfg.HooksDir
	to := cfg.HookTimeout
	cfgLock.RUnlock()
	if dir == "" {
		return nil
	}
	res := make(map[string]interface{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	files, _ := filepath.Glob(filepath.Join(dir, "*.sh"))
	for _, f := range files {
		wg.Add(1)
		go func(path string) {
			defer wg.Done()
			ctx2, cancel := context.WithTimeout(ctx, to)
			defer cancel()
			cmd := exec.CommandContext(ctx2, "sh", path)
			out, err := cmd.Output()
			key := strings.TrimSuffix(filepath.Base(path), ".sh")
			mu.Lock()
			if err != nil {
				res[key] = map[string]string{"error": err.Error()}
			} else {
				var j json.RawMessage
				if json.Unmarshal(out, &j) == nil {
					res[key] = j
				} else {
					res[key] = strings.TrimSpace(string(out))
				}
			}
			mu.Unlock()
		}(f)
	}
	wg.Wait()
	return res
}

// -------------- 上报 --------------
var healthMap = make(map[string]*temsHealth) // key = url

func initHealth(urls []string) {
	for _, u := range urls {
		healthMap[u] = &temsHealth{url: u}
	}
}

// -------------- 并发推送（只推可达） --------------
// 检查当前 url 是否可达
func (h *temsHealth) isAlive() bool {
	h.Lock()
	defer h.Unlock()
	return time.Now().After(h.blackUntil)
}

// 记录一次失败 / 成功
func (h *temsHealth) record(ok bool) {
	h.Lock()
	defer h.Unlock()
	if ok {
		h.failCount = 0
		h.blackUntil = time.Time{} // 解除黑名单
		return
	}
	h.failCount++
	if h.failCount >= maxFail {
		h.blackUntil = time.Now().Add(blackDur)
		log.Printf("TEMS %s blacklisted for %v", h.url, blackDur)
	}
}

// -------------- 并发推送（只推可达） --------------
func reportAll(m Metric) {
	wg := sync.WaitGroup{}
	for url, h := range healthMap {
		if !h.isAlive() {
			continue // 跳过黑名单
		}
		wg.Add(1)
		go func(u string, h *temsHealth) {
			defer wg.Done()
			body, _ := json.Marshal(m)
			client := &http.Client{Timeout: 3 * time.Second}
			resp, err := client.Post(u, "application/json", bytes.NewReader(body))
			success := err == nil && resp.StatusCode < 400
			h.record(success)
			if !success {
				log.Printf("push to %s failed: %v", u, err)
			}
		}(url, h)
	}
	wg.Wait()
}

// -------------- Web --------------
func runWeb() {
	cfgLock.RLock()
	addr := cfg.Web.Addr
	if addr == "" {
		addr = ":8080"
	}
	cfgLock.RUnlock()

	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(webFS))
	mux.HandleFunc("/stream", func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			select {
			case <-tick.C:
				m := collectOnce()
				ctx, cancel := context.WithTimeout(r.Context(), cfg.HookTimeout+time.Second)
				m.Hooks = runHooks(ctx)
				cancel()
				data, _ := json.Marshal(m)
				fmt.Fprintf(w, "data: %s\n\n", data)
				flusher.Flush()
			case <-r.Context().Done():
				return
			}
		}
	})
	log.Printf("dashboard: http://localhost%s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

// -------------- 主函数 --------------
func main() {
	const cfgPath = "config.yaml"
	loadConfig(cfgPath)
	initHealth(cfg.TemsURLs)
	if cfg.WatchConfig {
		watch(cfgPath)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go runWeb()

	tick := time.NewTicker(cfg.Interval)
	defer tick.Stop()

	for {
		select {
		case <-tick.C:
			m := collectOnce()
			ctx2, cancel := context.WithTimeout(ctx, cfg.HookTimeout+time.Second)
			m.Hooks = runHooks(ctx2)
			reportAll(m)
			cancel()
		case <-ctx.Done():
			log.Println("shutting down...")
			return
		}
	}
}
