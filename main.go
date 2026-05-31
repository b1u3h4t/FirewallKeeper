package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/b1u3h4t/FirewallKeeper/internal/backend"
	"github.com/b1u3h4t/FirewallKeeper/internal/config"
	"github.com/b1u3h4t/FirewallKeeper/internal/ip"
	"github.com/b1u3h4t/FirewallKeeper/internal/state"
)

func main() {
	defaultConfig := os.Getenv("CONFIG_PATH")
	if defaultConfig == "" {
		defaultConfig = "config.yaml"
	}
	configPath := flag.String("c", defaultConfig, "配置文件路径")
	once := flag.Bool("once", false, "只执行一次后退出（适合 cron/systemd timer）")
	force := flag.Bool("force", false, "即使 IP 未变化也强制更新规则")
	verbose := flag.Bool("v", false, "输出详细日志")
	flag.Parse()

	log.SetFlags(log.LstdFlags)
	if !*verbose {
		log.SetOutput(os.Stdout)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("加载配置失败: %v", err)
	}

	if *once {
		if err := runOnce(cfg, *force); err != nil {
			log.Fatalf("%v", err)
		}
		return
	}

	runDaemon(cfg, *force)
}

func runOnce(cfg *config.Config, force bool) error {
	currentIP, err := ip.FetchPublicIPv4(cfg.IPCheckURLs)
	if err != nil {
		return err
	}

	last, err := state.Load(cfg.StateFile)
	if err != nil {
		return fmt.Errorf("读取状态: %w", err)
	}

	ipUnchanged := last.IP == currentIP
	portsUnchanged := state.PortsEqual(last.Ports, cfg.Ports)
	if !force && ipUnchanged && portsUnchanged {
		log.Printf("公网 IP 与端口均未变化 (%s)，无需更新", currentIP)
		return nil
	}

	if last.IP == "" {
		log.Printf("公网 IP: (无) -> %s", currentIP)
	} else if !ipUnchanged {
		log.Printf("公网 IP: %s -> %s", last.IP, currentIP)
	}
	if !portsUnchanged {
		log.Printf("端口: %v -> %v", last.Ports, cfg.Ports)
	}

	backends, err := backend.NewAll(cfg)
	if err != nil {
		return err
	}

	names := make([]string, len(backends))
	for i, b := range backends {
		names[i] = b.Name()
	}
	log.Printf("已启用 %d 个目标: %s", len(backends), strings.Join(names, ", "))

	var oldPtr *string
	if last.IP != "" {
		oldPtr = &last.IP
	}
	if err := backend.UpsertAll(backends, currentIP, oldPtr, cfg); err != nil {
		return err
	}

	if err := state.Save(cfg.StateFile, state.Snapshot{IP: currentIP, Ports: cfg.Ports}); err != nil {
		return fmt.Errorf("保存状态: %w", err)
	}
	log.Printf("全部目标防火墙白名单已更新为 %s", currentIP)
	return nil
}

func runDaemon(cfg *config.Config, force bool) {
	log.Printf("守护模式启动，检测间隔 %d 秒", cfg.IntervalSeconds)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(time.Duration(cfg.IntervalSeconds) * time.Second)
	defer ticker.Stop()

	for {
		if err := runOnce(cfg, force); err != nil {
			log.Printf("本轮更新失败: %v", err)
		}
		force = false

		select {
		case <-ticker.C:
		case <-sigCh:
			log.Println("已退出")
			return
		}
	}
}
