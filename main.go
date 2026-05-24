package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
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

	lastIP, err := state.Load(cfg.StateFile)
	if err != nil {
		return fmt.Errorf("读取状态: %w", err)
	}

	if !force && lastIP == currentIP {
		log.Printf("公网 IP 未变化 (%s)，无需更新", currentIP)
		return nil
	}

	if lastIP == "" {
		log.Printf("公网 IP: (无) -> %s", currentIP)
	} else {
		log.Printf("公网 IP: %s -> %s", lastIP, currentIP)
	}

	b, err := backend.New(cfg)
	if err != nil {
		return err
	}

	var oldPtr *string
	if lastIP != "" {
		oldPtr = &lastIP
	}
	if err := b.UpsertWhitelist(currentIP, oldPtr, cfg); err != nil {
		return err
	}

	if err := state.Save(cfg.StateFile, currentIP); err != nil {
		return fmt.Errorf("保存状态: %w", err)
	}
	log.Printf("防火墙白名单已更新为 %s", currentIP)
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
