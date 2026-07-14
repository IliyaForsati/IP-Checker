package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	nfqueue "github.com/florianl/go-nfqueue/v2"
	"golang.org/x/sys/unix"

	"github.com/IliyaForsati/IP-Checker/internal/config"
	"github.com/IliyaForsati/IP-Checker/internal/decision"
	"github.com/IliyaForsati/IP-Checker/internal/dnsobserver"
	"github.com/IliyaForsati/IP-Checker/internal/logging"
	"github.com/IliyaForsati/IP-Checker/internal/nft"
	"github.com/IliyaForsati/IP-Checker/internal/packet"
	"github.com/IliyaForsati/IP-Checker/internal/sniobserver"
)

func main() {
	configPath := flag.String("config", "/etc/ip-checker/config.json", "path to the JSON config file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ipcheckerd: %v\n", err)
		os.Exit(1)
	}

	matcher, err := cfg.BuildMatcher()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ipcheckerd: %v\n", err)
		os.Exit(1)
	}

	logger, err := logging.New(cfg.Log.Level, cfg.Log.Path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ipcheckerd: %v\n", err)
		os.Exit(1)
	}

	logger.Info("config loaded", "path", *configPath, "enforcement_mode", cfg.EnforcementMode, "domains", len(cfg.Domains))

	if err := nft.Setup(cfg.NFQueue.DNSQueueNum, cfg.NFQueue.TLSQueueNum); err != nil {
		logger.Error("nft setup failed", "error", err)
		os.Exit(1)
	}
	logger.Info("nft rules installed")

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	dnsQueue, err := openQueue(cfg.NFQueue.DNSQueueNum)
	if err != nil {
		logger.Error("failed to open dns queue", "error", err)
		teardown(logger)
		os.Exit(1)
	}
	defer dnsQueue.Close()

	tlsQueue, err := openQueue(cfg.NFQueue.TLSQueueNum)
	if err != nil {
		logger.Error("failed to open tls queue", "error", err)
		teardown(logger)
		os.Exit(1)
	}
	defer tlsQueue.Close()

	monitorOnly := cfg.EnforcementMode == config.EnforcementModeMonitor
	engine := decision.NewEngine(matcher, logger, monitorOnly)
	flows := decision.NewFlowTable(time.Duration(cfg.FlowVerdictTTLSeconds) * time.Second)
	correlation := dnsobserver.NewTable(time.Duration(cfg.DNSCorrelationTTLSeconds) * time.Second)
	dnsPipeline := dnsobserver.NewPipeline(correlation, engine)
	tlsPipeline := sniobserver.NewPipeline(engine, flows, correlation)

	go sweepLoop(ctx, flows, correlation)
	go reloadLoop(ctx, *configPath, logger, engine)

	errHandler := func(e error) int {
		logger.Warn("nfqueue error", "error", e)
		return 0
	}

	if err := dnsQueue.RegisterWithErrorFunc(ctx, dnsObserveHandler(dnsQueue, logger, dnsPipeline), errHandler); err != nil {
		logger.Error("failed to register dns queue handler", "error", err)
		teardown(logger)
		os.Exit(1)
	}
	if err := tlsQueue.RegisterWithErrorFunc(ctx, tlsEnforceHandler(tlsQueue, logger, tlsPipeline), errHandler); err != nil {
		logger.Error("failed to register tls queue handler", "error", err)
		teardown(logger)
		os.Exit(1)
	}

	logger.Info("ipcheckerd running")
	<-ctx.Done()

	logger.Info("shutting down")
	teardown(logger)
}

func openQueue(queueNum uint16) (*nfqueue.Nfqueue, error) {
	return nfqueue.Open(&nfqueue.Config{
		NfQueue:      queueNum,
		MaxPacketLen: 0xFFFF,
		MaxQueueLen:  0xFF,
		Copymode:     nfqueue.NfQnlCopyPacket,
		AfFamily:     unix.AF_INET,
	})
}

func dnsObserveHandler(nf *nfqueue.Nfqueue, logger *slog.Logger, pipeline *dnsobserver.Pipeline) nfqueue.HookFunc {
	return func(a nfqueue.Attribute) int {
		if a.PacketID == nil {
			return 0
		}
		id := *a.PacketID

		if a.Payload != nil {
			logPacket(logger, "dns", *a.Payload)
			if ip, err := packet.ParseIPv4(*a.Payload); err == nil {
				pipeline.HandleIPv4(ip)
			}
		}

		if err := nf.SetVerdict(id, nfqueue.NfAccept); err != nil {
			logger.Warn("set verdict failed", "queue", "dns", "error", err)
		}
		return 0
	}
}

func tlsEnforceHandler(nf *nfqueue.Nfqueue, logger *slog.Logger, pipeline *sniobserver.Pipeline) nfqueue.HookFunc {
	return func(a nfqueue.Attribute) int {
		if a.PacketID == nil {
			return 0
		}
		id := *a.PacketID

		verdict := nfqueue.NfAccept
		if a.Payload != nil {
			if ip, err := packet.ParseIPv4(*a.Payload); err == nil {
				if pipeline.HandleIPv4(ip) == decision.VerdictDrop {
					verdict = nfqueue.NfDrop
				}
			} else {
				logger.Debug("non-ipv4 packet on tls queue", "error", err)
			}
		}

		if err := nf.SetVerdict(id, verdict); err != nil {
			logger.Warn("set verdict failed", "queue", "tls", "error", err)
		}
		return 0
	}
}

func logPacket(logger *slog.Logger, queueLabel string, raw []byte) {
	ip, err := packet.ParseIPv4(raw)
	if err != nil {
		logger.Debug("non-ipv4 packet observed", "queue", queueLabel, "error", err)
		return
	}

	switch ip.Protocol {
	case packet.ProtocolTCP:
		seg, err := packet.ParseTCP(ip.Payload)
		if err != nil {
			logger.Debug("malformed tcp segment", "queue", queueLabel, "error", err)
			return
		}
		logger.Debug("tcp packet observed",
			"queue", queueLabel,
			"src_ip", ip.SrcIP.String(), "dst_ip", ip.DstIP.String(),
			"src_port", seg.SrcPort, "dst_port", seg.DstPort,
			"syn", seg.HasFlag(packet.TCPFlagSYN))
	case packet.ProtocolUDP:
		dgram, err := packet.ParseUDP(ip.Payload)
		if err != nil {
			logger.Debug("malformed udp datagram", "queue", queueLabel, "error", err)
			return
		}
		logger.Debug("udp packet observed",
			"queue", queueLabel,
			"src_ip", ip.SrcIP.String(), "dst_ip", ip.DstIP.String(),
			"src_port", dgram.SrcPort, "dst_port", dgram.DstPort)
	}
}

func sweepLoop(ctx context.Context, flows *decision.FlowTable, correlation *dnsobserver.Table) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			flows.Sweep(now)
			correlation.Sweep(now)
		}
	}
}

func reloadLoop(ctx context.Context, configPath string, logger *slog.Logger, engine *decision.Engine) {
	reloadCh := make(chan os.Signal, 1)
	signal.Notify(reloadCh, syscall.SIGHUP)
	defer signal.Stop(reloadCh)

	for {
		select {
		case <-ctx.Done():
			return
		case <-reloadCh:
			cfg, err := config.Load(configPath)
			if err != nil {
				logger.Error("config reload failed, keeping previous config", "error", err)
				continue
			}
			matcher, err := cfg.BuildMatcher()
			if err != nil {
				logger.Error("config reload failed, keeping previous config", "error", err)
				continue
			}
			engine.SetState(matcher, cfg.EnforcementMode == config.EnforcementModeMonitor)
			logger.Info("config reloaded", "path", configPath, "enforcement_mode", cfg.EnforcementMode, "domains", len(cfg.Domains))
		}
	}
}

func teardown(logger *slog.Logger) {
	if err := nft.Teardown(); err != nil {
		logger.Error("nft teardown failed", "error", err)
	}
}
