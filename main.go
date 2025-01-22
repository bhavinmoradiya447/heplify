package main

import (
	"flag"
	"fmt"
	"os"
	"sync"

	"github.com/negbie/logp"
	"github.com/sipcapture/heplify/config"
	"github.com/sipcapture/heplify/promstats"
	"github.com/sipcapture/heplify/sniffer"
)

func createFlags() {

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Args: %s [option]\n", os.Args[0])
		flag.PrintDefaults()
	}

	var (
		ifaceConfig config.InterfacesConfig
		logging     logp.Logging
		fileRotator logp.FileRotator
		dbg         string
		std         bool
		sys         bool
		fNum        int
		fSize       uint64
	)

	//long
	flag.StringVar(&config.Cfg.PrometheusIPPort, "prometheus", ":8090", "prometheus metrics - ip:port. By default all IPs")
	flag.StringVar(&config.Cfg.DiscardMethod, "dim", "", "Discard uninteresting SIP packets by Method [OPTIONS,NOTIFY]")
	flag.BoolVar(&ifaceConfig.WithVlan, "vlan", false, "vlan")
	flag.BoolVar(&ifaceConfig.WithErspan, "erspan", false, "erspan")
	flag.IntVar(&fNum, "fnum", 7, "The total num of log files to keep")
	flag.Uint64Var(&fSize, "fsize", 10*1024*1024, "The rotate size per log file based on byte")

	//short
	flag.StringVar(&ifaceConfig.CustomBPF, "bpf", "", "Custom BPF to capture packets")
	//
	flag.UintVar(&ifaceConfig.FanoutID, "fg", 0, "Fanout group ID for af_packet")
	flag.IntVar(&ifaceConfig.FanoutWorker, "fw", 4, "Fanout worker count for af_packet")
	flag.StringVar(&ifaceConfig.ReadFile, "rf", "", "Read pcap file")
	flag.IntVar(&ifaceConfig.RotationTime, "rt", 60, "Pcap rotation time in minutes")
	flag.IntVar(&ifaceConfig.Loop, "lp", 1, "Loop count over ReadFile. Use 0 to loop forever")
	flag.BoolVar(&ifaceConfig.EOFExit, "eof-exit", false, "Exit on EOF of ReadFile")
	flag.BoolVar(&ifaceConfig.ReadSpeed, "rs", false, "Use packet timestamps with maximum pcap read speed")
	flag.StringVar(&ifaceConfig.PortRange, "pr", "5060-5090", "Portrange to capture SIP")
	flag.BoolVar(&sys, "sl", false, "Log to syslog")
	flag.IntVar(&ifaceConfig.BufferSizeMb, "b", 32, "Interface buffersize (MB)")
	flag.StringVar(&dbg, "d", "", "Enable certain debug selectors [defrag,layer,payload,rtp,rtcp,sdp]")
	flag.BoolVar(&std, "e", false, "Log to stderr and disable syslog/file output")
	flag.StringVar(&logging.Level, "l", "info", "Log level [debug, info, warning, error]")
	flag.BoolVar(&ifaceConfig.OneAtATime, "o", false, "Read packet for packet")
	flag.StringVar(&fileRotator.Path, "p", "./", "Log filepath")
	flag.StringVar(&fileRotator.Name, "n", "heplify.log", "Log filename")
	flag.IntVar(&ifaceConfig.Snaplen, "s", 8192, "Snaplength")
	flag.StringVar(&ifaceConfig.Device, "i", "any", "Listen on interface")
	flag.StringVar(&ifaceConfig.Type, "t", "af_packet", "Capture types are [pcap, af_packet]")
	flag.Parse()

	config.Cfg.Iface = &ifaceConfig
	logp.ToStderr = &std
	logging.ToSyslog = &sys
	logp.DebugSelectorsStr = &dbg
	fileRotator.KeepFiles = &fNum
	fileRotator.RotateEveryBytes = &fSize
	logging.Files = &fileRotator
	config.Cfg.Logging = &logging

}

func checkCritErr(err error) {
	if err != nil {
		fmt.Printf("\nCritical: %v\n\n", err)
		os.Exit(1)
	}
}

func main() {
	createFlags()

	err := logp.Init("sipcapture", config.Cfg.Logging)
	checkCritErr(err)

	worker := 1
	if config.Cfg.Iface.Type == "af_packet" &&
		config.Cfg.Iface.FanoutID > 0 && config.Cfg.Iface.FanoutWorker > 1 {
		worker = config.Cfg.Iface.FanoutWorker
	}

	var wg sync.WaitGroup

	go promstats.StartMetrics(&wg)

	for i := 0; i < worker; i++ {
		capture, err := sniffer.New(&config.Cfg)
		checkCritErr(err)

		defer func() {
			err = capture.Close()
			checkCritErr(err)
		}()

		wg.Add(1)
		go func() {

			err = capture.Run()
			checkCritErr(err)
			wg.Done()
		}()
	}
	wg.Wait()
}
