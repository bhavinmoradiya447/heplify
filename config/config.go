package config

import (
	"sync"

	"github.com/negbie/logp"
)

var Cfg Config

var WgExitGroup sync.WaitGroup

type Config struct {
	Iface            *InterfacesConfig
	Logging          *logp.Logging
	DiscardMethod    string
	PrometheusIPPort string
}

type InterfacesConfig struct {
	Device       string `config:"device"`
	Type         string `config:"type"`
	ReadFile     string `config:"read_file"`
	RotationTime int    `config:"rotation_time"`
	PortRange    string `config:"port_range"`
	WithVlan     bool   `config:"with_vlan"`
	WithErspan   bool   `config:"with_erspan"`
	Snaplen      int    `config:"snaplen"`
	BufferSizeMb int    `config:"buffer_size_mb"`
	ReadSpeed    bool   `config:"top_speed"`
	OneAtATime   bool   `config:"one_at_a_time"`
	Loop         int    `config:"loop"`
	EOFExit      bool   `config:"eof_exit"`
	FanoutID     uint   `config:"fanout_id"`
	FanoutWorker int    `config:"fanout_worker"`
	CustomBPF    string `config:"custom_bpf"`
}
