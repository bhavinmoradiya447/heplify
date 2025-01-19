package publish

import (
	"sync/atomic"
	"time"

	"github.com/negbie/logp"
	"github.com/sipcapture/heplify/decoder"
	"github.com/sipcapture/heplify/sipparser"
)

type Publisher struct {
	pubCount uint64
}

func NewPublisher() *Publisher {
	p := &Publisher{
		pubCount: 0,
	}

	go p.Start(decoder.PacketQueue)
	go p.printStats()
	return p
}

func (pub *Publisher) Start(pq chan *decoder.Packet) {
	for pkt := range pq {
		// TODO:: packet with all details
		// pkt.SrcIP, pkt.DstIP, pkt.SrcPort, pkt.DstPort, pkt.Payload
		/*
			Version:   uint32(h.Version),
			 	Protocol:  uint32(h.Protocol),
			 	SrcIP:     h.SrcIP.String(),
			 	DstIP:     h.DstIP.String(),
			 	SrcPort:   uint32(h.SrcPort),
			 	DstPort:   uint32(h.DstPort),
			 	Tsec:      h.Tsec,
			 	Tmsec:     h.Tmsec,
			 	ProtoType: uint32(h.ProtoType),
			 	Payload:   unsafeBytesToStr(h.Payload),
			 	CID:       unsafeBytesToStr(h.CID),
			 	Vlan:      uint32(h.Vlan),
		*/
		if pkt.GetDstPort() != 9060 { // 9060 is the port for heplify-server, so ignore metrics for this port
			//logp.Info("Packet: %v", pkt.GetPayload())

			var SIP = sipparser.ParseMsg(pkt.GetPayload(), nil, nil)
			var respone = SIP.FirstResp
			if respone == "" {
				respone = SIP.FirstMethod
			}
			logp.Info("srcIP:%v, SrcPort:%v, "+
				"DstIP:%v, DstPort:%v, Method: %v, Resp: %v, CallID: %v, FromHost: %v, ToHost: %v",
				pkt.GetSrcIP(),
				pkt.GetSrcPort(),
				pkt.GetDstIP(),
				pkt.GetDstPort(),
				SIP.CseqMethod,
				respone,
				SIP.CallID,
				SIP.FromHost,
				SIP.ToHost)
		}
		// publish metrics from here
	}
}

func (pub *Publisher) printStats() {
	for {
		<-time.After(1 * time.Minute)
		go func() {
			logp.Info("Packets since last minute sent: %d", atomic.LoadUint64(&pub.pubCount))
			atomic.StoreUint64(&pub.pubCount, 0)
		}()
	}
}
