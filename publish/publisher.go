package publish

import (
	"github.com/negbie/logp"
	"github.com/sipcapture/heplify/decoder"
	"github.com/sipcapture/heplify/sipparser"
)

type Publisher struct {
}

func NewPublisher() *Publisher {
	p := &Publisher{}

	go p.Start(decoder.PacketQueue)
	return p
}

func (pub *Publisher) Start(pq chan *decoder.Packet) {
	for pkt := range pq {

		// TODO:: packet with all details
		if pkt.GetDstPort() != 9060 && (pkt.GetSrcPort() == 5080 || pkt.GetDstPort() == 5080) {
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
		} else {
			h, err := DecodeHEP(pkt.Payload)
			if err == nil {
				var payload = h.Payload
				var SIP = sipparser.ParseMsg(string(payload), nil, nil)
				var respone = SIP.FirstResp
				if respone == "" {
					respone = SIP.FirstMethod
				}
				logp.Info("PARSED HEP3 srcIP:%v, SrcPort:%v, "+
					"DstIP:%v, DstPort:%v, Method: %v, Resp: %v, CallID: %v, FromHost: %v, ToHost: %v",
					h.SrcIP,
					h.SrcPort,
					h.DstIP,
					h.DstPort,
					SIP.CseqMethod,
					respone,
					SIP.CallID,
					SIP.FromHost,
					SIP.ToHost)
			} else {
				logp.Err("Error decoding HEP: %v", err)
			}

		}
		// publish metrics from here
	}
}
