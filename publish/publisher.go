package publish

import (
	"github.com/negbie/logp"
	"github.com/sipcapture/heplify/decoder"
	"github.com/sipcapture/heplify/promstats"
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
			var response = SIP.FirstResp
			if response == "" {
				response = SIP.FirstMethod
			}
			logp.Info("srcIP:%v, SrcPort:%v, "+
				"DstIP:%v, DstPort:%v, Method: %v, Resp: %v, CallID: %v, FromHost: %v, ToHost: %v",
				pkt.GetSrcIP(),
				pkt.GetSrcPort(),
				pkt.GetDstIP(),
				pkt.GetDstPort(),
				SIP.CseqMethod,
				response,
				SIP.CallID,
				SIP.FromHost,
				SIP.ToHost)
			incrementCounter(pkt.GetSrcIP(), pkt.GetDstIP(), SIP.CseqMethod, response, "FS/BNR")
		} else if pkt.GetDstPort() == 9060 {
			h, err := DecodeHEP(pkt.Payload)
			if err == nil {
				var payload = h.Payload
				var SIP = sipparser.ParseMsg(string(payload), nil, nil)
				var response = SIP.FirstResp
				if response == "" {
					response = SIP.FirstMethod
				}
				logp.Info("PARSED HEP3 srcIP:%v, SrcPort:%v, "+
					"DstIP:%v, DstPort:%v, Method: %v, Resp: %v, CallID: %v, FromHost: %v, ToHost: %v",
					h.SrcIP,
					h.SrcPort,
					h.DstIP,
					h.DstPort,
					SIP.CseqMethod,
					response,
					SIP.CallID,
					SIP.FromHost,
					SIP.ToHost)
				incrementCounter(pkt.GetSrcIP(), pkt.GetDstIP(), SIP.CseqMethod, response, SIP.ToHost)
			} else {
				logp.Err("Error decoding HEP: %v", err)
			}

		}
		// publish metrics from here
	}
}

func incrementCounter(srcIp string, destIp string, method string, response string, host string) {
	var target = destIp
	if method != response {
		target = srcIp
	}
	promstats.KamailioSipResponse.WithLabelValues(method, response, target, host).Inc()
}
