package publish

import (
	"github.com/negbie/logp"
	"github.com/sipcapture/heplify/decoder"
	"github.com/sipcapture/heplify/promstats"
	"github.com/sipcapture/heplify/sipparser"
	"net"
	"strings"
)

type Publisher struct {
}

var myIp = GetLocalIPs().String()

type void struct{}

var member void
var domainToIpMap = make(map[string]map[string]void)
var fsBnrIp = make(map[string]void)

func GetLocalIPs() net.IP {
	var ips []net.IP
	addresses, _ := net.InterfaceAddrs()

	for _, addr := range addresses {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				ips = append(ips, ipnet.IP)
			}
		}
	}
	return ips[0]
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
			var response = getResponseStr(SIP)
			logp.Debug("srcIP:%v, SrcPort:%v, "+
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
			if pkt.GetDstPort() == 5080 {
				fsBnrIp[pkt.GetDstIP()] = member
			}
			if pkt.GetSrcPort() == 5080 {
				fsBnrIp[pkt.GetSrcIP()] = member
			}
			incrementCounter(pkt.GetSrcIP(), pkt.GetDstIP(), SIP.CseqMethod, response, "FS/BNR")
		} else if pkt.GetDstPort() == 9060 {
			h, err := DecodeHEP(pkt.Payload)
			if err == nil {
				var payload = h.Payload
				var SIP = sipparser.ParseMsg(string(payload), nil, nil)
				response := getResponseStr(SIP)
				logp.Debug("PARSED HEP3 srcIP: %v, SrcPort:%v, "+
					"DstIP:%v, DstPort:%v, Method: %v, Resp: %v, CallID: %v, FromHost: %v, ToHost: %v",
					h.SrcIP.String(),
					h.SrcPort,
					h.DstIP,
					h.DstPort,
					SIP.CseqMethod,
					response,
					SIP.CallID,
					SIP.FromHost,
					SIP.ToHost)

				var host = SIP.ToHost
				if host != myIp {
					logp.Debug("domainToIpMap", "%v", domainToIpMap)
					targetIp := getTarget(h.SrcIP.String(), h.DstIP.String(), SIP.CseqMethod, response)
					if targetIp != myIp {
						if net.ParseIP(host) == nil {
							_, ok := fsBnrIp[targetIp]
							if (strings.Contains(host, "rt.intg") ||
								strings.Contains(host, "rt.qa") ||
								strings.Contains(host, "rt.load") ||
								strings.Contains(host, "rt.prod") ||
								strings.Contains(host, "rtg.intg") ||
								strings.Contains(host, "rtg.qa") ||
								strings.Contains(host, "rtg.load") ||
								strings.Contains(host, "rtg.prod")) && !ok {
								host = getHostName(host, targetIp)
							} else {
								if set, ok := domainToIpMap[host]; ok {
									set[targetIp] = member
								} else {
									domainToIpMap[host] = make(map[string]void)
									domainToIpMap[host][targetIp] = member
								}
							}
						} else {
							// GOT IP, Resolve
							host = getHostName(host, targetIp)
						}
					}
				}
				incrementCounter(h.SrcIP.String(), h.DstIP.String(), SIP.CseqMethod, response, host)
			} else {
				logp.Err("Error decoding HEP: %v", err)
			}

		}
		// publish metrics from here
	}
}

func getHostName(host string, targetIp string) string {
	var oldHost = host
	for k, v := range domainToIpMap {
		if _, ok := v[targetIp]; ok {
			host = k
			break
		}
	}
	if oldHost == host {
		host = "Unknown"
	}
	return host
}

func getResponseStr(SIP *sipparser.SipMsg) string {
	var response = SIP.FirstResp
	if response == "" {
		response = SIP.FirstMethod
	}
	return response
}

func incrementCounter(srcIp string, destIp string, method string, response string, host string) {
	target := getTarget(srcIp, destIp, method, response)
	if target == myIp {
		host = "KAM"
	}

	promstats.KamailioSipResponse.WithLabelValues(method, response, target, host).Inc()
}

func getTarget(srcIp string, destIp string, method string, response string) string {
	var target = destIp
	if method != response {
		target = srcIp
	}
	return target
}
