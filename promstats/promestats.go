package promstats

import (
	"net/http"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sipcapture/heplify/config"
)

var KamailioSipResponse = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "kamailio_sip_response",
		Help: "SIP method and response counter",
	},
	[]string{"method", "response", "target", "domain"},
)

func StartMetrics(wg *sync.WaitGroup) {
	wg.Add(1)

	prometheus.MustRegister(KamailioSipResponse)

	http.Handle("/metrics", promhttp.Handler())
	http.ListenAndServe(config.Cfg.PrometheusIPPort, nil)
	wg.Done()

}
