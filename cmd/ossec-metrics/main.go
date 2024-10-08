package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	addr = flag.String("listen-address", ":7070", "The address to listen on for HTTP requests.")
	// agentsTotal = prometheus.NewGauge(prometheus.GaugeOpts{
	// 	Namespace: "ossec_metrics",
	// 	Name:      "total_agents",
	// 	Help:      "total number of agents.",
	// })
	// agentsActive = prometheus.NewGauge(prometheus.GaugeOpts{
	// 	Namespace: "ossec_metrics",
	// 	Name:      "active_agents",
	// 	Help:      "total number of active agents.",
	// })
)

var previous_total = 0
var previous_active = 0

func init() {
	// Register the summary and the histogram with Prometheus's default registry.
	// prometheus.MustRegister(agentsTotal)
	// prometheus.MustRegister(agentsActive)
	// Add Go module build info.
	prometheus.MustRegister(prometheus.NewBuildInfoCollector())
}

type Collector struct {
}

func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- prometheus.NewDesc("empty", "empty", nil, nil)
}

func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	checkHealthy(ch)
	checkAgents(ch)
	// log.Println("End collect metric values")
}

func prometheusMetricshandler(w http.ResponseWriter, r *http.Request) {
	registry := prometheus.NewRegistry()
	collector := &Collector{}
	registry.MustRegister(collector)
	h := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	h.ServeHTTP(w, r)
}

func main() {
	flag.Parse()
	http.HandleFunc("/metrics", prometheusMetricshandler)
	log.Fatal(http.ListenAndServe(*addr, nil))
}

func checkAgents(ch chan<- prometheus.Metric) {
	var out bytes.Buffer
	cmd := exec.Command("/var/ossec/bin/agent_control", "-ls")
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		log.Println(err)
	}
	r := csv.NewReader(strings.NewReader(out.String()))
	total := 0
	active := 0
	for {
		record, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Println(err)
			break
		}
		total++
		if len(record) >= 4 {
			if strings.HasPrefix(record[3], "Active") {
				active++
			}
		}
	}
	if (active != previous_active) || (total != previous_total) {
		previous_total = total
		previous_active = active
		fmt.Printf("Found %d active out of %d total agents\n", active, total)
	}
	// agentsTotal.Set(float64(total))
	// agentsActive.Set(float64(active))
	ch <- prometheus.MustNewConstMetric(
		prometheus.NewDesc("ossec_total_agents", "ossec_total_agents", nil, nil),
		prometheus.GaugeValue,
		float64(total),
	)
	ch <- prometheus.MustNewConstMetric(
		prometheus.NewDesc("ossec_active_agents", "ossec_active_agents", nil, nil),
		prometheus.GaugeValue,
		float64(active),
	)
	out.Reset()
}

func checkHealthy(ch chan<- prometheus.Metric) {
	var out bytes.Buffer
	cmd := exec.Command("/var/ossec/bin/ossec-control", "-j", "status")
	if _, err := os.Stat("/var/ossec/bin/wazuh-control"); err == nil {
		cmd = exec.Command("/var/ossec/bin/wazuh-control", "-j", "status")
	}
	cmd.Stdout = &out
	err := cmd.Run()
	// if err != nil {
	// 	log.Println(err)
	// }
	basicReader := strings.NewReader(out.String())
	var b = make([]byte, basicReader.Size())
	_, err = basicReader.Read(b)
	if err != nil {
		panic(err)
	}
	output := map[string]interface {
	}{}
	err = json.Unmarshal(b, &output)
	if err != nil {
		panic(err)
	}
	for _, data := range output["data"].([]interface{}) {
		data := data.(map[string]interface{})
		daemon := strings.Replace(data["daemon"].(string), "-", "_", -1)
		if data["status"].(string) == "running" {
			ch <- prometheus.MustNewConstMetric(
				prometheus.NewDesc(fmt.Sprintf("%s_up", daemon), fmt.Sprintf("%s_up", daemon), nil, nil),
				prometheus.GaugeValue,
				1,
			)
		} else if data["status"].(string) == "stopped" {
			ch <- prometheus.MustNewConstMetric(
				prometheus.NewDesc(fmt.Sprintf("%s_up", daemon), fmt.Sprintf("%s_up", daemon), nil, nil),
				prometheus.GaugeValue,
				0,
			)
		}
	}
	out.Reset()
}
