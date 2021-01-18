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
	"os/exec"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	addr        = flag.String("listen-address", ":7070", "The address to listen on for HTTP requests.")
	agentsTotal = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "ossec_metrics",
		Name:      "total_agents",
		Help:      "total number of agents.",
	})
	agentsActive = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "ossec_metrics",
		Name:      "active_agents",
		Help:      "total number of active agents.",
	})
)

func init() {
	// Register the summary and the histogram with Prometheus's default registry.
	prometheus.MustRegister(agentsTotal)
	prometheus.MustRegister(agentsActive)
	// Add Go module build info.
	prometheus.MustRegister(prometheus.NewBuildInfoCollector())
}

func main() {
	flag.Parse()
	http.Handle("/metrics", promhttp.Handler())
	go checkAgents()
	go checkhealthy()
	log.Fatal(http.ListenAndServe(*addr, nil))
}

func checkAgents() {
	t := time.NewTicker(20 * time.Second)
	defer t.Stop()
	var out bytes.Buffer
	for {
		select {
		case <-t.C:
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
			agentsTotal.Set(float64(total))
			agentsActive.Set(float64(active))
			fmt.Printf("Found %d active out of %d total agents\n", active, total)
			out.Reset()
		}
	}
}

func checkhealthy() {
    cmd := exec.Command("/var/ossec/bin/ossec-control", "-j", "status")
    var str = cmd.Stdout
    basicReader := strings.NewReader(str)
    var b = make([]byte, basicReader.Size())
    _, err :=basicReader.Read(b)
    if err !=nil {
     	panic(err)
    }
    output := map[string]interface{
    }{
    }
    err = json.Unmarshal(b, &output)
    if err !=nil{
      	panic(err)
    }
    for _,data :=range output["data"].([]interface {}){
        data :=data.(map[string]interface{})
      	daemon := strings.Replace(data["daemon"].(string), "-","_",-1)
        if data["status"].(string) == "running"{
       	fmt.Printf("%s_up 1",daemon)
       	fmt.Println()
   	} else if data["status"].(string) == "stopped"{
   		fmt.Printf("%s_up 0",daemon)
   		fmt.Println()
   	}
    }
}