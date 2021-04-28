package ipsec

import (
	"github.com/prometheus/common/log"
	"strconv"
	"github.com/strongswan/govici/vici"
	"fmt"
)

type status struct {
	up         bool
	status     connectionStatus
	bytesIn    int
	bytesOut   int
	packetsIn  int
	packetsOut int
}

type connectionStatus int

const (
	tunnelInstalled       connectionStatus = 0
	connectionEstablished connectionStatus = 1
	down                  connectionStatus = 2
	unknown               connectionStatus = 3
	ignored               connectionStatus = 4
)

func queryStatus(ipSecConfiguration *Configuration) map[string]*status {
	statusMap := map[string]*status{}

	for _, connection := range ipSecConfiguration.tunnel {
		if connection.ignored {
			statusMap[connection.name] = &status{
				up:     true,
				status: ignored,
			}
			continue
		} else {
			statusMap[connection.name] = &status{
				up:     false,
				status: down,
			}
		}
	}

        session, err := vici.NewSession()
        if err != nil {
                fmt.Println(err)
		return statusMap
        }
        defer session.Close()

        m := vici.NewMessage()

        ms, err := session.StreamedCommandRequest("list-sas", "list-sa", m)
        if err != nil {
                fmt.Println(err)
		return statusMap
        }

        for _, n := range ms.Messages() {
                if n.Err() != nil {
			log.Warnf("Unable to retrieve the status of Strongswan. Reason: %v",  err)
                }
                if len(n.Keys()) == 0 {
                }
                for _, k := range n.Keys() {
                        p := n.Get(k).(*vici.Message)

			statusMap[k] = &status{
				up:     true,
				status: extractStatus( fmt.Sprintf("%s", p.Get("state")) ),
			}

                        f := p.Get("child-sas").(*vici.Message)
                        for _, j := range f.Keys() {
                                t := f.Get(j).(*vici.Message)
				bytes_in, _ := strconv.Atoi(fmt.Sprintf("%s", t.Get("bytes-in")))
				bytes_out, _ := strconv.Atoi(fmt.Sprintf("%s", t.Get("bytes-out")))
				packets_in, _ := strconv.Atoi(fmt.Sprintf("%s", t.Get("packets-in")))
				packets_out, _ := strconv.Atoi(fmt.Sprintf("%s", t.Get("packets-out")))
			        statusMap[k] = &status{
					up:         true,
					status:     extractStatus( fmt.Sprintf("%s", t.Get("state")) ),
					bytesIn:	bytes_in,
					bytesOut:	bytes_out,
					packetsIn:	packets_in,
					packetsOut:	packets_out,
			        }
                        }
                }
        }

	return statusMap
}

func extractStatus(status string) connectionStatus {

	if status == "ESTABLISHED" {
		return connectionEstablished
	} else if status == "INSTALLED" {
		return tunnelInstalled
	} else {
		return unknown
	}

}
