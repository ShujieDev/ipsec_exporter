package ipsec

import (
	"log"
	"time"
	"github.com/strongswan/govici/vici"
)

type connection struct {
	name    string
	ignored bool
}

type Configuration struct {
	tunnel []connection
}

func (c *Configuration) HasTunnels() bool {
	return len(c.tunnel) != 0
}

// NewConfiguration creates a Configuration struct out of an IPsec configuration from the filesystem.
func NewConfiguration() (*Configuration, error) {
	return newIpSecConfigLoader().Load()
}

type ipSecConfigurationLoader struct {
	FileName string
}

func newIpSecConfigLoader() *ipSecConfigurationLoader {
	return &ipSecConfigurationLoader{
	}
}

func (l *ipSecConfigurationLoader) Load() (*Configuration, error) {
	var connections []connection
	var err error

        session, err := vici.NewSession()
        for err != nil {
		log.Printf("Unable to establish vici session '%v'", err)
		time.Sleep(10 * time.Second)
		session, err = vici.NewSession()
        }
        defer session.Close()

        m := vici.NewMessage()

        ms, err := session.StreamedCommandRequest("list-conns", "list-conn", m)
        if err != nil {
		log.Printf("Unable to make the request in the vici session '%v'", err)
        }

        for _, n := range ms.Messages() {
                if n.Err() != nil {
			log.Printf("Unable error: '%v'", err)
                }
                if len(n.Keys()) == 0 {
                }
                for _, k := range n.Keys() {
			connections = append(connections, connection{name: k, ignored: false})
                }

        }


	return &Configuration{
		tunnel: connections,
	}, err
}
