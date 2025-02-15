package cmd

import (
	"fmt"
	"github.com/netnod/ipsec_exporter/exporter"
	"github.com/spf13/cobra"
	"os"
)

const (
	flagWebListenAddress = "web.listen-address"
)

var Version string
var RootCmd = &cobra.Command{
	Use:     "ipsec_exporter",
	Short:   "Prometheus exporter for ipsec status.",
	Long:    "",
	Run:     defaultCommand,
	Version: Version,
}

func init() {
	RootCmd.PersistentFlags().StringVar(&exporter.WebListenAddress, flagWebListenAddress,
		"0.0.0.0:9536",
		"Address on which to expose metrics.")
}

func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func defaultCommand(_ *cobra.Command, _ []string) {
	exporter.Serve()
}
