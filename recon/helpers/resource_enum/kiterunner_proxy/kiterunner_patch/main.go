package main

import (
	"github.com/assetnote/kiterunner/cmd/kiterunner/cmd"
	"github.com/assetnote/kiterunner/pkg/http"
	"github.com/spf13/cobra"
)

var proxyURL string

func init() {
	cmd.RootCmd.PersistentFlags().StringVar(&proxyURL, "proxy", "", "HTTP CONNECT proxy for target requests (capture route)")
}

func main() {
	cmd.RootCmd.PersistentPreRun = func(c *cobra.Command, args []string) {
		http.SetProxyURL(proxyURL)
	}
	cmd.Execute()
}
