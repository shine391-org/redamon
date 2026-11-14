package main

import (
	"fmt"
	"os"

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
		// Validate BEFORE any target traffic is generated. An invalid --proxy
		// must never degrade into a direct connection: the caller attaches
		// X-Redamon-Ctx to every request, and a direct run would leak that
		// signed tag to the target. The patched clients also install an
		// always-error dial function as defence in depth.
		if err := http.ValidateProxyURL(proxyURL); err != nil {
			fmt.Fprintf(os.Stderr, "kr: refusing to run with invalid --proxy: %v\n", err)
			os.Exit(1)
		}
		http.SetProxyURL(proxyURL)
	}
	cmd.Execute()
}
