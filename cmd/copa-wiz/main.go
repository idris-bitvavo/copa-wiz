package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/project-copacetic/scanner-plugin-template/internal/wiz"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("Usage: %s <wiz container scan report.json>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Reads a Wiz CLI / CI-CD JSON report and prints a Copacetic v1alpha1 UpdateManifest on stdout.\n")
		os.Exit(1)
	}

	report, err := wiz.NewParser().Parse(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error parsing report: %v\n", err)
		os.Exit(1)
	}

	reportBytes, err := json.Marshal(report)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error serializing report: %v\n", err)
		os.Exit(1)
	}

	if _, err := os.Stdout.Write(reportBytes); err != nil {
		fmt.Fprintf(os.Stderr, "error writing report to stdout: %v\n", err)
		os.Exit(1)
	}
}
