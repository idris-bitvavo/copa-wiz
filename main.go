package main

import (
	"encoding/json"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("Usage: %s <wiz container scan report.json>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Reads a Wiz CLI / CI-CD JSON report and prints a Copacetic v1alpha1 UpdateManifest on stdout.\n")
		os.Exit(1)
	}

	parser := newWizParser()
	report, err := parser.parse(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error parsing report: %v\n", err)
		os.Exit(1)
	}

	reportBytes, err := json.Marshal(report)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error serializing report: %v\n", err)
		os.Exit(1)
	}

	os.Stdout.Write(reportBytes)
}
