package main

import (
	"fmt"
	"os"
)

const version = "0.5.0"

func main() {
	args := parseArgs()

	if args.listen {
		if err := listenForBoops(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	} else if args.target != "" {
		if err := sendBoop(args.target, args.message); err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}
	} else {
		printUsage()
		os.Exit(1)
	}
}
