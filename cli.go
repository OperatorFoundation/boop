package main

import (
	"flag"
	"fmt"
	"strings"
)

type Args struct {
	listen  bool
	target  string
	message string
}

func parseArgs() Args {
	listen := flag.Bool("listen", false, "Listen for incoming boop messages")
	flag.Parse()

	args := Args{
		listen: *listen,
	}

	if !*listen && flag.NArg() > 0 {
		args.target = flag.Arg(0)
		args.message = strings.Join(flag.Args()[1:], " ")
	}

	return args
}

func printUsage() {
	fmt.Fprintf(flag.CommandLine.Output(), "Usage:\n")
	fmt.Fprintf(flag.CommandLine.Output(), "  boop --listen              Listen for boop messages\n")
	fmt.Fprintf(flag.CommandLine.Output(), "  boop <host> [message]      Send a boop to a host\n")
}
