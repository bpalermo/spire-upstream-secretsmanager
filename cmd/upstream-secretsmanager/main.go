// Command upstream-secretsmanager is a SPIRE UpstreamAuthority plugin that
// reads its intermediate CA from AWS Secrets Manager at every mint, with a
// validated local cache.
//
// This is the build skeleton: the plugin itself comes later. Until then the
// binary reports its version and refuses to run.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/bpalermo/spire-upstream-secretsmanager/common/version"
)

const name = "upstream-secretsmanager"

var errNotImplemented = errors.New("the plugin is not implemented yet")

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", name, err)
		os.Exit(1)
	}
}

// run parses args and either prints the version or reports that there is
// nothing to run yet.
func run(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	showVersion := fs.Bool("version", false, "print the version and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *showVersion {
		_, err := fmt.Fprintf(stdout, "%s %s\n", name, version.Version)
		return err
	}
	return errNotImplemented
}
