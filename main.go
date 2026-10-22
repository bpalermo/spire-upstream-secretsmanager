// Command upstream-secretsmanager is a SPIRE UpstreamAuthority plugin that
// reads its intermediate CA from AWS Secrets Manager at every mint, with a
// validated local cache.
//
// With no arguments it serves the plugin to the SPIRE server that executed
// it. `upstream-secretsmanager install <dir>` copies the executable to
// <dir>/upstream-secretsmanager (mode 0755) and exits, for images that have no
// shell to copy it with. `--version` prints the version.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spiffe/spire-plugin-sdk/pluginmain"
	upstreamauthorityv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/upstreamauthority/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"

	"github.com/bpalermo/spire-upstream-secretsmanager/common/version"
	"github.com/bpalermo/spire-upstream-secretsmanager/plugin"
)

const name = "upstream-secretsmanager"

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr, serve); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", name, err)
		os.Exit(1)
	}
}

// serve serves the plugin; it does not return.
func serve() {
	p := plugin.New()
	pluginmain.Serve(
		upstreamauthorityv1.UpstreamAuthorityPluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}

// run parses args and prints the version, installs the executable, or calls
// serve.
func run(args []string, stdout, stderr io.Writer, serve func()) error {
	if len(args) > 0 && args[0] == "install" {
		if len(args) != 2 {
			return errors.New("usage: " + name + " install <dir>")
		}
		dst, err := install(args[1])
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(stdout, "installed %s\n", dst)
		return err
	}

	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "usage: %s [--version] | %s install <dir>\n", name, name)
		fs.PrintDefaults()
	}
	showVersion := fs.Bool("version", false, "print the version and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *showVersion {
		_, err := fmt.Fprintf(stdout, "%s %s\n", name, version.Version)
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected arguments %q", fs.Args())
	}
	serve()
	return nil
}

// install copies the running executable to dir/upstream-secretsmanager, mode
// 0755, through a temporary file and a rename, and returns the path.
func install(dir string) (dst string, err error) {
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	src, err := os.Open(self)
	if err != nil {
		return "", err
	}
	defer src.Close()

	dst = filepath.Join(dir, name)
	tmp, err := os.CreateTemp(dir, "."+name+".tmp-*")
	if err != nil {
		return "", err
	}
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
		}
	}()
	if _, err = io.Copy(tmp, src); err != nil {
		return "", err
	}
	if err = tmp.Chmod(0o755); err != nil {
		return "", err
	}
	if err = tmp.Sync(); err != nil {
		return "", err
	}
	if err = tmp.Close(); err != nil {
		return "", err
	}
	if err = os.Rename(tmp.Name(), dst); err != nil {
		return "", err
	}
	return dst, nil
}
