// Package imagevolume_test mounts the plugin's own image as a Kubernetes
// image volume in a throwaway kind cluster (kind's containerd) and execs the
// binary from it, the way SPIRE server pods run the plugin.
//
// It answers: does the volume mount, does containerd unpack the image's
// tar+zstd layer, is the mount executable (not noexec), can a non-root user
// exec it, and which subPath forms work. CRI-O is not covered: kind nodes run
// containerd only.
//
// The image is the repository's //:image_index, as
// the OCI layout tarball rules_img builds; it is imported into the node's
// containerd with `ctr images import --all-platforms`, so its blobs, zstd
// layer included, reach containerd as built (no registry, no conversion).
//
// Needs a local Docker daemon and kind on PATH; the cluster is named susm-*
// and deleted at the end.
package imagevolume_test

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/bazelbuild/rules_go/go/runfiles"

	"github.com/bpalermo/spire-upstream-secretsmanager/verifiers/internal/docker"
)

var ociTarball = flag.String("oci_tarball", "", "runfiles path (rlocationpath) of the plugin image's OCI layout tarball")

// Pinned by the digest of the multi-platform index; Kubernetes v1.36, where
// ImageVolume is GA.
const (
	nodeImage    = "kindest/node:v1.36.4@sha256:099e049362a1526b2db71494e1947aae99bd16290d7c895f2b7ea312e3cbfaed"
	busyboxImage = "busybox:1.37.0@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e"
	pluginRef    = "localhost/spire-upstream-secretsmanager:verifier"
)

const podsYAML = `
apiVersion: v1
kind: Pod
metadata: {name: plugin}
spec:
  restartPolicy: Never
  containers:
  # The binary as a container's command: runc execs it from the volume.
  - name: run
    image: %[1]s
    command: ["/plugin/upstream-secretsmanager", "--version"]
    volumeMounts: [{name: plugin, mountPath: /plugin}]
  # The same as an unprivileged user, as SPIRE server runs.
  - name: nonroot
    image: %[1]s
    command: ["/plugin/upstream-secretsmanager", "--version"]
    securityContext: {runAsUser: 65532, runAsGroup: 65532, runAsNonRoot: true}
    volumeMounts: [{name: plugin, mountPath: /plugin}]
  # A shell beside the volume, for kubectl exec and /proc/mounts; the second
  # mount is a directory subPath (the image root).
  - name: shell
    image: %[1]s
    command: ["sleep", "3600"]
    volumeMounts:
    - {name: plugin, mountPath: /plugin}
    - {name: plugin, mountPath: /subdir, subPath: .}
  volumes:
  - name: plugin
    image: {reference: "%[2]s", pullPolicy: Never}
---
apiVersion: v1
kind: Pod
metadata: {name: subpath-file}
spec:
  restartPolicy: Never
  containers:
  # A file subPath: the binary itself mounted at a path of its own.
  - name: run
    image: %[1]s
    command: ["/opt/spire/plugins/upstream-secretsmanager", "--version"]
    volumeMounts:
    - {name: plugin, mountPath: /opt/spire/plugins/upstream-secretsmanager, subPath: upstream-secretsmanager}
  volumes:
  - name: plugin
    image: {reference: "%[2]s", pullPolicy: Never}
`

func TestImageVolume(t *testing.T) {
	docker.Require(t)
	tarball, err := runfiles.Rlocation(*ociTarball)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("RESULT imagevolume layer media types: %s", layerMediaTypes(t, tarball))

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	cluster := docker.Name("iv")
	kubeconfig := filepath.Join(t.TempDir(), "kubeconfig")
	kind := func(ctx context.Context, args ...string) (string, error) {
		out, err := exec.CommandContext(ctx, "kind", args...).CombinedOutput()
		return strings.TrimSpace(string(out)), err
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if out, err := kind(ctx, "delete", "cluster", "--name", cluster, "--kubeconfig", kubeconfig); err != nil {
			t.Errorf("kind delete cluster %s: %v\n%s", cluster, err, out)
		}
	})
	if out, err := kind(ctx, "create", "cluster", "--name", cluster, "--image", nodeImage, "--kubeconfig", kubeconfig, "--wait", "3m"); err != nil {
		t.Fatalf("kind create cluster: %v\n%s", err, out)
	}
	node := cluster + "-control-plane"
	kubectl := func(args ...string) (string, error) {
		return docker.Run(ctx, append([]string{"exec", "-i", node, "kubectl", "--kubeconfig", "/etc/kubernetes/admin.conf"}, args...)...)
	}
	must := func(out string, err error) string {
		t.Helper()
		if err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		return out
	}

	version := must(kubectl("version"))
	t.Logf("RESULT imagevolume cluster: %s", strings.ReplaceAll(version, "\n", " | "))
	t.Logf("RESULT imagevolume containerd: %s", must(docker.Run(ctx, "exec", node, "containerd", "--version")))
	gates := must(kubectl("get", "--raw", "/metrics"))
	var gate string
	for _, l := range strings.Split(gates, "\n") {
		if strings.HasPrefix(l, `kubernetes_feature_enabled{name="ImageVolume"`) {
			gate = l
		}
	}
	t.Logf("RESULT imagevolume feature gate: %s", gate)
	if !strings.HasSuffix(gate, " 1") {
		t.Fatalf("ImageVolume is not enabled: %q", gate)
	}

	must(docker.RunStdin(ctx, tarball, "exec", "-i", node, "ctr", "-n", "k8s.io", "images", "import",
		"--all-platforms", "--index-name", pluginRef, "-"))
	t.Logf("RESULT imagevolume imported: %s", docker.LastLine(must(docker.Run(ctx, "exec", node, "ctr", "-n", "k8s.io", "images", "ls")), pluginRef))

	manifest := filepath.Join(t.TempDir(), "pods.yaml")
	if err := os.WriteFile(manifest, []byte(fmt.Sprintf(podsYAML, busyboxImage, pluginRef)), 0o644); err != nil {
		t.Fatal(err)
	}
	must(docker.RunStdin(ctx, manifest, "exec", "-i", node, "kubectl", "--kubeconfig", "/etc/kubernetes/admin.conf", "apply", "-f", "-"))
	waitFor := func(what, pod, jsonpath string) string {
		t.Helper()
		var last string
		docker.WaitFor(t, what, 3*time.Minute, func() error {
			out, err := kubectl("get", "pod", pod, "-o", "jsonpath="+jsonpath)
			last = out
			if err != nil || out == "" {
				return fmt.Errorf("%v: %q", err, out)
			}
			return nil
		})
		return last
	}

	for _, c := range []string{"run", "nonroot"} {
		code := waitFor(c, "plugin", `{.status.containerStatuses[?(@.name=="`+c+`")].state.terminated.exitCode}`)
		logs, _ := kubectl("logs", "plugin", "-c", c)
		t.Logf("RESULT imagevolume container %s: exit %s, output %q", c, code, logs)
		if code != "0" || !strings.HasPrefix(logs, "upstream-secretsmanager ") {
			t.Errorf("container %s: exit %s, output %q", c, code, logs)
		}
	}

	waitFor("shell", "plugin", `{.status.containerStatuses[?(@.name=="shell")].state.running.startedAt}`)
	for _, dir := range []string{"/plugin", "/subdir"} {
		mounts := must(kubectl("exec", "plugin", "-c", "shell", "--", "grep", " "+dir+" ", "/proc/mounts"))
		var opts []string
		for _, o := range strings.Split(strings.Fields(mounts)[3], ",") {
			if !strings.Contains(o, "dir=") {
				opts = append(opts, o)
			}
		}
		out, err := kubectl("exec", "plugin", "-c", "shell", "--", dir+"/upstream-secretsmanager", "--version")
		t.Logf("RESULT imagevolume kubectl exec %s/upstream-secretsmanager: %q (err %v); mount options %s", dir, out, err, opts)
		if err != nil || !strings.HasPrefix(out, "upstream-secretsmanager ") {
			t.Errorf("exec from %s: %v %q", dir, err, out)
		}
		if slices.Contains(opts, "noexec") || !slices.Contains(opts, "ro") {
			t.Errorf("%s mount options %s: want ro and not noexec", dir, opts)
		}
	}

	// containerd mounts only directories of an image volume as a subPath; a
	// file subPath fails container creation. The plugin image has the binary
	// at its root, so SPIRE mounts the whole volume (or subPath ".").
	msg := waitFor("subpath-file", "subpath-file", `{.status.containerStatuses[0].state.waiting.message}`)
	reason, _ := kubectl("get", "pod", "subpath-file", "-o", "jsonpath={.status.containerStatuses[0].state.waiting.reason}")
	t.Logf("RESULT imagevolume file subPath: %s: %s", reason, msg)
	if !strings.Contains(msg, "only directory subpath is supported") {
		t.Errorf("file subPath: got %s %q, want containerd's only-directory error (did containerd start supporting it?)", reason, msg)
	}
}

// layerMediaTypes reads the OCI layout tarball and returns the layer media
// types of every manifest of its index.
func layerMediaTypes(t *testing.T, path string) string {
	t.Helper()
	blobs := map[string][]byte{}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	tr := tar.NewReader(f)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if h.Typeflag != tar.TypeReg || h.Size > 1<<20 {
			continue
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		blobs[strings.TrimPrefix(h.Name, "./")] = b
	}
	type desc struct {
		MediaType string `json:"mediaType"`
		Digest    string `json:"digest"`
		Platform  *struct {
			Architecture string `json:"architecture"`
		} `json:"platform"`
	}
	var index struct {
		Manifests []desc `json:"manifests"`
	}
	if err := json.Unmarshal(blobs["index.json"], &index); err != nil {
		t.Fatalf("index.json: %v", err)
	}
	var out []string
	for _, m := range index.Manifests {
		var man struct {
			Layers []desc `json:"layers"`
		}
		if err := json.Unmarshal(blobs["blobs/sha256/"+strings.TrimPrefix(m.Digest, "sha256:")], &man); err != nil {
			t.Fatalf("manifest %s: %v", m.Digest, err)
		}
		for _, l := range man.Layers {
			out = append(out, m.Platform.Architecture+"="+l.MediaType)
			if !strings.HasSuffix(l.MediaType, "+zstd") {
				t.Errorf("%s layer %s is %s, want zstd", m.Platform.Architecture, l.Digest, l.MediaType)
			}
		}
	}
	return strings.Join(out, " ")
}
