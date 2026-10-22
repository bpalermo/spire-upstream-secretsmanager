// Package protodeps keeps go.mod's requirements on the Go packages that only
// the generated (uncommitted) .pb.go files import, so that `go mod tidy`
// does not drop them and `bazel mod tidy` their use_repo.
package protodeps

import (
	// The buf/validate annotations every proto of this repository imports.
	_ "buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go/buf/validate"
)
