"""Where the plugin image is published: ONE setting.

Every published coordinate is derived from the constants below: the
`image_push` of //upstream-secretsmanager. Shell and the workflows read it
through bazel/registry.sh, and bazel/check-registry-config.sh fails CI on a
registry spelled out anywhere else. Nothing else may spell the registry out.

The coordinate:

    <IMAGE_REGISTRY>/<IMAGE_NAMESPACE>/spire-upstream-secretsmanager

Keep each assignment below on ONE line, exactly `NAME = "value"`, so a script
can read it with a line-anchored grep.
"""

# Registry host.
IMAGE_REGISTRY = "quay.io"

# Organization under the host. Quay has NO nested repositories: everything is
# `<host>/<namespace>/<name>`, one path segment after the org.
IMAGE_NAMESPACE = "palermo"

# Where cosign's keyless signature lands on IMAGE_REGISTRY, which the release
# workflow ASSERTS for every digest it signs: "referrer" (an OCI 1.1 referrer
# and no tag -- a registry that serves the Referrers API, as quay.io does) or
# "tag" (cosign 3's `sha256-<hex>` fallback tag -- a registry without it).
SIGNATURE_LAYOUT = "referrer"

def image_repository(component):
    """Repository path (no host) of a component's image.

    Args:
      component: "spire-upstream-secretsmanager".

    Returns:
      e.g. "palermo/spire-upstream-secretsmanager".
    """
    return "{}/{}".format(IMAGE_NAMESPACE, component)

def image_reference(component):
    """Host-qualified image repository of a component.

    Args:
      component: "spire-upstream-secretsmanager".

    Returns:
      e.g. "quay.io/palermo/spire-upstream-secretsmanager".
    """
    return "{}/{}".format(IMAGE_REGISTRY, image_repository(component))
