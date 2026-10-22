"""Where the plugin image is published.

The `image_push` of //upstream-secretsmanager pushes to

    <IMAGE_REGISTRY>/<IMAGE_NAMESPACE>/spire-upstream-secretsmanager

release.yml names the same coordinate once, in its IMAGE variable, and fails
a release whose push went anywhere else.
"""

# Registry host.
IMAGE_REGISTRY = "quay.io"

# Organization under the host. Quay has NO nested repositories: everything is
# `<host>/<namespace>/<name>`, one path segment after the org.
IMAGE_NAMESPACE = "palermo"

def image_repository(component):
    """Repository path (no host) of a component's image.

    Args:
      component: "spire-upstream-secretsmanager".

    Returns:
      e.g. "palermo/spire-upstream-secretsmanager".
    """
    return "{}/{}".format(IMAGE_NAMESPACE, component)
