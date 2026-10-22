"""Where the plugin image is published: ONE setting.

The `image_push` of //:upstream-secretsmanager derives its coordinates from
the constants below, and so does the release workflow, through the Bazel
target. Nothing else may spell the registry out.

The coordinate:

    <IMAGE_REGISTRY>/<IMAGE_NAMESPACE>/spire-upstream-secretsmanager
"""

# Registry host.
IMAGE_REGISTRY = "ghcr.io"

# Owner under the host.
IMAGE_NAMESPACE = "bpalermo"

def image_repository():
    """Repository path (no host) of the plugin image.

    Returns:
      "bpalermo/spire-upstream-secretsmanager".
    """
    return "{}/spire-upstream-secretsmanager".format(IMAGE_NAMESPACE)

def image_reference():
    """Host-qualified image repository of the plugin image.

    Returns:
      "ghcr.io/bpalermo/spire-upstream-secretsmanager".
    """
    return "{}/{}".format(IMAGE_REGISTRY, image_repository())
