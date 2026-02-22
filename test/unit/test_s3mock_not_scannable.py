"""
Regression tests for https://github.com/CERT-Polska/Artemis/issues/2310.

"s3mock" is an internal Docker-Compose service used only as a placeholder
S3-compatible endpoint for karton.  It must never be treated as a legitimate
scan target: the classifier must reject it, and the subdomain brute-forcer
must not have it in its wordlist (which would cause "s3mock.<real-domain>"
DNS queries to reach external resolvers).
"""

import os
import pathlib
import unittest

import yaml

from artemis.domains import is_domain


class TestS3MockNotScannable(unittest.TestCase):
    def test_s3mock_is_not_a_valid_domain(self) -> None:
        """'s3mock' must not be treated as a valid domain for scanning.

        Without a TLD, is_domain() must return False, so the classifier
        never creates a DOMAIN task for the karton S3-mock hostname.
        """
        self.assertFalse(is_domain("s3mock"))

    def test_s3mock_not_in_subdomain_wordlists(self) -> None:
        """'s3mock' must not appear in any subdomain brute-force wordlist.

        If it did, every scanned domain would trigger a DNS lookup for
        "s3mock.<domain>", leaking to external nameservers (see #2310).
        """
        wordlist_dir = os.path.join(os.path.dirname(__file__), "..", "..", "artemis", "modules", "data", "subdomains")
        for filename in os.listdir(wordlist_dir):
            filepath = os.path.join(wordlist_dir, filename)
            with open(filepath) as fh:
                for lineno, line in enumerate(fh, start=1):
                    stripped = line.strip()
                    if stripped.startswith("#") or not stripped:
                        continue
                    self.assertNotEqual(
                        stripped,
                        "s3mock",
                        msg=(
                            f"Found 's3mock' at {filename}:{lineno}. "
                            "This would cause DNS lookups for 's3mock.<scanned-domain>' "
                            "to reach external nameservers (issue #2310)."
                        ),
                    )

    def test_docker_compose_has_ndots0_for_artemis_image_services(self) -> None:
        """All Docker Compose services that use the Artemis image must set
        dns_opt: [ndots:0] so that the short hostname 's3mock' is resolved
        as an absolute name rather than being expanded with the host's DNS
        search domains (#2310).

        The test is skipped (rather than failing) when docker-compose.yaml
        cannot be found in the directory tree above this file, which happens
        in CI environments where tests are mounted at a path that doesn't
        include the repo root (e.g. /opt/test/).
        """
        # Walk upward from this file to find the repo root that contains
        # docker-compose.yaml.  We stop at the filesystem root.
        compose_path = None
        for parent in pathlib.Path(__file__).resolve().parents:
            candidate = parent / "docker-compose.yaml"
            if candidate.is_file():
                compose_path = candidate
                break

        if compose_path is None:
            self.skipTest(
                "docker-compose.yaml not present in the directory tree above "
                "this test file; skipping compose dns_opt guard test."
            )

        with compose_path.open() as fh:
            compose = yaml.safe_load(fh)

        artemis_image = "certpl/artemis"
        karton_system_image = "certpl/karton-system"
        karton_dashboard_image = "certpl/karton-dashboard"

        for service_name, service_cfg in compose.get("services", {}).items():
            image = service_cfg.get("image", "")
            if not (
                image.startswith(artemis_image)
                or image.startswith(karton_system_image)
                or image.startswith(karton_dashboard_image)
            ):
                continue
            dns_opt = service_cfg.get("dns_opt", [])
            self.assertIn(
                "ndots:0",
                dns_opt,
                msg=(
                    f"Service '{service_name}' (image: {image!r}) is missing "
                    "'ndots:0' in dns_opt. Add it to prevent DNS search-domain "
                    "expansion for internal hostnames like 's3mock' (issue #2310)."
                ),
            )

