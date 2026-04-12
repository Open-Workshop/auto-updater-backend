import unittest

from core.instance_migration import (
    canonical_instance_spec,
    instance_needs_migration,
    instance_requires_runtime_recovery,
    migrated_instance_manifest,
)


INSTANCE = {
    "apiVersion": "auto-updater.miskler.ru/v1alpha1",
    "kind": "MirrorInstance",
    "metadata": {
        "name": "demo",
        "namespace": "auto-updater",
        "resourceVersion": "42",
        "uid": "uid-1",
        "generation": 7,
    },
    "spec": {
        "enabled": True,
        "source": {
            "steamAppId": 294100,
            "owGameId": 12,
            "language": "english",
        },
        "sync": {
            "pageSize": 77,
            "pollIntervalSeconds": 600,
            "customMirrorSetting": {"keep": True},
        },
        "credentials": {"secretRef": "demo-ow-credentials"},
        "parser": {"proxyPoolSecretRef": "demo-parser-proxies"},
        "steamcmd": {"proxy": {"type": "socks5", "secretRef": "demo-steamcmd-proxy"}},
        "storage": {
            "parser": {"size": "20Gi", "storageClassName": "local-path"},
            "runner": {"size": "10Gi", "storageClassName": "local-path"},
        },
    },
    "status": {
        "phase": "Ready",
    },
}


class InstanceMigrationTests(unittest.TestCase):
    def test_legacy_instance_needs_migration(self) -> None:
        self.assertTrue(instance_needs_migration(INSTANCE))
        self.assertFalse(instance_requires_runtime_recovery(INSTANCE))

    def test_migrated_manifest_uses_canonical_spec_only(self) -> None:
        migrated = migrated_instance_manifest(INSTANCE)

        self.assertEqual(migrated["spec"], canonical_instance_spec(INSTANCE))
        self.assertEqual(migrated["spec"]["parser"]["type"], "steam-workshop")
        self.assertEqual(migrated["spec"]["parser"]["config"]["steamAppId"], 294100)
        self.assertEqual(migrated["spec"]["parser"]["config"]["pageSize"], 77)
        self.assertEqual(
            migrated["spec"]["parser"]["config"]["customMirrorSetting"],
            {"keep": True},
        )
        self.assertEqual(
            migrated["spec"]["parser"]["secretRefs"]["parserProxyPoolSecretRef"],
            "demo-parser-proxies",
        )
        self.assertEqual(
            migrated["spec"]["parser"]["workloads"]["steamcmd"]["config"]["proxyType"],
            "socks5",
        )
        self.assertEqual(
            migrated["spec"]["parser"]["workloads"]["parser"]["storage"]["size"],
            "20Gi",
        )
        self.assertNotIn("source", migrated["spec"])
        self.assertNotIn("sync", migrated["spec"])
        self.assertNotIn("steamcmd", migrated["spec"])
        self.assertNotIn("storage", migrated["spec"])
        self.assertNotIn("status", migrated)
        self.assertEqual(migrated["metadata"]["resourceVersion"], "42")
        self.assertNotIn("uid", migrated["metadata"])
        self.assertNotIn("generation", migrated["metadata"])

    def test_canonical_instance_does_not_need_migration(self) -> None:
        canonical = {
            "apiVersion": INSTANCE["apiVersion"],
            "kind": INSTANCE["kind"],
            "metadata": {
                "name": "demo",
                "namespace": "auto-updater",
            },
            "spec": canonical_instance_spec(INSTANCE),
        }

        self.assertFalse(instance_needs_migration(canonical))
        self.assertFalse(instance_requires_runtime_recovery(canonical))

    def test_pruned_instance_requires_runtime_recovery(self) -> None:
        pruned = {
            "apiVersion": INSTANCE["apiVersion"],
            "kind": INSTANCE["kind"],
            "metadata": {
                "name": "rimworld-main",
                "namespace": "auto-updater",
            },
            "spec": {
                "enabled": True,
                "credentials": {"secretRef": "rimworld-main-ow-credentials"},
                "parser": {},
            },
        }

        self.assertTrue(instance_requires_runtime_recovery(pruned))


if __name__ == "__main__":
    unittest.main()
