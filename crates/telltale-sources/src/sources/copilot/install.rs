//! GitHub Copilot install inventory evidence definition.

use crate::install_inventory::AgentInstallDef;

pub(crate) const INSTALL: AgentInstallDef = AgentInstallDef {
    agent: "copilot",
    executables: &["copilot"],
    node_packages: &["@github/copilot"],
    extension_ids: &["github.copilot", "github.copilot-chat"],
    global_storage_ids: &["github.copilot", "github.copilot-chat"],
};

#[cfg(test)]
mod tests {
    use crate::install_inventory::{
        InstallConfidence, InstallInventoryContext, InstallPlatform,
        collect_install_inventory_for_platform, snapshot_to_event,
    };

    #[test]
    fn copilot_cli_install_evidence_is_metadata_only_and_independent_of_extensions() {
        for (platform, launcher, package) in [
            (InstallPlatform::Unix, Some("copilot"), false),
            (InstallPlatform::Windows, Some("copilot.exe"), false),
            (InstallPlatform::Windows, Some("copilot.cmd"), false),
            (InstallPlatform::Unix, None, true),
        ] {
            let temp = tempfile::tempdir().unwrap();
            let bin = temp.path().join("PRIVATE_INSTALL_PATH/bin");
            let node = temp.path().join("PRIVATE_INSTALL_PATH/node_modules");
            std::fs::create_dir_all(&bin).unwrap();
            if let Some(launcher) = launcher {
                std::fs::write(bin.join(launcher), b"not executable: PRIVATE_CONTENT").unwrap();
            }
            if package {
                let root = node.join("@github/copilot");
                std::fs::create_dir_all(&root).unwrap();
                std::fs::write(root.join("package.json"), b"not JSON: PRIVATE_CONTENT").unwrap();
            }
            let context = InstallInventoryContext {
                home: temp.path().into(),
                path_dirs: vec![bin],
                node_roots: vec![node],
                extension_roots: vec![],
                global_storage_roots: vec![],
            };
            let snapshot = collect_install_inventory_for_platform(&context, 1, platform);
            let copilot = snapshot
                .agents
                .iter()
                .find(|a| a.agent == "copilot")
                .unwrap();
            assert!(copilot.installed, "{platform:?} {launcher:?} {package}");
            assert_eq!(copilot.confidence, InstallConfidence::Confirmed);
            let present = copilot
                .signals
                .iter()
                .filter(|s| s.present)
                .collect::<Vec<_>>();
            assert_eq!(present.len(), 1);
            assert_eq!(
                present[0].kind,
                if package {
                    "node_package"
                } else {
                    "executable"
                }
            );
            assert_eq!(
                present[0].name,
                if package {
                    "@github/copilot"
                } else {
                    "copilot"
                }
            );
            assert!(present[0].path_hash.is_some());
            for serialized in [
                serde_json::to_string(&snapshot).unwrap(),
                serde_json::to_string(&snapshot_to_event(&snapshot).unwrap()).unwrap(),
            ] {
                assert!(!serialized.contains("PRIVATE_INSTALL_PATH"));
                assert!(!serialized.contains("PRIVATE_CONTENT"));
            }
        }
    }
}
