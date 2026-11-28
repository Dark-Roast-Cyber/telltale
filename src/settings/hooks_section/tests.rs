use super::*;

#[cfg(test)]
#[test]
fn telemetry_rotation_settings_merge_by_field() {
    let mut settings = HooksSettings::default();
    assert_eq!(
        settings.config().telemetry_rotation,
        RotationConfig::default()
    );
    settings.apply_document(
        serde_yaml::from_str("telemetry: {max_size_bytes: 1024, keep: 3}").unwrap(),
        Path::new("synthetic-system.yaml"),
    );
    settings.apply_document(
        serde_yaml::from_str("telemetry: {max_size_bytes: 0}").unwrap(),
        Path::new("synthetic-managed.yaml"),
    );
    assert_eq!(
        settings.config().telemetry_rotation,
        RotationConfig {
            max_size_bytes: 0,
            keep: 3
        }
    );
    assert!(serde_yaml::from_str::<HooksSection>("telemetry: {keep: -1}").is_err());
    assert!(serde_yaml::from_str::<HooksSection>("telemetry: {unknown: true}").is_err());
}
