use compute_api::spec::{ComputeSpec, RestrictedRole};

#[test]
fn restricted_role_debug_redacts_verifier_but_serialization_preserves_it() {
    let verifier = "SCRAM-SHA-256$4096:c2FsdA==$cHJvb2Y=:c2VydmVy";
    let role = RestrictedRole {
        name: "appthrust_broker_reader_a".into(),
        encrypted_password: Some(verifier.into()),
        login: true,
        member_of: vec!["appthrust_postgrest".into()],
    };

    let debug = format!("{role:?}");
    assert!(!debug.contains(verifier), "Debug exposed a role verifier");
    assert!(debug.contains("<redacted>"));

    let json = serde_json::to_string(&role).unwrap();
    assert!(json.contains(verifier), "compute spec lost the verifier");
    let decoded: RestrictedRole = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, role);
}

#[test]
fn old_compute_specs_keep_the_restricted_collection_absent() {
    let spec: ComputeSpec = serde_json::from_str(include_str!("cluster_spec.json")).unwrap();
    assert!(spec.cluster.restricted_roles.is_empty());
    let serialized = serde_json::to_string(&spec).unwrap();
    assert!(!serialized.contains("\"restricted_roles\""));
}
