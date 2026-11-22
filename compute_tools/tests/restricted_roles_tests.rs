use std::collections::HashMap;

use compute_api::spec::{ComputeSpec, DeltaOp, RestrictedRole, Role};
use compute_tools::pg_helpers::{
    RestrictedRoleMembership, RestrictedRoleState, RoleExt, plan_restricted_role,
    plan_restricted_roles, validate_restricted_roles,
};

const VERIFIER: &str = "SCRAM-SHA-256$4096:AQIDBAUGBwgJCgsMDQ4PEA==$8rrDg00OqaiWXJ7p+sCgHEIaBSHY89ZJl3mfIsf32oY=:05L1f+yZbiN8O0AnO40Og85NNRhvzTS57naKRWCcsIA=";
const SAFE_FLAGS: &str = "NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS";
const PRIVILEGED: &str = "neon_superuser";

fn role() -> RestrictedRole {
    RestrictedRole {
        name: "appthrust_broker_reader_a".into(),
        encrypted_password: Some(VERIFIER.into()),
        login: true,
        member_of: vec!["appthrust_postgrest".into()],
    }
}

fn membership(name: &str) -> RestrictedRoleMembership {
    RestrictedRoleMembership {
        name: name.into(),
        grantor: "bootstrap_admin".into(),
        admin: false,
        inherit: false,
        set: true,
    }
}

fn observed() -> RestrictedRoleState {
    RestrictedRoleState {
        login: true,
        encrypted_password: Some(VERIFIER.into()),
        memberships: vec![membership("appthrust_postgrest")],
        ..Default::default()
    }
}

fn plan(role: &RestrictedRole, state: Option<&RestrictedRoleState>) -> anyhow::Result<Vec<String>> {
    plan_restricted_role(role, state, &"bootstrap_admin".into(), PRIVILEGED)
}

fn spec(roles: Vec<RestrictedRole>) -> ComputeSpec {
    let mut spec = ComputeSpec::default();
    spec.cluster.restricted_roles = roles;
    spec
}

#[test]
fn fresh_restricted_login_has_only_explicit_safe_attributes_and_memberships() {
    let queries = plan(&role(), None).unwrap();
    assert_eq!(queries, vec![
        format!("CREATE ROLE \"appthrust_broker_reader_a\" {SAFE_FLAGS} LOGIN PASSWORD '{VERIFIER}'"),
        "GRANT \"appthrust_postgrest\" TO \"appthrust_broker_reader_a\" WITH ADMIN FALSE, INHERIT FALSE, SET TRUE GRANTED BY \"bootstrap_admin\"".into(),
    ]);
}

#[test]
fn fresh_disabled_role_is_nologin_without_a_password() {
    let mut desired = role();
    desired.login = false;
    desired.encrypted_password = None;
    desired.member_of.clear();
    assert_eq!(
        plan(&desired, None).unwrap(),
        vec![format!(
            "CREATE ROLE \"appthrust_broker_reader_a\" {SAFE_FLAGS} NOLOGIN PASSWORD NULL"
        )]
    );
}

#[test]
fn disabling_existing_role_clears_password_and_extra_authority() {
    let mut desired = role();
    desired.login = false;
    desired.encrypted_password = None;
    desired.member_of.clear();
    let mut state = observed();
    state.inherit = true;
    state.create_role = true;
    state.create_db = true;
    state.replication = true;
    state.bypass_rls = true;
    assert_eq!(plan(&desired, Some(&state)).unwrap(), vec![
        format!("ALTER ROLE \"appthrust_broker_reader_a\" {SAFE_FLAGS} NOLOGIN PASSWORD NULL"),
        "REVOKE \"appthrust_postgrest\" FROM \"appthrust_broker_reader_a\" GRANTED BY \"bootstrap_admin\" RESTRICT".into(),
    ]);
}

#[test]
fn nologin_is_reconciled_even_when_password_is_already_null() {
    let mut desired = role();
    desired.login = false;
    desired.encrypted_password = None;
    let mut state = observed();
    state.encrypted_password = None;
    assert_eq!(
        plan(&desired, Some(&state)).unwrap(),
        vec![format!(
            "ALTER ROLE \"appthrust_broker_reader_a\" {SAFE_FLAGS} NOLOGIN PASSWORD NULL"
        )]
    );
}

#[test]
fn login_and_each_privilege_are_reconciled_without_password_change() {
    for attribute in 0..7 {
        let mut state = observed();
        match attribute {
            0 => state.login = false,
            1 => state.inherit = true,
            2 => state.superuser = true,
            3 => state.create_role = true,
            4 => state.create_db = true,
            5 => state.replication = true,
            6 => state.bypass_rls = true,
            _ => unreachable!(),
        }
        assert_eq!(
            plan(&role(), Some(&state)).unwrap(),
            vec![format!(
                "ALTER ROLE \"appthrust_broker_reader_a\" {SAFE_FLAGS} LOGIN PASSWORD '{VERIFIER}'"
            )],
            "attribute {attribute}"
        );
    }
}

#[test]
fn changing_memberships_does_not_depend_on_password_change() {
    let mut desired = role();
    desired.member_of = vec!["appthrust_postgrest_editor".into()];
    assert_eq!(plan(&desired, Some(&observed())).unwrap(), vec![
        "REVOKE \"appthrust_postgrest\" FROM \"appthrust_broker_reader_a\" GRANTED BY \"bootstrap_admin\" RESTRICT".to_owned(),
        "GRANT \"appthrust_postgrest_editor\" TO \"appthrust_broker_reader_a\" WITH ADMIN FALSE, INHERIT FALSE, SET TRUE GRANTED BY \"bootstrap_admin\"".into(),
    ]);
}

#[test]
fn direct_privileged_membership_drift_is_revoked() {
    let mut state = observed();
    state.memberships.push(membership(PRIVILEGED));
    assert_eq!(
        plan(&role(), Some(&state)).unwrap(),
        vec![
            "REVOKE \"neon_superuser\" FROM \"appthrust_broker_reader_a\" GRANTED BY \"bootstrap_admin\" RESTRICT"
        ]
    );
}

#[test]
fn membership_options_are_reconciled_without_password_change() {
    for option in 0..3 {
        let mut state = observed();
        match option {
            0 => state.memberships[0].admin = true,
            1 => state.memberships[0].inherit = true,
            2 => state.memberships[0].set = false,
            _ => unreachable!(),
        }
        assert_eq!(
            plan(&role(), Some(&state)).unwrap(),
            vec![
                "GRANT \"appthrust_postgrest\" TO \"appthrust_broker_reader_a\" WITH ADMIN FALSE, INHERIT FALSE, SET TRUE GRANTED BY \"bootstrap_admin\""
            ]
        );
    }
}

#[test]
fn foreign_grantors_fail_closed_for_desired_and_extra_memberships() {
    for group in ["appthrust_postgrest", PRIVILEGED] {
        let mut state = observed();
        let mut foreign = membership(group);
        foreign.grantor = "tenant_owner".into();
        state.memberships.push(foreign);
        assert_eq!(
            plan(&role(), Some(&state)).unwrap_err().to_string(),
            "restricted role has an unowned membership"
        );
    }
}

#[test]
fn converged_state_produces_no_role_writes() {
    assert!(plan(&role(), Some(&observed())).unwrap().is_empty());
    let mut desired = role();
    desired.login = false;
    desired.encrypted_password = None;
    let mut state = observed();
    state.login = false;
    state.encrypted_password = None;
    assert!(plan(&desired, Some(&state)).unwrap().is_empty());
}

#[test]
fn login_rejects_missing_plaintext_md5_and_malformed_scram() {
    let invalid = [
        None,
        Some("plaintext-do-not-log".into()),
        Some("md500000000000000000000000000000000".into()),
        Some("SCRAM-SHA-256$4096:salt$stored:server".into()),
        Some(VERIFIER.replace("$4096:", "$0:")),
        Some(VERIFIER.replace("$4096:", "$2147483648:")),
        Some(VERIFIER.replace("$4096:", "$-1:")),
        Some(VERIFIER.replace("$4096:", "$+4096:")),
        Some(VERIFIER.replace("AQIDBAUGBwgJCgsMDQ4PEA==", "AQID=AAA")),
        Some(VERIFIER.replace("AQIDBAUGBwgJCgsMDQ4PEA==", "")),
        Some(format!("{VERIFIER}' ; SELECT 'credential-leak")),
        Some(format!("{VERIFIER}:extra")),
    ];
    for password in invalid {
        let mut desired = role();
        desired.encrypted_password = password;
        assert_eq!(
            plan(&desired, None).unwrap_err().to_string(),
            "restricted LOGIN role requires a valid SCRAM-SHA-256 verifier"
        );
    }
}

#[test]
fn disabled_spec_must_not_retain_a_password() {
    let mut desired = role();
    desired.login = false;
    assert_eq!(
        plan(&desired, None).unwrap_err().to_string(),
        "restricted NOLOGIN role must not contain a password"
    );
}

#[test]
fn duplicate_and_overlapping_names_reject_the_whole_plan() {
    let desired = role();
    assert_eq!(
        plan_restricted_roles(
            &spec(vec![desired.clone(), desired.clone()]),
            &HashMap::new(),
            &"bootstrap_admin".into(),
            PRIVILEGED,
        )
        .unwrap_err()
        .to_string(),
        "duplicate restricted role name"
    );
    let mut overlap = spec(vec![desired.clone()]);
    overlap.cluster.roles.push(Role {
        name: desired.name,
        encrypted_password: None,
        options: None,
    });
    assert_eq!(
        plan_restricted_roles(
            &overlap,
            &HashMap::new(),
            &"bootstrap_admin".into(),
            PRIVILEGED,
        )
        .unwrap_err()
        .to_string(),
        "restricted role overlaps an ordinary role"
    );
}

#[test]
fn unsafe_identifiers_and_memberships_are_rejected() {
    for name in [
        "",
        "pg_read_all_stats",
        "cloud_admin",
        "zenith_admin",
        "postgres",
        PRIVILEGED,
        "contains\0nul",
        "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl",
    ] {
        let mut desired = role();
        desired.name = name.into();
        assert!(plan(&desired, None).is_err());
    }
    for group in [PRIVILEGED, "pg_read_all_stats", "appthrust_broker_reader_a"] {
        let mut desired = role();
        desired.member_of = vec![group.into()];
        assert!(plan(&desired, None).is_err());
    }
    let mut desired = role();
    desired.member_of.push(desired.member_of[0].clone());
    assert!(plan(&desired, None).is_err());
}

#[test]
fn ordinary_group_roles_and_role_deltas_cannot_override_restricted_state() {
    let mut desired = spec(vec![role()]);
    desired.cluster.roles.push(Role {
        name: "appthrust_postgrest".into(),
        encrypted_password: None,
        options: None,
    });
    assert!(validate_restricted_roles(&desired, PRIVILEGED).is_err());
    desired.cluster.roles.clear();
    for (action, name, new_name) in [
        ("delete_role", "appthrust_broker_reader_a", None),
        ("rename_role", "other", Some("appthrust_broker_reader_a")),
        ("delete_role", "appthrust_postgrest", None),
    ] {
        desired.delta_operations = Some(vec![DeltaOp {
            action: action.into(),
            name: name.into(),
            new_name: new_name.map(String::from),
        }]);
        assert_eq!(
            validate_restricted_roles(&desired, PRIVILEGED)
                .unwrap_err()
                .to_string(),
            "role delta operation conflicts with restricted roles"
        );
    }
}

#[test]
fn identifiers_and_bootstrap_grantor_are_quoted() {
    let mut desired = role();
    desired.name = "slot\"; SELECT 'x'--".into();
    desired.member_of = vec!["group\"with\\slash".into()];
    let queries =
        plan_restricted_role(&desired, None, &"renamed\"bootstrap".into(), PRIVILEGED).unwrap();
    assert_eq!(
        queries[0],
        format!("CREATE ROLE \"slot\"\"; SELECT 'x'--\" {SAFE_FLAGS} LOGIN PASSWORD '{VERIFIER}'")
    );
    assert_eq!(
        queries[1],
        "GRANT \"group\"\"with\\slash\" TO \"slot\"\"; SELECT 'x'--\" WITH ADMIN FALSE, INHERIT FALSE, SET TRUE GRANTED BY \"renamed\"\"bootstrap\""
    );
}

#[test]
fn ordinary_only_specs_have_no_restricted_writes_and_keep_console_options() {
    let mut desired = ComputeSpec::default();
    desired.cluster.roles.push(Role {
        name: "console_owner".into(),
        encrypted_password: Some("abc123".into()),
        options: None,
    });
    assert!(
        plan_restricted_roles(
            &desired,
            &HashMap::new(),
            &"bootstrap_admin".into(),
            PRIVILEGED,
        )
        .unwrap()
        .is_empty()
    );
    assert_eq!(
        desired.cluster.roles[0].to_pg_options(),
        " LOGIN PASSWORD 'md5abc123'"
    );
}
