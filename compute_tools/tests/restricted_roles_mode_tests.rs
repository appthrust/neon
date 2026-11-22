use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use compute_api::responses::{ComputeConfig, ComputeCtlConfig};
use compute_api::spec::{ComputeMode, ComputeSpec, RestrictedRole};
use compute_tools::compute::{ComputeNode, ComputeNodeParams, ComputeState, ParsedSpec};
use utils::lsn::Lsn;

const MODE_ERROR: &str = "restricted roles require Primary mode and skip_pg_catalog_updates=false";
const UNSUPPORTED_MODES: [(ComputeMode, bool); 5] = [
    (ComputeMode::Primary, true),
    (ComputeMode::Replica, false),
    (ComputeMode::Replica, true),
    (ComputeMode::Static(Lsn(42)), false),
    (ComputeMode::Static(Lsn(42)), true),
];

fn storage_spec() -> ComputeSpec {
    ComputeSpec {
        pageserver_connstring: Some("postgresql://localhost:1".into()),
        safekeeper_connstrings: vec!["localhost:1".into()],
        tenant_id: Some("00112233445566778899001122334455".parse().unwrap()),
        timeline_id: Some("ffeeddccbbaa99887766554433221100".parse().unwrap()),
        ..Default::default()
    }
}

fn disabled_role() -> RestrictedRole {
    RestrictedRole {
        name: "appthrust_broker_reader_a".into(),
        login: false,
        encrypted_password: None,
        member_of: Vec::new(),
    }
}

fn unsupported_state(mode: ComputeMode, skip_pg_catalog_updates: bool) -> ComputeState {
    // Deliberately bypass TryFrom's input guard to exercise the direct entrypoints.
    let mut pspec = ParsedSpec::try_from(storage_spec()).unwrap();
    pspec.spec.cluster.restricted_roles.push(disabled_role());
    pspec.spec.mode = mode;
    pspec.spec.skip_pg_catalog_updates = skip_pg_catalog_updates;
    // If reconfigure reaches rsyslog, fail before touching its global configuration.
    pspec.spec.logs_export_host = Some("invalid-host-without-port".into());
    ComputeState {
        pspec: Some(pspec),
        ..ComputeState::new()
    }
}

fn node() -> ComputeNode {
    ComputeNode::new(
        ComputeNodeParams {
            compute_id: "restricted-role-mode-test".into(),
            connstr: "postgresql://localhost:1/postgres".parse().unwrap(),
            privileged_role_name: "neon_superuser".into(),
            resize_swap_on_bind: false,
            set_disk_quota_for_fs: None,
            #[cfg(target_os = "linux")]
            filecache_connstr: String::new(),
            #[cfg(target_os = "linux")]
            cgroup: String::new(),
            #[cfg(target_os = "linux")]
            vm_monitor_addr: String::new(),
            // No real filesystem or subprocess target, even if a guard regresses.
            pgdata: "\0".into(),
            pgbin: "\0".into(),
            pgversion: "16".into(),
            external_http_port: 0,
            internal_http_port: 0,
            remote_ext_base_url: None,
            installed_extensions_collection_interval: Arc::new(AtomicU64::new(17)),
            instance_id: None,
            pg_init_timeout: None,
            pg_isready_bin: "\0".into(),
            lakebase_mode: false,
            build_tag: String::new(),
            control_plane_uri: None,
            config_path_test_only: None,
        },
        ComputeConfig {
            spec: None,
            compute_ctl_config: ComputeCtlConfig::default(),
        },
    )
    .unwrap()
}

#[test]
fn parsed_specs_keep_empty_opt_in_in_every_mode() {
    for mode in [
        ComputeMode::Primary,
        ComputeMode::Replica,
        ComputeMode::Static(Lsn(42)),
    ] {
        for skip_pg_catalog_updates in [false, true] {
            let mut spec = storage_spec();
            spec.mode = mode;
            spec.skip_pg_catalog_updates = skip_pg_catalog_updates;
            ParsedSpec::try_from(spec).unwrap();
        }
    }
}

#[test]
fn parsed_specs_accept_restricted_nologin_on_primary() {
    let mut spec = storage_spec();
    spec.cluster.restricted_roles.push(disabled_role());
    ParsedSpec::try_from(spec).unwrap();
}

// These direct-entrypoint tests intentionally have no Tokio runtime: unsupported
// declarations must fail before spawning tasks, opening PostgreSQL, or doing I/O.
#[test]
fn prepare_pgdata_rejects_unsupported_roles_before_filesystem_access() {
    let node = node();
    for (mode, skip) in UNSUPPORTED_MODES {
        let state = unsupported_state(mode, skip);
        assert_eq!(
            node.prepare_pgdata(&state).unwrap_err().to_string(),
            MODE_ERROR
        );
    }
}

#[test]
fn reconfigure_rejects_unsupported_roles_before_configuration_changes() {
    let node = node();
    for (mode, skip) in UNSUPPORTED_MODES {
        *node.state.lock().unwrap() = unsupported_state(mode, skip);
        assert_eq!(node.reconfigure().unwrap_err().to_string(), MODE_ERROR);
        assert_eq!(
            node.params
                .installed_extensions_collection_interval
                .load(Ordering::SeqCst),
            17
        );
    }
}

#[test]
fn configure_as_primary_rejects_unsupported_roles_before_reload_or_post_apply() {
    let node = node();
    for (mode, skip) in UNSUPPORTED_MODES {
        let state = unsupported_state(mode, skip);
        assert_eq!(
            node.configure_as_primary(&state).unwrap_err().to_string(),
            MODE_ERROR
        );
    }
}
