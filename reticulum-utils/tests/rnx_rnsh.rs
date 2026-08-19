//! rnx + rnsh end-to-end over UDP loopback transports (Phase 8).

use std::time::Duration;

#[tokio::test]
async fn rnx_remote_execution_roundtrip() {
    let _ = env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("warn"),
    )
    .try_init();

    // Listener on its own transport + config dir.
    let server_dir =
        std::env::temp_dir().join(format!("rn-rnx-server-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&server_dir);
    std::fs::create_dir_all(&server_dir).unwrap();

    let server_options = reticulum_utils::rnx::ServeOptions {
        config_dir: server_dir.clone(),
        allow_all: true,
        allowed: vec![],
        udp_loopback: Some((5003, 5004)),
        idle_timeout: None,
    };

    let listener = tokio::spawn(async move {
        let _ = reticulum_utils::rnx::serve(&server_options).await;
    });

    // The listener announces the rnx destination; capture it by watching
    // the shared identity file + announcing over the loopback pair. The
    // client discovers it via the identity storage path.
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Read the listener identity from the storage file to derive the
    // destination hash deterministically.
    let identity_hex = std::fs::read_to_string(server_dir.join("storage/identities/rnx"))
        .expect("listener identity file");

    // The destination hash derives from the app name + identity; use the
    // client-side announce discovery over the same UDP pair instead:
    // the listener announces, the client subscribes.
    let client_dir =
        std::env::temp_dir().join(format!("rn-rnx-client-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&client_dir);
    std::fs::create_dir_all(&client_dir).unwrap();

    // Wait for the listener to be up (its announce went out on 5003),
    // then run the client with the mirrored ports.
    tokio::time::sleep(Duration::from_secs(1)).await;

    let exec_options = reticulum_utils::rnx::ExecOptions {
        config_dir: client_dir.clone(),
        timeout: Duration::from_secs(20),
        udp_loopback: Some((5004, 5003)),
    };

    // Derive the destination hash from the identity file.
    let identity =
        reticulum::identity::PrivateIdentity::new_from_hex_string(identity_hex.trim())
            .expect("listener identity");
    let destination =
        reticulum::destination::DestinationName::new("rnx", "execute")
            .address_hash_for(identity.as_identity());

    let result = reticulum_utils::rnx::execute(
        &destination,
        "printf hello-from-rnx",
        &exec_options,
    )
    .await
    .expect("remote execution");

    assert!(result.executed, "command must have been executed");
    assert_eq!(result.retval, 0);
    assert_eq!(result.stdout, b"hello-from-rnx");

    listener.abort();
}

#[tokio::test]
async fn rnsh_session_command_roundtrip() {
    let _ = env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("warn"),
    )
    .try_init();

    let server_dir =
        std::env::temp_dir().join(format!("rn-rnsh-server-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&server_dir);
    std::fs::create_dir_all(&server_dir).unwrap();

    let server_options = reticulum_utils::rnsh::ServeOptions {
        config_dir: server_dir.clone(),
        allow_all: true,
        allowed: Vec::new(),
        default_command: None,
        allow_remote_command: true,
        udp_loopback: Some((5005, 5006)),
    };

    let listener = tokio::spawn(async move {
        let _ = reticulum_utils::rnsh::serve(&server_options).await;
    });

    tokio::time::sleep(Duration::from_secs(2)).await;

    let identity_hex = std::fs::read_to_string(server_dir.join("storage/identities/rnsh"))
        .expect("listener identity file");
    let identity =
        reticulum::identity::PrivateIdentity::new_from_hex_string(identity_hex.trim())
            .expect("listener identity");
    let destination =
        reticulum::destination::DestinationName::new("rnsh", "shell")
            .address_hash_for(identity.as_identity());

    let client_dir =
        std::env::temp_dir().join(format!("rn-rnsh-client-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&client_dir);
    std::fs::create_dir_all(&client_dir).unwrap();

    let options = reticulum_utils::rnsh::ServeOptions {
        config_dir: client_dir,
        allow_all: false,
        allowed: Vec::new(),
        default_command: None,
        allow_remote_command: true,
        udp_loopback: Some((5006, 5005)),
    };

    let outcome = reticulum_utils::rnsh::run_command(
        &destination,
        "printf shell-output",
        &options,
    )
    .await
    .expect("session command");

    assert_eq!(outcome.stdout, b"shell-output");

    listener.abort();
}
