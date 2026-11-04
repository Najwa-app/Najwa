//! Real process, HTTP boundary, OS keystore, SQLCipher and restart coverage.
use serde_json::{json, Value};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

struct Service {
    child: Child,
    port: u16,
    token: String,
}
impl Drop for Service {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
fn port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
fn launch(profile: &Path, assets: &Path, port: u16) -> Child {
    let executable = std::env::var_os("NAJWA_WEB_TEST_EXE")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_najwa-web").into());
    Command::new(executable)
        .args([
            "--no-browser",
            "--profile",
            profile.to_str().unwrap(),
            "--assets",
            assets.to_str().unwrap(),
            "--port",
            &port.to_string(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
}
fn request(port: u16, path: &str, body: Option<Value>, extra: &str) -> (u16, Value) {
    let mut stream = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(90)))
        .unwrap();
    let data = body.map(|v| v.to_string());
    write!(
        stream,
        "{} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n{extra}{}\r\n{}",
        if data.is_some() { "POST" } else { "GET" },
        data.as_ref()
            .map(|v| format!(
                "Content-Type: application/json\r\nContent-Length: {}\r\n",
                v.len()
            ))
            .unwrap_or_default(),
        data.unwrap_or_default()
    )
    .unwrap();
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).unwrap();
    let split = bytes.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let header = std::str::from_utf8(&bytes[..split]).unwrap();
    let status = header.split_whitespace().nth(1).unwrap().parse().unwrap();
    let body = serde_json::from_slice(&bytes[split + 4..]).unwrap_or(Value::Null);
    (status, body)
}
impl Service {
    fn start(profile: &Path, assets: &Path) -> Self {
        let port = port();
        let mut child = launch(profile, assets, port);
        let until = Instant::now() + Duration::from_secs(15);
        loop {
            assert!(
                child.try_wait().unwrap().is_none(),
                "local service exited during startup"
            );
            if profile.join("web-instance.json").is_file()
                && TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port)).is_ok()
            {
                break;
            }
            assert!(Instant::now() < until, "local service did not start");
            thread::sleep(Duration::from_millis(50));
        }
        let instance: Value =
            serde_json::from_slice(&std::fs::read(profile.join("web-instance.json")).unwrap())
                .unwrap();
        let token = instance["token"].as_str().unwrap().to_owned();
        assert_eq!(request(port, "/api/bootstrap", None, "").0, 403);
        assert_eq!(
            request(
                port,
                "/api/bootstrap",
                None,
                &format!("X-Najwa-Launch: {token}\r\n")
            )
            .1["session"],
            instance["session"]
        );
        Self { child, port, token }
    }
    fn api(&self, path: &str, body: Option<Value>) -> Value {
        let (status, value) = request(
            self.port,
            path,
            body,
            &format!("X-Najwa-Session: {}\r\n", self.token),
        );
        assert_eq!(status, 200);
        value
    }
    fn status(&self) -> Value {
        self.api("/api/status", None)["ok"].clone()
    }
    fn identity(&self, operation: Value) -> Value {
        let status = self.status();
        self.api("/api/identity",Some(json!({"session":status["session"],"generation":status["generation"],"operation":operation})))
    }
    fn lock(&self) {
        let status = self.status();
        assert_eq!(
            self.api(
                "/api/lock",
                Some(json!({"session":status["session"],"generation":status["generation"]}))
            )["ok"]["phase"],
            "locked"
        );
    }
    fn messaging(&self, operation: Value) -> Value {
        let status = self.status();
        self.api("/api/invoke",Some(json!({"command":"messaging_request","args":{"request":{"session":status["session"],"generation":status["generation"],"operation":operation}}})))
    }
    fn unlock(&self, password: &str) -> Value {
        let mut value = self.identity(json!({"kind":"unlock","password":password}));
        if value["error"]["code"] == "rate_limited" {
            let delay = value["error"]["retryAfterMs"].as_u64().unwrap();
            assert!(delay <= 2000);
            thread::sleep(Duration::from_millis(delay + 100));
            value = self.identity(json!({"kind":"unlock","password":password}));
        }
        value
    }
}
struct ScopedKey(PathBuf);
impl Drop for ScopedKey {
    fn drop(&mut self) {
        if let Ok(bytes) = std::fs::read(&self.0) {
            if let Ok(record) = najwa_identity::IdentityRecordStandard::from_bytes(&bytes) {
                let _ = najwa_identity::platform::delete_record_dkm(&record);
            }
        }
    }
}

#[test]
fn saved_preferences_bridge_failure_idle_lock_and_offline_erasure() {
    let temp = tempfile::tempdir().unwrap();
    let profile = temp.path().join("profile");
    let assets = temp.path().join("ui");
    std::fs::create_dir(&assets).unwrap();
    std::fs::write(assets.join("index.html"), "Najwa").unwrap();
    let _key = ScopedKey(profile.join("identity.najwa"));
    let service = Service::start(&profile, &assets);
    assert_eq!(service.api("/api/preferences",None)["error"]["code"],"stale_operation");
    let password = "synthetic preferences orchard lantern";
    let mut created = service.identity(json!({"kind":"create","password":password,"confirmation":password}));
    if cfg!(target_os = "linux") && created["error"]["code"] == "keystore_unavailable" {
        let approval = service.identity(json!({"kind":"approve_software_storage","confirmed":true}));
        assert!(approval["ok"].is_object(), "{approval}");
        created = service.identity(json!({"kind":"create","password":password,"confirmation":password}));
    }
    assert_eq!(created["ok"]["identity"]["phase"], "unlocked", "{created}");
    let record = najwa_identity::IdentityRecordStandard::from_bytes(&std::fs::read(profile.join("identity.najwa")).unwrap()).unwrap();
    assert_eq!(service.api("/api/preferences",None)["ok"],json!({"lockTimeoutSeconds":300,"bridges":[]}));
    let save = |service: &Service, prefs: Value| {
        let status = service.status();
        service.api("/api/preferences",Some(json!({"session":status["session"],"generation":status["generation"],"preferences":prefs})))
    };
    for seconds in [0,59,3601] {
        assert_eq!(save(&service,json!({"lockTimeoutSeconds":seconds,"bridges":[]}))["error"]["code"], "invalid_preferences");
    }
    assert_eq!(save(&service,json!({"lockTimeoutSeconds":900,"bridges":["meek 127.0.0.1:9"]}))["error"]["code"],"invalid_bridges");
    assert_eq!(service.api("/api/preferences",None)["ok"]["bridges"],json!([]));
    assert_eq!(save(&service,json!({"lockTimeoutSeconds":900,"bridges":[]}))["ok"]["identity"]["phase"],"unlocked");
    assert_eq!(service.status()["lockTimeoutSeconds"],900);
    // An unreachable bridge must never retain the previous direct connection.
    let bridge = format!("127.0.0.1:{} 0123456789ABCDEF0123456789ABCDEF01234567",port());
    let saved = save(&service,json!({"lockTimeoutSeconds":3600,"bridges":[bridge]}));
    assert_eq!(saved["ok"]["identity"]["phase"],"locked","{saved}");
    assert_eq!(service.unlock(password)["ok"]["identity"]["phase"],"unlocked");
    assert_eq!(service.api("/api/preferences",None)["ok"]["bridges"],json!([bridge]));
    let old_status = service.status();
    drop(service);
    let service = Service::start(&profile,&assets);
    assert_eq!(service.unlock(password)["ok"]["identity"]["lockTimeoutSeconds"],3600);
    assert_eq!(service.api("/api/preferences",None)["ok"]["bridges"],json!([bridge]));
    let until = Instant::now()+Duration::from_secs(65);
    while Instant::now()<until {
        let network=service.api("/api/invoke",Some(json!({"command":"messaging_status","args":{}})));
        assert_ne!(network["ok"]["connection"],"connected","bridge failure must not connect directly");
        thread::sleep(Duration::from_secs(1));
    }
    // One minute is the minimum. Exercise the production idle worker, no test clock override.
    assert_eq!(save(&service,json!({"lockTimeoutSeconds":60,"bridges":[bridge]}))["ok"]["identity"]["phase"],"unlocked");
    let until=Instant::now()+Duration::from_secs(72);
    // Read the phase once per iteration: the lock may complete between two reads.
    loop {
        let status = service.status();
        if status["phase"] == "locked" || Instant::now() >= until {
            break;
        }
        assert!(matches!(status["phase"].as_str(),Some("unlocked" | "locking")),"automatic locking must finish without an error: {status}");
        thread::sleep(Duration::from_secs(1));
    }
    assert_eq!(service.status()["phase"],"locked","saved one-minute idle timeout must lock");
    let outside=temp.path().join("exported-file");
    std::fs::write(&outside,b"keep external files").unwrap();
    std::fs::write(profile.join("unfinished-transfer"),b"erase profile files").unwrap();
    let status=service.status();
    let erase=|session:Value,generation:Value,confirmed:bool,confirmation:&str| service.api("/api/erase",Some(json!({"session":session,"generation":generation,"confirmed":confirmed,"confirmation":confirmation})));
    assert_eq!(erase(status["session"].clone(),status["generation"].clone(),false,"ERASE")["error"]["code"],"invalid_confirmation");
    assert_eq!(erase(status["session"].clone(),status["generation"].clone(),true,"erase")["error"]["code"],"invalid_confirmation");
    assert_eq!(erase(old_status["session"].clone(),old_status["generation"].clone(),true,"ERASE")["error"]["code"],"stale_operation");
    let erased=erase(status["session"].clone(),status["generation"].clone(),true,"ERASE");
    assert_eq!(erased["ok"]["phase"],"erased","{erased}");
    assert_eq!(erased["ok"]["mailboxes"],json!({"deactivated":[],"unreachable":[]}),"a locked profile contacts no mailbox");
    assert!(najwa_identity::platform::retrieve_record_dkm(&record).is_err(),"only this identity's key must be removed");
    assert!(!profile.join("identity.najwa").exists());
    assert!(!profile.join("najwa.db").exists());
    assert!(!profile.join("unfinished-transfer").exists());
    assert!(!profile.join("wipe.pending").exists());
    assert_eq!(std::fs::read(&outside).unwrap(),b"keep external files");
    drop(service);
    let reopened=Service::start(&profile,&assets);
    assert_eq!(reopened.status()["phase"],"absent");
}

#[test]
#[cfg(windows)]
fn interrupted_erasure_blocks_unlock_survives_restart_and_can_retry() {
    use std::os::windows::fs::OpenOptionsExt;
    let temp=tempfile::tempdir().unwrap();let profile=temp.path().join("profile");let assets=temp.path().join("ui");
    std::fs::create_dir(&assets).unwrap();std::fs::write(assets.join("index.html"),"Najwa").unwrap();
    let _key=ScopedKey(profile.join("identity.najwa"));
    let other_profile=temp.path().join("other-profile");
    let _other_key=ScopedKey(other_profile.join("identity.najwa"));
    let other=Service::start(&other_profile,&assets);
    let password="synthetic erasure orchard lantern";
    assert_eq!(other.identity(json!({"kind":"create","password":password,"confirmation":password}))["ok"]["identity"]["phase"],"unlocked");
    let other_fingerprint=other.status()["fingerprint"].clone();other.lock();
    let service=Service::start(&profile,&assets);
    assert_eq!(service.identity(json!({"kind":"create","password":password,"confirmation":password}))["ok"]["identity"]["phase"],"unlocked");
    let record=najwa_identity::IdentityRecordStandard::from_bytes(&std::fs::read(profile.join("identity.najwa")).unwrap()).unwrap();
    let path=profile.join("blocked-file");std::fs::write(&path,b"synthetic partial erasure").unwrap();
    let held=std::fs::OpenOptions::new().read(true).share_mode(0).open(&path).unwrap();
    let status=service.status();
    let erased=service.api("/api/erase",Some(json!({"session":status["session"],"generation":status["generation"],"confirmed":true,"confirmation":"ERASE"})));
    assert_eq!(erased["error"]["code"],"wipe_incomplete");assert_eq!(service.status()["phase"],"wiping");
    assert!(najwa_identity::platform::retrieve_record_dkm(&record).is_err(),"the erased profile's factor was removed before file cleanup failed");
    assert_eq!(other.unlock(password)["ok"]["identity"]["fingerprint"],other_fingerprint,"erasure must preserve another profile's hardware key");
    other.lock();
    let marker=std::fs::read(profile.join("wipe.pending")).unwrap();
    let status=service.status();
    assert_eq!(service.api("/api/lock",Some(json!({"session":status["session"],"generation":status["generation"]})))["ok"]["phase"],"wiping");
    assert_eq!(service.identity(json!({"kind":"create","password":password,"confirmation":password}))["error"]["code"],"stale_operation");
    drop(service);drop(held);
    // A partial/corrupt record cannot prevent the erasure recovery screen opening.
    std::fs::write(profile.join("identity.najwa"),b"partly erased").unwrap();
    let service=Service::start(&profile,&assets);assert_eq!(service.status()["phase"],"wiping");
    assert_eq!(std::fs::read(profile.join("wipe.pending")).unwrap(),marker);
    let status=service.status();
    let erased=service.api("/api/erase",Some(json!({"session":status["session"],"generation":status["generation"],"confirmed":true,"confirmation":"ERASE"})));
    assert_eq!(erased["ok"]["phase"],"erased","{erased}");assert!(!path.exists());assert!(!profile.join("wipe.pending").exists());
    assert_eq!(other.unlock(password)["ok"]["identity"]["fingerprint"],other_fingerprint);
}

#[test]
#[cfg(windows)]
fn windows_session_lock_message_locks_an_unlocked_profile_despite_activity() {
    use windows_sys::Win32::UI::WindowsAndMessaging::*;
    let temp = tempfile::tempdir().unwrap();
    let profile = temp.path().join("profile");
    let assets = temp.path().join("ui");
    std::fs::create_dir(&assets).unwrap();
    std::fs::write(assets.join("index.html"), "Najwa").unwrap();
    let _key = ScopedKey(profile.join("identity.najwa"));
    let service = Service::start(&profile, &assets);
    let password = "synthetic session lock orchard";
    let created = service.identity(json!({"kind":"create","password":password,"confirmation":password}));
    assert_eq!(created["ok"]["identity"]["phase"], "unlocked", "{created}");
    // The service's message-only listener window (src/os_lock.rs).
    let class: Vec<u16> = "NajwaOsLock".encode_utf16().chain([0]).collect();
    let until = Instant::now() + Duration::from_secs(10);
    let window = 'found: loop {
        let mut window = std::ptr::null_mut();
        loop {
            window = unsafe { FindWindowExW(HWND_MESSAGE, window, class.as_ptr(), std::ptr::null()) };
            if window.is_null() {
                break;
            }
            let mut process = 0;
            unsafe { GetWindowThreadProcessId(window, &mut process) };
            if process == service.child.id() {
                break 'found window;
            }
        }
        assert!(Instant::now() < until, "OS lock listener window not found");
        thread::sleep(Duration::from_millis(50));
    };
    // SendMessage returns after the window procedure, so the lock has finished.
    let send = |message: u32, event: u32| unsafe { SendMessageW(window, message, event as usize, 0) };
    let status = service.status();
    // Keep unlocked reports activity; neither it nor unlock and wake events hold or cause a lock.
    assert!(service.api("/api/activity", Some(json!({"session":status["session"],"generation":status["generation"]})))["ok"].is_null());
    send(WM_WTSSESSION_CHANGE, WTS_SESSION_UNLOCK);
    send(WM_POWERBROADCAST, PBT_APMRESUMEAUTOMATIC);
    assert_eq!(service.status()["phase"], "unlocked");
    assert_eq!(service.status()["generation"], status["generation"]);
    send(WM_WTSSESSION_CHANGE, WTS_SESSION_LOCK);
    let locked = service.status();
    assert_eq!(locked["phase"], "locked", "{locked}");
    assert!(locked["generation"].as_u64() > status["generation"].as_u64());
}

#[test]
#[cfg(target_os = "linux")]
#[ignore = "requires Linux with no /dev/tpmrm0; verifies the production binary cannot fall back"]
fn missing_tpm_refuses_identity_without_creating_software_keys() {
    assert!(!Path::new("/dev/tpmrm0").exists(), "run this negative test without a TPM device");
    assert!(najwa_identity::platform::hardware_keystore_required());
    let temp = tempfile::tempdir().unwrap();
    let profile = temp.path().join("profile");
    let assets = temp.path().join("ui");
    std::fs::create_dir(&assets).unwrap();
    std::fs::write(assets.join("index.html"), "Najwa").unwrap();
    let _key = ScopedKey(profile.join("identity.najwa"));
    let service = Service::start(&profile, &assets);
    assert_eq!(service.status()["hardware"], "unverified");
    assert_eq!(service.status()["protection"], "hardware");
    let created = service.identity(json!({"kind":"create","password":"synthetic missing TPM test","confirmation":"synthetic missing TPM test"}));
    assert_eq!(created["error"]["code"], "keystore_unavailable", "{created}");
    assert_eq!(service.status()["softwareFallbackAvailable"], true);
    assert_eq!(service.status()["softwareFallbackApproved"], false);
    assert_eq!(service.status()["phase"], "absent");
    assert!(!profile.join("identity.najwa").exists());
    drop(service);
    let restarted = Service::start(&profile, &assets);
    assert_eq!(restarted.status()["phase"], "absent");
    assert!(!profile.join("identity.najwa").exists());
}

#[test]
#[cfg(any(target_os = "windows", target_os = "linux"))]
fn hardware_key_loss_refuses_unlock_after_restart() {
    assert!(najwa_identity::platform::hardware_keystore_required());
    let temp = tempfile::tempdir().unwrap();
    let profile = temp.path().join("profile");
    let assets = temp.path().join("ui");
    std::fs::create_dir(&assets).unwrap();
    std::fs::write(assets.join("index.html"), "Najwa").unwrap();
    let _key = ScopedKey(profile.join("identity.najwa"));
    let service = Service::start(&profile, &assets);
    assert_eq!(service.status()["hardware"], "unverified");
    let created = service.identity(json!({"kind":"create","password":"synthetic hardware key loss","confirmation":"synthetic hardware key loss"}));
    assert_eq!(created["ok"]["identity"]["phase"], "unlocked", "{created}");
    drop(service);
    let bytes = std::fs::read(profile.join("identity.najwa")).unwrap();
    let record = najwa_identity::IdentityRecordStandard::from_bytes(&bytes).unwrap();
    najwa_identity::platform::delete_record_dkm(&record).unwrap();
    let restarted = Service::start(&profile, &assets);
    let result = restarted.unlock("synthetic hardware key loss");
    assert!(result["error"].is_object(), "{result}");
    assert_eq!(restarted.status()["phase"], "locked");
    assert_eq!(std::fs::read(profile.join("identity.najwa")).unwrap(), bytes);
    let approval = restarted.identity(json!({"kind":"approve_software_storage","confirmed":true}));
    assert_eq!(approval["ok"]["identity"]["softwareFallbackApproved"], true, "unlock={result}; approval={approval}; status={}", restarted.status());
    assert!(restarted.unlock("synthetic hardware key loss")["error"].is_object(), "approval must not bypass a missing hardware key");
    assert_eq!(std::fs::read(profile.join("identity.najwa")).unwrap(), bytes);
}

#[test]
#[cfg(target_os = "linux")]
#[ignore = "requires Linux without a TPM and an unlocked Secret Service"]
fn missing_tpm_software_fallback_requires_profile_consent_and_survives_restart() {
    assert!(!Path::new("/dev/tpmrm0").exists());
    let temp = tempfile::tempdir().unwrap();
    let profile = temp.path().join("approved");
    let assets = temp.path().join("ui");
    std::fs::create_dir(&assets).unwrap();
    std::fs::write(assets.join("index.html"), "Najwa").unwrap();
    let _key = ScopedKey(profile.join("identity.najwa"));
    let first = Service::start(&profile, &assets);
    assert!(first.identity(json!({"kind":"approve_software_storage","confirmed":true}))["error"].is_object());
    let create = json!({"kind":"create","password":"approved software orchard lantern","confirmation":"approved software orchard lantern"});
    assert_eq!(first.identity(create.clone())["error"]["code"], "keystore_unavailable");
    assert!(first.identity(json!({"kind":"approve_software_storage","confirmed":false}))["error"].is_object());
    assert_eq!(first.status()["softwareFallbackApproved"], false);
    assert_eq!(first.identity(create.clone())["error"]["code"], "keystore_unavailable");
    assert!(!profile.join("identity.najwa").exists());
    let approved = first.identity(json!({"kind":"approve_software_storage","confirmed":true}));
    assert_eq!(approved["ok"]["identity"]["softwareFallbackApproved"], true);
    assert!(!profile.join("identity.najwa").exists(), "approval never replays a passphrase");
    let created = first.identity(create.clone());
    assert_eq!(created["ok"]["identity"]["phase"], "unlocked", "{created}");
    assert_eq!(first.status()["protection"], "os-keystore");
    assert_eq!(first.status()["hardware"], "unavailable");
    let fingerprint = first.status()["fingerprint"].clone();
    let words = first.identity(json!({"kind":"recovery_words"}))["ok"]["value"]["words"].as_str().unwrap().to_owned();
    let old = najwa_identity::IdentityRecordStandard::from_bytes(&std::fs::read(profile.join("identity.najwa")).unwrap()).unwrap();
    assert!(najwa_identity::platform::record_uses_software_storage(&old).unwrap());
    assert!(first.messaging(json!({"kind":"set_delivery_mode","mode":"privacy"}))["error"].is_null());
    let other = Service::start(&temp.path().join("unapproved"), &assets);
    assert_eq!(other.identity(create)["error"]["code"], "keystore_unavailable");
    assert_eq!(other.status()["softwareFallbackApproved"], false);
    drop(other);
    drop(first);
    let reopened = Service::start(&profile, &assets);
    assert_eq!(reopened.status()["softwareFallbackApproved"], true);
    assert_eq!(reopened.status()["protection"], "os-keystore");
    assert_eq!(reopened.unlock("approved software orchard lantern")["ok"]["identity"]["fingerprint"], fingerprint);
    assert_eq!(reopened.api("/api/invoke",Some(json!({"command":"messaging_status","args":{}})))["ok"]["deliveryMode"], "privacy");
    let changed = reopened.identity(json!({"kind":"change_password","current":"approved software orchard lantern","password":"replacement software orchard lantern","confirmation":"replacement software orchard lantern"}));
    assert_eq!(changed["ok"]["identity"]["phase"], "unlocked", "{changed}");
    assert!(najwa_identity::platform::retrieve_record_dkm(&old).is_err());
    reopened.lock();
    assert_eq!(reopened.unlock("replacement software orchard lantern")["ok"]["identity"]["fingerprint"], fingerprint);
    reopened.lock();
    let recovered = reopened.identity(json!({"kind":"recover","words":words,"password":"recovered software orchard lantern","confirmation":"recovered software orchard lantern"}));
    assert_eq!(recovered["ok"]["identity"]["fingerprint"], fingerprint, "{recovered}");
}

#[test]
fn persistent_identity_recovery_and_http_boundary() {
    let temp = tempfile::tempdir().unwrap();
    let profile = temp.path().join("profile");
    let real_ui = std::env::var_os("NAJWA_WEB_TEST_UI").map(PathBuf::from);
    let assets = real_ui.clone().unwrap_or_else(|| temp.path().join("ui"));
    if real_ui.is_none() {
        std::fs::create_dir(&assets).unwrap();
        std::fs::write(assets.join("index.html"), "<html>Najwa</html>").unwrap();
    }
    let _key = ScopedKey(profile.join("identity.najwa"));
    let service = Service::start(&profile, &assets);
    assert_eq!(service.status()["phase"], "absent");
    assert_eq!(request(service.port, "/api/status", None, "").0, 403);
    assert_eq!(
        request(
            service.port,
            "/api/bootstrap",
            None,
            "Origin: https://example.org\r\n"
        )
        .0,
        403
    );
    assert_eq!(
        request(
            service.port,
            "/api/bootstrap",
            None,
            "Sec-Fetch-Site: cross-site\r\n"
        )
        .0,
        403
    );
    // The Unix file:// launch page reaches the app as a cross-site navigation.
    let navigation = "Sec-Fetch-Site: cross-site\r\nSec-Fetch-Mode: navigate\r\nSec-Fetch-Dest: document\r\n";
    assert_eq!(request(service.port, "/", None, navigation).0, 200);
    assert_eq!(request(service.port, "/index.html", None, navigation).0, 403);
    assert_eq!(request(service.port, "/api/bootstrap", None, navigation).0, 403);
    assert_eq!(
        request(service.port, "/", None, "Sec-Fetch-Site: cross-site\r\nSec-Fetch-Mode: no-cors\r\nSec-Fetch-Dest: document\r\n").0,
        403
    );
    assert_eq!(
        request(service.port, "/%2e%2e/identity.najwa", None, "").0,
        404
    );
    assert_eq!(
        service.api("/api/identity", Some(json!({"unexpected":true})))["error"]["code"],
        "invalid_request"
    );
    assert_eq!(
        service.identity(json!({"kind":"create","password":"short","confirmation":"short"}))
            ["error"]["code"],
        "invalid_password"
    );
    let password = "orchard river lantern local";
    let created =
        service.identity(json!({"kind":"create","password":password,"confirmation":password}));
    assert_eq!(created["ok"]["identity"]["phase"], "unlocked", "{created}");
    let fingerprint = service.status()["fingerprint"].clone();
    let words = service.identity(json!({"kind":"recovery_words"}))["ok"]["value"]["words"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(words.split_whitespace().count(), 24);
    let record = service.identity(json!({"kind":"export_recovery"}))["ok"]["value"]["record"]
        .as_str()
        .unwrap()
        .to_owned();
    use base64::Engine;
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(&record)
            .unwrap(),
        std::fs::read(profile.join("identity.recovery")).unwrap()
    );
    assert!(service.identity(json!({"kind":"acknowledge_recovery"}))["ok"].is_object());
    assert_eq!(
        service.identity(json!({"kind":"recovery_words"}))["error"]["code"],
        "recovery_missing"
    );
    if real_ui.is_some() {
        let web_project = Path::new(env!("CARGO_MANIFEST_DIR")).join("../desktop");
        let browser = Command::new("node")
            .current_dir(web_project)
            .args([
                "local-web/smoke.mjs",
                &format!("http://127.0.0.1:{}/#{}", service.port, service.token),
            ])
            .status()
            .unwrap();
        assert!(browser.success(), "real browser smoke test failed");
        assert_eq!(
            service.unlock(password)["ok"]["identity"]["phase"],
            "unlocked"
        );
    }
    assert!(
        service.messaging(json!({"kind":"set_delivery_mode","mode":"privacy"}))["ok"].is_null()
    );
    let mut second = launch(&profile, &assets, port());
    let until = Instant::now() + Duration::from_secs(10);
    while second.try_wait().unwrap().is_none() && Instant::now() < until {
        thread::sleep(Duration::from_millis(50));
    }
    assert!(!second
        .try_wait()
        .unwrap()
        .expect("duplicate profile process must exit")
        .success());
    let old_token = service.token.clone();
    let old_session = service.status()["session"].clone();
    drop(service); // Simulate process/browser shutdown, not a synthetic in-memory reopen.
    let service = Service::start(&profile, &assets);
    assert_eq!(service.status()["phase"], "locked");
    assert_eq!(service.status()["fingerprint"], fingerprint);
    assert_ne!(service.token, old_token);
    assert_eq!(
        service.unlock("wrong passphrase")["error"]["code"],
        "authentication_failed"
    );
    assert_eq!(
        service.unlock(password)["ok"]["identity"]["phase"],
        "unlocked"
    );
    let network = service.api(
        "/api/invoke",
        Some(json!({"command":"messaging_status","args":{}})),
    );
    assert_eq!(
        network["ok"]["deliveryMode"], "privacy",
        "SQLCipher settings must survive restart"
    );
    assert_eq!(service.api("/api/identity",Some(json!({"session":old_session,"generation":1,"operation":{"kind":"unlock","password":password}})))["error"]["code"],"stale_operation");
    let next = "new orchard river lantern";
    assert_eq!(
        service.identity(
            json!({"kind":"change_password","current":password,"password":next,"confirmation":next})
        )["ok"]["identity"]["phase"],
        "unlocked"
    );
    service.lock();
    assert_eq!(
        service.unlock(password)["error"]["code"],
        "authentication_failed"
    );
    assert_eq!(
        service.unlock(next)["ok"]["identity"]["fingerprint"],
        fingerprint
    );
    service.lock();
    let recovered = "recovered orchard river lantern";
    // A valid kit for another identity must never replace this profile's key.
    let original_record = std::fs::read(profile.join("identity.najwa")).unwrap();
    let original_recovery = std::fs::read(profile.join("identity.recovery")).unwrap();
    let foreign = najwa_identity::Identity {
        keypair: najwa_crypto::keys::Ed25519KeyPair::from_seed(&zeroize::Zeroizing::new([91; 32])),
        created_at: 1,
        version: 2,
    };
    let (foreign_words, foreign_recovery) =
        najwa_identity::backup::create_recovery_record(&foreign, 24).unwrap();
    std::fs::write(
        profile.join("identity.recovery"),
        foreign_recovery.to_bytes(),
    )
    .unwrap();
    assert_eq!(service.identity(json!({"kind":"recover","words":foreign_words,"password":recovered,"confirmation":recovered}))["error"]["code"],"recovery_invalid");
    assert_eq!(
        std::fs::read(profile.join("identity.najwa")).unwrap(),
        original_record
    );
    std::fs::write(profile.join("identity.recovery"), original_recovery).unwrap();
    let result = service.identity(
        json!({"kind":"recover","words":words,"password":recovered,"confirmation":recovered}),
    );
    assert_eq!(
        result["ok"]["identity"]["fingerprint"], fingerprint,
        "{result}"
    );
    service.lock();
    // Lock must invalidate an unlock that is already inside its KDF.
    let before = service.status();
    let token = service.token.clone();
    let service_port = service.port;
    let unlocking = thread::spawn(move || {
        request(
            service_port,
            "/api/identity",
            Some(
                json!({"session":before["session"],"generation":before["generation"],"operation":{"kind":"unlock","password":recovered}}),
            ),
            &format!("X-Najwa-Session: {token}\r\n"),
        )
    });
    let until = Instant::now() + Duration::from_secs(10);
    while service.status()["busy"] != true && Instant::now() < until {
        thread::sleep(Duration::from_millis(10));
    }
    service.lock();
    assert_eq!(
        unlocking.join().unwrap().1["error"]["code"],
        "stale_operation"
    );
    assert_eq!(service.status()["phase"], "locked");
    assert_eq!(
        service.unlock(recovered)["ok"]["identity"]["phase"],
        "unlocked"
    );
    for path in ["identity.najwa", "identity.recovery", "najwa.db"] {
        if let Ok(bytes) = std::fs::read(profile.join(path)) {
            for secret in [password, next, recovered, words.as_str()] {
                assert!(
                    !bytes.windows(secret.len()).any(|v| v == secret.as_bytes()),
                    "plaintext credential on disk"
                );
            }
            assert!(!bytes.starts_with(b"SQLite format 3"));
        }
    }
    service.lock();
    let imported_profile = temp.path().join("imported-profile");
    let _imported_key = ScopedKey(imported_profile.join("identity.najwa"));
    let imported = Service::start(&imported_profile, &assets);
    let restored = imported.identity(json!({"kind":"restore","record":record,"words":words,"password":password,"confirmation":password}));
    assert_eq!(
        restored["ok"]["identity"]["fingerprint"], fingerprint,
        "{restored}"
    );
    assert_eq!(restored["ok"]["identity"]["prekeyRefreshRequired"], true);
    assert_eq!(imported.identity(json!({"kind":"restore","record":record,"words":words,"password":password,"confirmation":password}))["error"]["code"],"already_exists");
    // Quitting an unlocked app must drain its keys and release the profile lease.
    let status = imported.status();
    assert!(imported.api(
        "/api/quit",
        Some(json!({"session":status["session"],"generation":status["generation"]}))
    )["error"]
        .is_null());
    let mut imported = imported;
    let until = Instant::now() + Duration::from_secs(10);
    while imported.child.try_wait().unwrap().is_none() && Instant::now() < until {
        thread::sleep(Duration::from_millis(50));
    }
    assert!(imported
        .child
        .try_wait()
        .unwrap()
        .expect("Quit must stop the native process")
        .success());
    assert!(!imported_profile.join("web-instance.json").exists());
    let reopened = Service::start(&imported_profile, &assets);
    assert_eq!(reopened.status()["phase"], "locked");
    assert_eq!(reopened.status()["fingerprint"], fingerprint);
}

fn browser_cookie(service: &Service) -> String {
    let mut stream = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, service.port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    write!(stream, "GET /api/bootstrap HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nX-Najwa-Launch: {}\r\nConnection: close\r\n\r\n", service.port, service.token).unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    assert!(response.starts_with("HTTP/1.1 200"));
    let cookie = response
        .lines()
        .find_map(|line| line.strip_prefix("set-cookie: "))
        .unwrap();
    assert!(cookie.contains("HttpOnly; SameSite=Strict; Path=/api/bootstrap; Max-Age="));
    cookie.split(';').next().unwrap().to_owned()
}

#[test]
fn paired_browser_reconnects_after_restart_without_reusing_api_credentials() {
    let directory = tempfile::tempdir().unwrap();
    let profile = directory.path().join("profile");
    let assets = directory.path().join("ui");
    std::fs::create_dir(&assets).unwrap();
    std::fs::write(assets.join("index.html"), "Najwa").unwrap();
    let _key = ScopedKey(profile.join("identity.najwa"));
    let mut first = Service::start(&profile, &assets);
    let created = first.identity(json!({"kind":"create","password":"reconnect orchard river lantern","confirmation":"reconnect orchard river lantern"}));
    assert_eq!(created["ok"]["identity"]["phase"], "unlocked");
    let fingerprint = first.status()["fingerprint"].clone();
    let cookie = browser_cookie(&first);
    let permission = cookie.split_once('=').unwrap().1;
    assert_ne!(permission, first.token);
    let previous = first.status();
    assert!(first.api(
        "/api/quit",
        Some(json!({"session":previous["session"],"generation":previous["generation"]}))
    )["error"]
        .is_null());
    let deadline = Instant::now() + Duration::from_secs(10);
    while first.child.try_wait().unwrap().is_none() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(50));
    }
    assert!(first
        .child
        .try_wait()
        .unwrap()
        .expect("Quit must stop the process")
        .success());
    let child = launch(&profile, &assets, first.port);
    let mut restarted = Service {
        child,
        port: first.port,
        token: String::new(),
    };
    let deadline = Instant::now() + Duration::from_secs(15);
    while !profile.join("web-instance.json").exists() {
        assert!(
            restarted.child.try_wait().unwrap().is_none(),
            "restarted service exited"
        );
        assert!(Instant::now() < deadline, "restarted service did not start");
        thread::sleep(Duration::from_millis(50));
    }
    let instance: Value =
        serde_json::from_slice(&std::fs::read(profile.join("web-instance.json")).unwrap()).unwrap();
    restarted.token = instance["token"].as_str().unwrap().to_owned();
    assert_ne!(restarted.token, first.token);
    assert_ne!(restarted.status()["session"], previous["session"]);
    assert_eq!(restarted.status()["phase"], "locked");
    assert_eq!(restarted.status()["fingerprint"], fingerprint);
    let bootstrap = request(
        restarted.port,
        "/api/bootstrap",
        None,
        &format!("Cookie: {cookie}\r\n"),
    );
    assert_eq!(bootstrap.0, 200);
    assert_eq!(bootstrap.1["token"], restarted.token);
    for extra in [
        String::new(),
        format!("X-Najwa-Launch: {}\r\n", first.token),
        format!("Cookie: Najwa-Launch-{}=forged\r\n", first.port),
        format!("Cookie: {cookie}\r\nOrigin: https://example.org\r\n"),
        format!("Cookie: {cookie}\r\nSec-Fetch-Site: cross-site\r\n"),
    ] {
        assert_eq!(
            request(restarted.port, "/api/bootstrap", None, &extra).0,
            403
        );
    }
    for extra in [
        format!("X-Najwa-Session: {}\r\n", first.token),
        format!("X-Najwa-Session: {permission}\r\n"),
        format!("Cookie: {cookie}\r\n"),
    ] {
        assert_eq!(request(restarted.port, "/api/status", None, &extra).0, 403);
    }
    assert_eq!(
        request(restarted.port, "/browser-access.json", None, "").0,
        404
    );
    let other = Service::start(&directory.path().join("other-profile"), &assets);
    let other_cookie = format!("Najwa-Launch-{}={permission}", other.port);
    assert_eq!(
        request(
            other.port,
            "/api/bootstrap",
            None,
            &format!("Cookie: {other_cookie}\r\n")
        )
        .0,
        403
    );
}
