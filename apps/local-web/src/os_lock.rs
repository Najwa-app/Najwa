//! Operating-system lock triggers (S13 §8.5). Locking the session, switching
//! user or sleeping locks the profile through the same path as `POST /api/lock`.
//! Each platform runs a listener thread. A listener that cannot start prints one
//! line to standard error and the service runs without it.
use std::sync::OnceLock;

static ON_LOCK: OnceLock<Box<dyn Fn() + Send + Sync>> = OnceLock::new();

/// Starts the platform listener. `on_lock` runs on a listener thread.
pub fn watch(on_lock: impl Fn() + Send + Sync + 'static) {
    if ON_LOCK.set(Box::new(on_lock)).is_ok() {
        std::thread::spawn(platform::listen);
    }
}
fn lock() {
    if let Some(on_lock) = ON_LOCK.get() {
        on_lock();
    }
}
fn unavailable(trigger: &str) {
    eprintln!("Najwa: {trigger} will not lock Najwa");
}

#[cfg(windows)]
mod platform {
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::{
        Foundation::{HWND, LPARAM, LRESULT, WPARAM},
        System::{
            LibraryLoader::GetModuleHandleW,
            Power::RegisterSuspendResumeNotification,
            RemoteDesktop::{WTSRegisterSessionNotification, NOTIFY_FOR_THIS_SESSION},
        },
        UI::WindowsAndMessaging::*,
    };

    /// Class of the message-only listener window (found by tests/persistent_profile.rs).
    const CLASS: &str = "NajwaOsLock";

    /// Session lock, console or remote disconnect (user switch) and suspend lock.
    pub fn should_lock(message: u32, wparam: WPARAM) -> bool {
        let Ok(event) = u32::try_from(wparam) else {
            return false;
        };
        match message {
            WM_WTSSESSION_CHANGE => matches!(
                event,
                WTS_SESSION_LOCK | WTS_CONSOLE_DISCONNECT | WTS_REMOTE_DISCONNECT
            ),
            WM_POWERBROADCAST => event == PBT_APMSUSPEND,
            _ => false,
        }
    }
    unsafe extern "system" fn window(
        hwnd: HWND,
        message: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        // Lock before returning: Windows waits about two seconds for suspend handlers.
        if should_lock(message, wparam) {
            super::lock();
        }
        DefWindowProcW(hwnd, message, wparam, lparam)
    }
    pub fn listen() {
        let class: Vec<u16> = CLASS.encode_utf16().chain([0]).collect();
        unsafe {
            let instance = GetModuleHandleW(null());
            let description = WNDCLASSW {
                lpfnWndProc: Some(window),
                hInstance: instance,
                lpszClassName: class.as_ptr(),
                ..std::mem::zeroed()
            };
            let hwnd = if RegisterClassW(&description) == 0 {
                null_mut()
            } else {
                CreateWindowExW(
                    0, class.as_ptr(), null(), 0, 0, 0, 0, 0,
                    HWND_MESSAGE, null_mut(), instance, null(),
                )
            };
            if hwnd.is_null() {
                super::unavailable("locking, switching user or sleeping");
                return;
            }
            if WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION) == 0 {
                super::unavailable("locking or switching user");
            }
            // Message-only windows receive no broadcasts; this addresses suspend to this one.
            if RegisterSuspendResumeNotification(hwnd, DEVICE_NOTIFY_WINDOW_HANDLE) == 0 {
                super::unavailable("sleeping");
            }
            let mut message: MSG = std::mem::zeroed();
            while GetMessageW(&mut message, null_mut(), 0, 0) > 0 {
                DispatchMessageW(&message);
            }
        }
    }
}

// Not yet run on Linux: only type-checked with a cross-target `cargo check`.
#[cfg(target_os = "linux")]
mod platform {
    use dbus::{
        blocking::{BlockingSender, Connection},
        message::MatchRule,
        Message,
    };
    use std::time::Duration;

    const LOGIND: &str = "org.freedesktop.login1";

    pub fn listen() {
        std::thread::spawn(screen_saver);
        let Ok(bus) = Connection::new_system() else {
            return super::unavailable("locking the session or sleeping");
        };
        let sleep = MatchRule::new_signal("org.freedesktop.login1.Manager", "PrepareForSleep");
        watch(&bus, "sleeping", sleep.with_sender(LOGIND).with_path("/org/freedesktop/login1"));
        match session(&bus) {
            Some(path) => {
                let lock = MatchRule::new_signal("org.freedesktop.login1.Session", "Lock");
                watch(&bus, "locking the session", lock.with_sender(LOGIND).with_path(path));
            }
            None => super::unavailable("locking the session"),
        }
        run(&bus);
    }
    /// logind's "auto" session: the caller's, or else the user's graphical session.
    fn session(bus: &Connection) -> Option<String> {
        let call = Message::new_method_call(LOGIND, "/org/freedesktop/login1", "org.freedesktop.login1.Manager", "GetSession")
            .ok()?
            .append1("auto");
        let reply = bus.send_with_reply_and_block(call, Duration::from_secs(5)).ok()?;
        let path = reply.read1::<dbus::Path>().ok()?.to_string();
        Some(path)
    }
    fn screen_saver() {
        let Ok(bus) = Connection::new_session() else {
            return super::unavailable("the screen saver");
        };
        // GNOME announces its lock screen only on its own interface.
        for interface in ["org.freedesktop.ScreenSaver", "org.gnome.ScreenSaver"] {
            watch(&bus, "the screen saver", MatchRule::new_signal(interface, "ActiveChanged"));
        }
        run(&bus);
    }
    fn watch(bus: &Connection, trigger: &str, rule: MatchRule<'static>) {
        // PrepareForSleep(true) and ActiveChanged(true) lock. Lock has no argument.
        // Only an explicit false (wake, screen saver off) does not.
        let added = bus.add_match(rule, |_: (), _, message: &Message| {
            if message.get1::<bool>().unwrap_or(true) {
                super::lock();
            }
            true
        });
        if added.is_err() {
            super::unavailable(trigger);
        }
    }
    fn run(bus: &Connection) {
        while bus.process(Duration::from_secs(60)).is_ok() {}
    }
}

// Not yet run on macOS: only type-checked with a cross-target `cargo check`.
#[cfg(target_os = "macos")]
mod platform {
    use core_foundation::{
        base::{CFRelease, CFTypeRef, TCFType},
        dictionary::{CFDictionaryGetValue, CFDictionaryRef},
        number::kCFBooleanFalse,
        runloop::{
            kCFRunLoopDefaultMode, CFRunLoop, CFRunLoopAddSource, CFRunLoopGetCurrent,
            CFRunLoopRunResult, CFRunLoopSourceRef,
        },
        string::CFString,
    };
    use std::{
        ffi::c_void,
        ptr::null_mut,
        sync::atomic::{AtomicU32, Ordering},
        time::Duration,
    };

    // IOKit/IOMessage.h: iokit_common_msg(0x270) and iokit_common_msg(0x280).
    const CAN_SYSTEM_SLEEP: u32 = 0xE000_0270;
    const SYSTEM_WILL_SLEEP: u32 = 0xE000_0280;

    #[link(name = "IOKit", kind = "framework")]
    extern "C" {
        fn IORegisterForSystemPower(
            refcon: *mut c_void,
            port: *mut *mut c_void,
            callback: extern "C" fn(*mut c_void, u32, u32, *mut c_void),
            notifier: *mut u32,
        ) -> u32;
        fn IONotificationPortGetRunLoopSource(port: *mut c_void) -> CFRunLoopSourceRef;
        fn IOAllowPowerChange(kernel_port: u32, notification: isize) -> i32;
    }
    #[link(name = "CoreGraphics", kind = "framework")]
    extern "C" {
        fn CGSessionCopyCurrentDictionary() -> CFDictionaryRef;
    }

    static ROOT_PORT: AtomicU32 = AtomicU32::new(0);

    extern "C" fn power(_: *mut c_void, _: u32, message: u32, argument: *mut c_void) {
        if message == SYSTEM_WILL_SLEEP {
            super::lock();
        }
        // Sleep waits for this answer (up to 30 s), so it comes after the lock.
        if matches!(message, CAN_SYSTEM_SLEEP | SYSTEM_WILL_SLEEP) {
            unsafe { IOAllowPowerChange(ROOT_PORT.load(Ordering::SeqCst), argument as isize) };
        }
    }
    /// The screen is locked, or another user's session holds the console.
    fn session_locked() -> bool {
        unsafe {
            let session = CGSessionCopyCurrentDictionary();
            if session.is_null() {
                return false;
            }
            let value = |key: &'static str| {
                CFDictionaryGetValue(session, CFString::from_static_string(key).as_concrete_TypeRef() as *const c_void)
            };
            let screen = value("CGSSessionScreenIsLocked");
            let console = value("kCGSSessionOnConsoleKey");
            CFRelease(session as CFTypeRef);
            let no = kCFBooleanFalse as *const c_void;
            (!screen.is_null() && screen != no) || console == no
        }
    }
    pub fn listen() {
        unsafe {
            let mut port = null_mut();
            let mut notifier = 0;
            let root = IORegisterForSystemPower(null_mut(), &mut port, power, &mut notifier);
            if root == 0 {
                super::unavailable("sleeping");
            } else {
                ROOT_PORT.store(root, Ordering::SeqCst);
                CFRunLoopAddSource(
                    CFRunLoopGetCurrent(),
                    IONotificationPortGetRunLoopSource(port),
                    kCFRunLoopDefaultMode,
                );
            }
        }
        // ponytail: poll every 2 s. Distributed notifications such as
        // com.apple.screenIsLocked arrive only on the main thread's run loop,
        // and the main thread runs tokio. Moving tokio off it would allow them.
        let mut was_locked = false;
        loop {
            let ran = CFRunLoop::run_in_mode(unsafe { kCFRunLoopDefaultMode }, Duration::from_secs(2), false);
            if matches!(ran, CFRunLoopRunResult::Finished) {
                std::thread::sleep(Duration::from_secs(2)); // no power source to wait on
            }
            let locked = session_locked();
            if locked && !was_locked {
                super::lock();
            }
            was_locked = locked;
        }
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::platform::should_lock;
    use windows_sys::Win32::UI::WindowsAndMessaging::*;

    #[test]
    fn windows_locks_on_session_lock_user_switch_and_suspend_only() {
        for event in [WTS_SESSION_LOCK, WTS_CONSOLE_DISCONNECT, WTS_REMOTE_DISCONNECT] {
            assert!(should_lock(WM_WTSSESSION_CHANGE, event as usize));
        }
        assert!(should_lock(WM_POWERBROADCAST, PBT_APMSUSPEND as usize));
        for event in [WTS_SESSION_UNLOCK, WTS_SESSION_LOGON, WTS_CONSOLE_CONNECT, WTS_REMOTE_CONNECT] {
            assert!(!should_lock(WM_WTSSESSION_CHANGE, event as usize));
        }
        for event in [PBT_APMRESUMEAUTOMATIC, PBT_APMRESUMESUSPEND, PBT_APMPOWERSTATUSCHANGE] {
            assert!(!should_lock(WM_POWERBROADCAST, event as usize));
        }
        // An event code only counts under its own message.
        assert!(!should_lock(WM_POWERBROADCAST, WTS_SESSION_LOCK as usize));
        assert!(!should_lock(WM_SETTINGCHANGE, PBT_APMSUSPEND as usize));
    }
}
