//! iOS DKM via Security.framework C FFI (§25.5, item 4.7).
//!
//! Stores the 32-byte Device Key Material in the iOS Keychain using
//! `SecItemAdd`/`SecItemCopyMatching`/`SecItemDelete` from Security.framework.
//!
//! On devices with Secure Enclave, the DKM wrapper key is hardware-backed.
//! This module is only compiled on `target_os = "ios"`.

use crate::error::{IdentityError, Result};

// Core Foundation and Security framework extern declarations.
// These are available on iOS without any additional linking beyond `-framework Security`.

#[allow(non_camel_case_types)]
type CFStringRef = *const std::ffi::c_void;
#[allow(non_camel_case_types)]
type CFDataRef = *const std::ffi::c_void;
#[allow(non_camel_case_types)]
type CFDictionaryRef = *const std::ffi::c_void;
#[allow(non_camel_case_types)]
type CFMutableDictionaryRef = *mut std::ffi::c_void;
#[allow(non_camel_case_types)]
type CFTypeRef = *const std::ffi::c_void;
#[allow(non_camel_case_types)]
type CFIndex = isize;
#[allow(non_camel_case_types)]
type OSStatus = i32;

const ERR_SEC_SUCCESS: OSStatus = 0;
const ERR_SEC_ITEM_NOT_FOUND: OSStatus = -25300;
const ERR_SEC_DUPLICATE_ITEM: OSStatus = -25299;

extern "C" {
    // CoreFoundation
    fn CFDictionaryCreateMutable(
        allocator: *const std::ffi::c_void,
        capacity: CFIndex,
        key_callbacks: *const std::ffi::c_void,
        value_callbacks: *const std::ffi::c_void,
    ) -> CFMutableDictionaryRef;
    fn CFDictionarySetValue(
        dict: CFMutableDictionaryRef,
        key: *const std::ffi::c_void,
        value: *const std::ffi::c_void,
    );
    fn CFDataCreate(
        allocator: *const std::ffi::c_void,
        bytes: *const u8,
        length: CFIndex,
    ) -> CFDataRef;
    fn CFDataGetBytePtr(data: CFDataRef) -> *const u8;
    fn CFDataGetLength(data: CFDataRef) -> CFIndex;
    fn CFRelease(cf: *const std::ffi::c_void);

    // kCF dictionary callback constants
    static kCFTypeDictionaryKeyCallBacks: *const std::ffi::c_void;
    static kCFTypeDictionaryValueCallBacks: *const std::ffi::c_void;

    // Security.framework — Keychain Services
    fn SecItemAdd(attributes: CFDictionaryRef, result: *mut CFTypeRef) -> OSStatus;
    fn SecItemCopyMatching(query: CFDictionaryRef, result: *mut CFTypeRef) -> OSStatus;
    fn SecItemDelete(query: CFDictionaryRef) -> OSStatus;

    // Keychain attribute keys
    static kSecClass: CFStringRef;
    static kSecClassGenericPassword: CFStringRef;
    static kSecAttrService: CFStringRef;
    static kSecAttrAccount: CFStringRef;
    static kSecValueData: CFStringRef;
    static kSecReturnData: CFStringRef;
    static kSecMatchLimit: CFStringRef;
    static kSecMatchLimitOne: CFStringRef;
    static kSecAttrAccessible: CFStringRef;
    static kSecAttrAccessibleWhenUnlockedThisDeviceOnly: CFStringRef;
}

const SERVICE_NAME: &[u8] = b"com.najwa.identity\0";
const ACCOUNT_NAME: &[u8] = b"najwa-dkm-v1\0";

/// Create a CFString from a null-terminated byte slice.
///
/// # Safety
/// `bytes` must be a valid null-terminated UTF-8 string.
unsafe fn cfstring_from_cstr(bytes: &[u8]) -> CFStringRef {
    extern "C" {
        fn CFStringCreateWithCString(
            allocator: *const std::ffi::c_void,
            c_str: *const u8,
            encoding: u32,
        ) -> CFStringRef;
    }
    const K_CF_STRING_ENCODING_UTF8: u32 = 0x08000100;
    CFStringCreateWithCString(std::ptr::null(), bytes.as_ptr(), K_CF_STRING_ENCODING_UTF8)
}

pub fn store_dkm(dkm: &[u8; 32]) -> Result<()> {
    // SAFETY: All CF* and SecItem* calls use valid pointers to live local variables.
    // CFRelease is called on every CF object we create before returning, preventing leaks.
    // The extern statics (kSecClass, etc.) are provided by Security.framework at link time.
    unsafe {
        let service = cfstring_from_cstr(SERVICE_NAME);
        let account = cfstring_from_cstr(ACCOUNT_NAME);
        let data = CFDataCreate(std::ptr::null(), dkm.as_ptr(), 32);

        let dict = CFDictionaryCreateMutable(
            std::ptr::null(),
            6,
            kCFTypeDictionaryKeyCallBacks,
            kCFTypeDictionaryValueCallBacks,
        );
        CFDictionarySetValue(
            dict,
            kSecClass as *const _,
            kSecClassGenericPassword as *const _,
        );
        CFDictionarySetValue(dict, kSecAttrService as *const _, service as *const _);
        CFDictionarySetValue(dict, kSecAttrAccount as *const _, account as *const _);
        CFDictionarySetValue(dict, kSecValueData as *const _, data as *const _);
        CFDictionarySetValue(
            dict,
            kSecAttrAccessible as *const _,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly as *const _,
        );

        // Delete any existing item first to handle updates
        let del_dict = CFDictionaryCreateMutable(
            std::ptr::null(),
            3,
            kCFTypeDictionaryKeyCallBacks,
            kCFTypeDictionaryValueCallBacks,
        );
        CFDictionarySetValue(
            del_dict,
            kSecClass as *const _,
            kSecClassGenericPassword as *const _,
        );
        CFDictionarySetValue(del_dict, kSecAttrService as *const _, service as *const _);
        CFDictionarySetValue(del_dict, kSecAttrAccount as *const _, account as *const _);
        let _ = SecItemDelete(del_dict as CFDictionaryRef); // Ignore not-found error

        let status = SecItemAdd(dict as CFDictionaryRef, std::ptr::null_mut());

        CFRelease(service as *const _);
        CFRelease(account as *const _);
        CFRelease(data as *const _);
        CFRelease(dict as *const _);
        CFRelease(del_dict as *const _);

        if status == ERR_SEC_SUCCESS {
            Ok(())
        } else {
            Err(IdentityError::DkmError(format!(
                "SecItemAdd failed: OSStatus {status}"
            )))
        }
    }
}

pub fn retrieve_dkm() -> Result<[u8; 32]> {
    // SAFETY: All CF* and SecItem* calls use valid pointers to live local variables.
    // We check the OSStatus return before accessing `result`. CFDataGetBytePtr is valid
    // because SecItemCopyMatching returns a CFDataRef when kSecReturnData is set.
    // CFRelease is called on every CF object before each return path.
    unsafe {
        let service = cfstring_from_cstr(SERVICE_NAME);
        let account = cfstring_from_cstr(ACCOUNT_NAME);

        let dict = CFDictionaryCreateMutable(
            std::ptr::null(),
            5,
            kCFTypeDictionaryKeyCallBacks,
            kCFTypeDictionaryValueCallBacks,
        );
        CFDictionarySetValue(
            dict,
            kSecClass as *const _,
            kSecClassGenericPassword as *const _,
        );
        CFDictionarySetValue(dict, kSecAttrService as *const _, service as *const _);
        CFDictionarySetValue(dict, kSecAttrAccount as *const _, account as *const _);
        CFDictionarySetValue(dict, kSecReturnData as *const _, 1 as *const _); // kCFBooleanTrue
        CFDictionarySetValue(
            dict,
            kSecMatchLimit as *const _,
            kSecMatchLimitOne as *const _,
        );

        let mut result: CFTypeRef = std::ptr::null();
        let status = SecItemCopyMatching(dict as CFDictionaryRef, &mut result);

        CFRelease(service as *const _);
        CFRelease(account as *const _);
        CFRelease(dict as *const _);

        if status == ERR_SEC_ITEM_NOT_FOUND {
            return Err(IdentityError::DkmError("DKM not found in Keychain".into()));
        }
        if status != ERR_SEC_SUCCESS {
            return Err(IdentityError::DkmError(format!(
                "SecItemCopyMatching failed: OSStatus {status}"
            )));
        }

        let data = result as CFDataRef;
        let len = CFDataGetLength(data);
        if len != 32 {
            CFRelease(result);
            return Err(IdentityError::DkmError(format!(
                "DKM size mismatch: expected 32, got {len}"
            )));
        }

        let ptr = CFDataGetBytePtr(data);
        let mut dkm = [0u8; 32];
        std::ptr::copy_nonoverlapping(ptr, dkm.as_mut_ptr(), 32);
        CFRelease(result);

        Ok(dkm)
    }
}

pub fn delete_dkm() -> Result<()> {
    // SAFETY: All CF* and SecItem* calls use valid pointers to live local variables.
    // CFRelease is called on every CF object before returning.
    unsafe {
        let service = cfstring_from_cstr(SERVICE_NAME);
        let account = cfstring_from_cstr(ACCOUNT_NAME);

        let dict = CFDictionaryCreateMutable(
            std::ptr::null(),
            3,
            kCFTypeDictionaryKeyCallBacks,
            kCFTypeDictionaryValueCallBacks,
        );
        CFDictionarySetValue(
            dict,
            kSecClass as *const _,
            kSecClassGenericPassword as *const _,
        );
        CFDictionarySetValue(dict, kSecAttrService as *const _, service as *const _);
        CFDictionarySetValue(dict, kSecAttrAccount as *const _, account as *const _);

        let status = SecItemDelete(dict as CFDictionaryRef);

        CFRelease(service as *const _);
        CFRelease(account as *const _);
        CFRelease(dict as *const _);

        if status == ERR_SEC_SUCCESS || status == ERR_SEC_ITEM_NOT_FOUND {
            Ok(())
        } else {
            Err(IdentityError::DkmError(format!(
                "SecItemDelete failed: OSStatus {status}"
            )))
        }
    }
}
