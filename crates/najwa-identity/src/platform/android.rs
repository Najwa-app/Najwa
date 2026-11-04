//! Android DKM via JNI (AndroidKeyStore) (§25.4, item 4.6).
//!
//! Stores the 32-byte Device Key Material in Android KeyStore via JNI.
//! The DKM is wrapped with an AES-256-GCM key stored in AndroidKeyStore
//! (hardware-backed on devices with StrongBox/TEE), and the wrapped
//! ciphertext (IV || ct) is persisted in the app-private SharedPreferences
//! file `najwa_dkm` under the key `wrapped_dkm` as a NO_WRAP Base64 string.
//!
//! This yields the stable, hardware-bound 2-of-2 identity protection
//! described in S02 §4: even an attacker with the raw app private data
//! cannot unwrap the DKM without the KeyStore wrapper key, and an attacker
//! with KeyStore access cannot recover plaintext without the wrapped blob.
//!
//! This module is only compiled on `target_os = "android"`.

use crate::error::{IdentityError, Result};
use jni::objects::{Global, JByteArray, JObject, JString, JValue};
use jni::{jni_sig, jni_str, Env};
use std::sync::OnceLock;

const KEYSTORE_PROVIDER: &str = "AndroidKeyStore";
const KEY_ALIAS: &str = "najwa_dkm_wrapper";
const PREF_NAME: &str = "najwa_dkm";
const PREF_KEY: &str = "wrapped_dkm";
/// `Context.MODE_PRIVATE` — private per-app SharedPreferences file.
const MODE_PRIVATE: i32 = 0;
/// `android.util.Base64.NO_WRAP` — single-line Base64 with no trailing newline.
const BASE64_NO_WRAP: i32 = 2;
/// AES-GCM authentication tag length in bits.
const GCM_TAG_BITS: i32 = 128;
/// AES-GCM IV length in bytes (AndroidKeyStore mandates 12).
const GCM_IV_LEN: usize = 12;

/// Cached JVM pointer for JNI calls from Rust threads.
static JAVA_VM: OnceLock<jni::JavaVM> = OnceLock::new();

/// Global reference to the Android `Application` Context, supplied by Kotlin
/// via `nativeSetAppContext` immediately after `System.loadLibrary`.
static APP_CONTEXT: OnceLock<Global<JObject<'static>>> = OnceLock::new();

/// Must be called once from JNI_OnLoad or app initialization to cache the JVM.
pub fn set_java_vm(vm: jni::JavaVM) {
    let _ = JAVA_VM.set(vm);
}

/// Cache a global reference to the Android application Context.
///
/// Must be called from Kotlin via the FFI bridge (`nativeSetAppContext`)
/// before any `store_dkm` / `retrieve_dkm` / `delete_dkm` call. Without this
/// the DKM cannot be persisted in SharedPreferences and unlock will fail.
pub fn set_app_context(env: &mut Env, ctx: JObject) -> Result<()> {
    if APP_CONTEXT.get().is_some() {
        // Idempotent: a second call is a no-op so hot-restarts / unit tests
        // that re-invoke nativeSetAppContext do not fail.
        return Ok(());
    }
    let global = env
        .new_global_ref(&ctx)
        .map_err(|e| IdentityError::DkmError(format!("new_global_ref(Context): {}", e)))?;
    APP_CONTEXT
        .set(global)
        .map_err(|_| IdentityError::DkmError("APP_CONTEXT already set".into()))?;
    tracing::info!("najwa-identity: APP_CONTEXT cached for SharedPreferences-backed DKM");
    Ok(())
}

fn with_env<F, T>(f: F) -> Result<T>
where
    F: FnOnce(&mut Env) -> Result<T>,
{
    let vm = JAVA_VM
        .get()
        .ok_or_else(|| IdentityError::DkmError("JavaVM not initialized".into()))?;
    vm.attach_current_thread(|env| f(env))
}

/// Obtain the cached application Context or fail with DkmError.
fn app_context() -> Result<&'static Global<JObject<'static>>> {
    APP_CONTEXT.get().ok_or_else(|| {
        IdentityError::DkmError(
            "APP_CONTEXT not set — call nativeSetAppContext after System.loadLibrary".into(),
        )
    })
}

/// Generate or load the AES wrapper key in AndroidKeyStore.
fn ensure_wrapper_key(env: &mut Env) -> Result<()> {
    // Check if key already exists
    let provider_jstr = env.new_string(KEYSTORE_PROVIDER)?;
    let ks = env
        .call_static_method(
            jni_str!("java/security/KeyStore"),
            jni_str!("getInstance"),
            jni_sig!("(Ljava/lang/String;)Ljava/security/KeyStore;"),
            &[JValue::Object(&provider_jstr.into())],
        )?
        .l()?;

    env.call_method(
        &ks,
        jni_str!("load"),
        jni_sig!("(Ljava/security/KeyStore$LoadStoreParameter;)V"),
        &[JValue::Object(&JObject::null())],
    )?;

    let alias_jstr = env.new_string(KEY_ALIAS)?;
    let has_key = env
        .call_method(
            &ks,
            jni_str!("containsAlias"),
            jni_sig!("(Ljava/lang/String;)Z"),
            &[JValue::Object(&alias_jstr.into())],
        )?
        .z()?;

    if has_key {
        return Ok(());
    }

    // Generate new AES-256-GCM key in AndroidKeyStore
    let purpose_encrypt_decrypt = 3i32; // KeyProperties.PURPOSE_ENCRYPT | PURPOSE_DECRYPT

    // Use KeyGenerator to create AES key
    let aes_jstr = env.new_string("AES")?;
    let provider_jstr2 = env.new_string(KEYSTORE_PROVIDER)?;
    let kg = env
        .call_static_method(
            jni_str!("javax/crypto/KeyGenerator"),
            jni_str!("getInstance"),
            jni_sig!("(Ljava/lang/String;Ljava/lang/String;)Ljavax/crypto/KeyGenerator;"),
            &[
                JValue::Object(&aes_jstr.into()),
                JValue::Object(&provider_jstr2.into()),
            ],
        )?
        .l()?;

    // Build the KeyGenParameterSpec
    let alias_jstr2 = env.new_string(KEY_ALIAS)?;
    let builder = env.new_object(
        jni_str!("android/security/keystore/KeyGenParameterSpec$Builder"),
        jni_sig!("(Ljava/lang/String;I)V"),
        &[
            JValue::Object(&alias_jstr2.into()),
            JValue::Int(purpose_encrypt_decrypt),
        ],
    )?;

    let gcm_jstr = env.new_string("GCM")?;
    let block_modes = env.new_object_array(1, jni_str!("java/lang/String"), &gcm_jstr)?;
    env.call_method(
        &builder,
        jni_str!("setBlockModes"),
        jni_sig!("([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;"),
        &[JValue::Object(&block_modes.into())],
    )?;

    let nopad_jstr = env.new_string("NoPadding")?;
    let paddings = env.new_object_array(1, jni_str!("java/lang/String"), &nopad_jstr)?;
    env.call_method(
        &builder,
        jni_str!("setEncryptionPaddings"),
        jni_sig!("([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;"),
        &[JValue::Object(&paddings.into())],
    )?;

    env.call_method(
        &builder,
        jni_str!("setKeySize"),
        jni_sig!("(I)Landroid/security/keystore/KeyGenParameterSpec$Builder;"),
        &[JValue::Int(256)],
    )?;

    let spec_obj = env
        .call_method(
            &builder,
            jni_str!("build"),
            jni_sig!("()Landroid/security/keystore/KeyGenParameterSpec;"),
            &[],
        )?
        .l()?;

    env.call_method(
        &kg,
        jni_str!("init"),
        jni_sig!("(Ljava/security/spec/AlgorithmParameterSpec;)V"),
        &[JValue::Object(&spec_obj)],
    )?;

    env.call_method(
        &kg,
        jni_str!("generateKey"),
        jni_sig!("()Ljavax/crypto/SecretKey;"),
        &[],
    )?;

    Ok(())
}

/// Load the AES wrapper key from AndroidKeyStore.
fn load_wrapper_key<'local>(env: &mut Env<'local>) -> Result<JObject<'local>> {
    let provider_jstr = env.new_string(KEYSTORE_PROVIDER)?;
    let ks = env
        .call_static_method(
            jni_str!("java/security/KeyStore"),
            jni_str!("getInstance"),
            jni_sig!("(Ljava/lang/String;)Ljava/security/KeyStore;"),
            &[JValue::Object(&provider_jstr.into())],
        )?
        .l()?;

    env.call_method(
        &ks,
        jni_str!("load"),
        jni_sig!("(Ljava/security/KeyStore$LoadStoreParameter;)V"),
        &[JValue::Object(&JObject::null())],
    )?;

    let alias_jstr = env.new_string(KEY_ALIAS)?;
    let key = env
        .call_method(
            &ks,
            jni_str!("getKey"),
            jni_sig!("(Ljava/lang/String;[C)Ljava/security/Key;"),
            &[
                JValue::Object(&alias_jstr.into()),
                JValue::Object(&JObject::null()),
            ],
        )?
        .l()?;
    Ok(key)
}

/// Write `bytes` to SharedPreferences under `PREF_KEY`, Base64-encoded NO_WRAP.
fn shared_prefs_put(env: &mut Env, combined: &[u8]) -> Result<()> {
    let ctx = app_context()?;
    // context.getSharedPreferences(PREF_NAME, MODE_PRIVATE)
    let pref_name_jstr = env.new_string(PREF_NAME)?;
    let prefs = env
        .call_method(
            ctx.as_ref(),
            jni_str!("getSharedPreferences"),
            jni_sig!("(Ljava/lang/String;I)Landroid/content/SharedPreferences;"),
            &[
                JValue::Object(&pref_name_jstr.into()),
                JValue::Int(MODE_PRIVATE),
            ],
        )?
        .l()?;

    // prefs.edit()
    let editor = env
        .call_method(
            &prefs,
            jni_str!("edit"),
            jni_sig!("()Landroid/content/SharedPreferences$Editor;"),
            &[],
        )?
        .l()?;

    // Base64.encodeToString(combined, NO_WRAP)
    let combined_jarr = env.byte_array_from_slice(combined)?;
    let encoded = env
        .call_static_method(
            jni_str!("android/util/Base64"),
            jni_str!("encodeToString"),
            jni_sig!("([BI)Ljava/lang/String;"),
            &[
                JValue::Object(&combined_jarr.into()),
                JValue::Int(BASE64_NO_WRAP),
            ],
        )?
        .l()?;

    // editor.putString(PREF_KEY, encoded)
    let pref_key_jstr = env.new_string(PREF_KEY)?;
    env.call_method(
        &editor,
        jni_str!("putString"),
        jni_sig!(
            "(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;"
        ),
        &[
            JValue::Object(&pref_key_jstr.into()),
            JValue::Object(&encoded),
        ],
    )?;

    // editor.apply()
    env.call_method(&editor, jni_str!("apply"), jni_sig!("()V"), &[])?;

    Ok(())
}

/// Read the SharedPreferences entry and Base64-decode it. Returns `None`
/// cleanly if the entry is missing (first-run, post-wipe, etc).
fn shared_prefs_get(env: &mut Env) -> Result<Option<Vec<u8>>> {
    let ctx = app_context()?;
    let pref_name_jstr = env.new_string(PREF_NAME)?;
    let prefs = env
        .call_method(
            ctx.as_ref(),
            jni_str!("getSharedPreferences"),
            jni_sig!("(Ljava/lang/String;I)Landroid/content/SharedPreferences;"),
            &[
                JValue::Object(&pref_name_jstr.into()),
                JValue::Int(MODE_PRIVATE),
            ],
        )?
        .l()?;

    let pref_key_jstr = env.new_string(PREF_KEY)?;
    let null_default = JObject::null();
    let value = env
        .call_method(
            &prefs,
            jni_str!("getString"),
            jni_sig!("(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;"),
            &[
                JValue::Object(&pref_key_jstr.into()),
                JValue::Object(&null_default),
            ],
        )?
        .l()?;

    if value.is_null() {
        return Ok(None);
    }

    // Coerce to JString and round-trip through Rust so we can hand a fresh
    // JString back to `Base64.decode`. jni 0.22 no longer implements
    // `From<JObject> for JString`, so we rebuild via `from_raw`.
    let value_str: JString = unsafe { JString::from_raw(env, value.into_raw()) };
    let rust_str: String = value_str.try_to_string(env)?;

    let jstr_for_decode = env.new_string(&rust_str)?;
    let decoded = env
        .call_static_method(
            jni_str!("android/util/Base64"),
            jni_str!("decode"),
            jni_sig!("(Ljava/lang/String;I)[B"),
            &[
                JValue::Object(&jstr_for_decode.into()),
                JValue::Int(BASE64_NO_WRAP),
            ],
        )?
        .l()?;

    let arr = unsafe { JByteArray::from_raw(env, decoded.into_raw()) };
    let bytes = env.convert_byte_array(&arr)?;
    Ok(Some(bytes))
}

/// Delete the SharedPreferences entry (no-op if missing).
fn shared_prefs_clear(env: &mut Env) -> Result<()> {
    let ctx = match app_context() {
        Ok(c) => c,
        // If the Context was never set, there is nothing to clear — treat as success.
        Err(_) => return Ok(()),
    };
    let pref_name_jstr = env.new_string(PREF_NAME)?;
    let prefs = env
        .call_method(
            ctx.as_ref(),
            jni_str!("getSharedPreferences"),
            jni_sig!("(Ljava/lang/String;I)Landroid/content/SharedPreferences;"),
            &[
                JValue::Object(&pref_name_jstr.into()),
                JValue::Int(MODE_PRIVATE),
            ],
        )?
        .l()?;

    let editor = env
        .call_method(
            &prefs,
            jni_str!("edit"),
            jni_sig!("()Landroid/content/SharedPreferences$Editor;"),
            &[],
        )?
        .l()?;

    let pref_key_jstr = env.new_string(PREF_KEY)?;
    env.call_method(
        &editor,
        jni_str!("remove"),
        jni_sig!("(Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;"),
        &[JValue::Object(&pref_key_jstr.into())],
    )?;

    env.call_method(&editor, jni_str!("apply"), jni_sig!("()V"), &[])?;
    Ok(())
}

pub fn store_dkm(dkm: &[u8; 32]) -> Result<()> {
    // Fail fast if Context is missing — otherwise we'd encrypt, throw away
    // the ciphertext, and produce the exact "silent DKM loss" bug we're fixing.
    let _ = app_context()?;
    with_env(|env| {
        ensure_wrapper_key(env)?;
        let key_entry = load_wrapper_key(env)?;

        // Encrypt DKM with AES-256-GCM
        let transform_jstr = env.new_string("AES/GCM/NoPadding")?;
        let cipher = env
            .call_static_method(
                jni_str!("javax/crypto/Cipher"),
                jni_str!("getInstance"),
                jni_sig!("(Ljava/lang/String;)Ljavax/crypto/Cipher;"),
                &[JValue::Object(&transform_jstr.into())],
            )?
            .l()?;

        let encrypt_mode = 1i32; // Cipher.ENCRYPT_MODE
        env.call_method(
            &cipher,
            jni_str!("init"),
            jni_sig!("(ILjava/security/Key;)V"),
            &[JValue::Int(encrypt_mode), JValue::Object(&key_entry)],
        )?;

        // Get IV (KeyStore-generated; caller MUST NOT supply one on encrypt)
        let iv = env
            .call_method(&cipher, jni_str!("getIV"), jni_sig!("()[B"), &[])?
            .l()?;

        // Encrypt
        let plaintext = env.byte_array_from_slice(dkm)?;
        let ciphertext = env
            .call_method(
                &cipher,
                jni_str!("doFinal"),
                jni_sig!("([B)[B"),
                &[JValue::Object(&plaintext.into())],
            )?
            .l()?;

        let iv_arr = unsafe { JByteArray::from_raw(env, iv.into_raw()) };
        let iv_bytes = env.convert_byte_array(&iv_arr)?;
        let ct_arr = unsafe { JByteArray::from_raw(env, ciphertext.into_raw()) };
        let ct_bytes = env.convert_byte_array(&ct_arr)?;

        if iv_bytes.len() != GCM_IV_LEN {
            return Err(IdentityError::DkmError(format!(
                "unexpected GCM IV length {}",
                iv_bytes.len()
            )));
        }

        let mut combined = Vec::with_capacity(iv_bytes.len() + ct_bytes.len());
        combined.extend_from_slice(&iv_bytes);
        combined.extend_from_slice(&ct_bytes);

        shared_prefs_put(env, &combined)?;

        tracing::info!(
            "najwa-identity: DKM wrapped and persisted (iv={}B, ct={}B)",
            iv_bytes.len(),
            ct_bytes.len()
        );
        Ok(())
    })
}

pub fn retrieve_dkm() -> Result<[u8; 32]> {
    with_env(|env| {
        let combined = match shared_prefs_get(env)? {
            Some(b) => b,
            None => {
                return Err(IdentityError::DkmError(
                    "no wrapped DKM in SharedPreferences".into(),
                ));
            }
        };

        if combined.len() < GCM_IV_LEN + 16 {
            return Err(IdentityError::DkmError(format!(
                "wrapped DKM too short: {} bytes",
                combined.len()
            )));
        }
        let (iv_bytes, ct_bytes) = combined.split_at(GCM_IV_LEN);

        let key_entry = load_wrapper_key(env)?;

        // Build GCMParameterSpec(128, iv)
        let iv_jarr = env.byte_array_from_slice(iv_bytes)?;
        let gcm_spec = env.new_object(
            jni_str!("javax/crypto/spec/GCMParameterSpec"),
            jni_sig!("(I[B)V"),
            &[JValue::Int(GCM_TAG_BITS), JValue::Object(&iv_jarr.into())],
        )?;

        let transform_jstr = env.new_string("AES/GCM/NoPadding")?;
        let cipher = env
            .call_static_method(
                jni_str!("javax/crypto/Cipher"),
                jni_str!("getInstance"),
                jni_sig!("(Ljava/lang/String;)Ljavax/crypto/Cipher;"),
                &[JValue::Object(&transform_jstr.into())],
            )?
            .l()?;

        let decrypt_mode = 2i32; // Cipher.DECRYPT_MODE
        env.call_method(
            &cipher,
            jni_str!("init"),
            jni_sig!("(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;)V"),
            &[
                JValue::Int(decrypt_mode),
                JValue::Object(&key_entry),
                JValue::Object(&gcm_spec),
            ],
        )?;

        let ct_jarr = env.byte_array_from_slice(ct_bytes)?;
        let pt = env
            .call_method(
                &cipher,
                jni_str!("doFinal"),
                jni_sig!("([B)[B"),
                &[JValue::Object(&ct_jarr.into())],
            )?
            .l()?;

        let pt_arr = unsafe { JByteArray::from_raw(env, pt.into_raw()) };
        let pt_bytes = env.convert_byte_array(&pt_arr)?;

        if pt_bytes.len() != 32 {
            return Err(IdentityError::DkmError(format!(
                "unwrapped DKM has wrong length {}",
                pt_bytes.len()
            )));
        }
        let mut dkm = [0u8; 32];
        dkm.copy_from_slice(&pt_bytes);
        Ok(dkm)
    })
}

pub fn delete_dkm() -> Result<()> {
    with_env(|env| {
        // Clear the persisted ciphertext first; even if KeyStore deletion
        // fails below, a stale wrapped blob without its wrapper key is useless
        // and we must not leave a decoy that future `retrieve_dkm` calls hit.
        shared_prefs_clear(env)?;

        // Delete the wrapper key from AndroidKeyStore
        let provider_jstr = env.new_string(KEYSTORE_PROVIDER)?;
        let ks = env
            .call_static_method(
                jni_str!("java/security/KeyStore"),
                jni_str!("getInstance"),
                jni_sig!("(Ljava/lang/String;)Ljava/security/KeyStore;"),
                &[JValue::Object(&provider_jstr.into())],
            )?
            .l()?;

        env.call_method(
            &ks,
            jni_str!("load"),
            jni_sig!("(Ljava/security/KeyStore$LoadStoreParameter;)V"),
            &[JValue::Object(&JObject::null())],
        )?;

        let alias_jstr = env.new_string(KEY_ALIAS)?;
        env.call_method(
            &ks,
            jni_str!("deleteEntry"),
            jni_sig!("(Ljava/lang/String;)V"),
            &[JValue::Object(&alias_jstr.into())],
        )?;

        tracing::info!("najwa-identity: DKM wrapper key + SharedPreferences entry deleted");
        Ok(())
    })
}
