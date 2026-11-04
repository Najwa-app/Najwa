/* Najwa thin C ABI (S17 §1–§6).
 *
 * 13 operation functions (§4.1–§4.4) + 7 callback functions (§5.2 + clear).
 * Contracts (normative, apply to every symbol):
 *  - §3: no panic crosses the boundary; NULL/UTF-8 inputs rejected by code.
 *  - §4.4: strings returned by najwa_* MUST be freed with najwa_free_string
 *    (zeroize-before-free); najwa_version() is static and MUST NOT be freed.
 *  - §5.3: after najwa_set_*_callback / najwa_clear_all_callbacks returns,
 *    the previous callback is quiescent (not executing, never invoked again).
 *  - §5.5: callbacks fire on ONE dedicated thread; callbacks MUST NOT call
 *    any najwa_* function (no re-entry).
 *  - §5.6: returned JSON may contain plaintext; free via najwa_free_string.
 */
/* Maintained by hand to match the najwa-ffi exports (S17 §6). */

#ifndef NAJWA_CORE_H
#define NAJWA_CORE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------------------------------------------------------------------
 * §5.1 Callback types (closed sets are normative)
 * --------------------------------------------------------------------------- */

/* Message status lifecycle (§5.1): 0=Queued, 1=Deposited, 2=Delivered,
 * 3=Read, 4=Failed (retries exhausted), 5=Retrying (the core retries the
 * send). No other value may be emitted. */
typedef void (*NajwaMessageReceivedCallback)(const char* contact_id, const char* content);
typedef void (*NajwaMessageStatusCallback)(const char* msg_id, int32_t status);
typedef void (*NajwaConnectionStatusCallback)(int32_t connected);
/* Not emitted in this release (S17 §5.1). */
typedef void (*NajwaErrorCallback)(int32_t code, const char* message);
/* Feature strings (S17 §5.1, closed set): "cover_traffic" is the only defined
 * feature; "vpn_mode", "post_poll_burst" and "background_poll" are reserved.
 * Not emitted in this release. Platform layers MUST ignore unrecognised
 * strings. */
typedef void (*NajwaFeatureToggleCallback)(const char* feature, int32_t enabled);
/* S17 §5.4 event channel: event_json is a UTF-8 JSON object with at least
 * {"event": "<name>", ...}. Defined events: "file_transfer_interrupted"
 * (S11 §2.6/§4.1), "file_transfer_progress" (S11 §3), "repair_state_changed"
 * (S06 §3.7). No operation emits events on this channel in this release;
 * only the message-received, message-status and connection-status callbacks
 * fire. Platform layers MUST ignore unrecognised event names. */
typedef void (*NajwaEventCallback)(const char* event_json);

/* ---------------------------------------------------------------------------
 * §5.2 Registration (thread-safe, quiescent on return — §5.3)
 * --------------------------------------------------------------------------- */

void najwa_set_message_received_callback(NajwaMessageReceivedCallback cb);
void najwa_set_message_status_callback(NajwaMessageStatusCallback cb);
void najwa_set_connection_status_callback(NajwaConnectionStatusCallback cb);
void najwa_set_error_callback(NajwaErrorCallback cb);
void najwa_set_feature_toggle_callback(NajwaFeatureToggleCallback cb);
void najwa_set_event_callback(NajwaEventCallback cb);
/* Clears every slot and drops queued events; a callback registered afterwards
 * receives later events at once. najwa_lock also suspends delivery until the
 * next create or unlock. */
void najwa_clear_all_callbacks(void);

/* ---------------------------------------------------------------------------
 * §4.1 Lifecycle (6)
 * --------------------------------------------------------------------------- */

/* Initialize with a data directory. First caller wins; later calls return
 * NAJWA_ALREADY_INITIALIZED. */
int32_t najwa_init(const char* data_dir);

/* 1 if an identity record exists, 0 if not, negative on error. */
int32_t najwa_identity_exists(void);

/* Create a new identity protected by password (S02). A password that fails
 * the S02 §11.1 length or strength rule returns NAJWA_WEAK_PASSPHRASE. */
int32_t najwa_create_identity(const char* password);

/* Unlock (rate-limited, S02 §10). Starts the transport bootstrap in the
 * background; send/poll return NAJWA_TRANSPORT_ERROR until it completes. */
int32_t najwa_unlock(const char* password);

/* §4.1 (normative): reject new key-using entry, drain in-flight operations
 * (deadline ≥ 2 s), quiesce callbacks, then zeroize key material. */
int32_t najwa_lock(void);

/* Refuse new operations and drain in-flight ones within deadline_ms.
 * Returns NAJWA_SUCCESS when drained, NAJWA_INTERNAL_ERROR on deadline expiry. */
int32_t najwa_cancel_operations(int32_t deadline_ms);

/* ---------------------------------------------------------------------------
 * §4.2 Contacts & Messages (4)
 * --------------------------------------------------------------------------- */

/* JSON array; caller MUST free with najwa_free_string. */
char* najwa_list_contacts(void);

/* JSON array for the (decimal) contact id; caller MUST free. */
char* najwa_list_messages(const char* contact_id);

/* Accepts a text message for the contact. 0 = accepted (status callback
 * emits the persisted status). */
int32_t najwa_send_message(const char* contact_id, const char* content);

/* Poll all mailboxes; delivered messages arrive via the received callback. */
int32_t najwa_poll_messages(void);

/* ---------------------------------------------------------------------------
 * §4.3 Battery State (1)
 * --------------------------------------------------------------------------- */

/* level 0-100 (otherwise NAJWA_NULL_POINTER); any non-zero is_charging counts
 * as 1. The value is stored; no feature reads it. */
int32_t najwa_update_battery(int32_t level, int32_t is_charging);

/* ---------------------------------------------------------------------------
 * §4.4 Utility (2)
 * --------------------------------------------------------------------------- */

/* Zeroize-before-free (§5.6.2). No-op on NULL. */
void najwa_free_string(char* ptr);

/* Static string — MUST NOT be passed to najwa_free_string. */
const char* najwa_version(void);

/* Error codes (§2) — see crates/najwa-ffi/src/error.rs for the table. */
#define NAJWA_SUCCESS 0
#define NAJWA_NULL_POINTER (-1)
#define NAJWA_INVALID_UTF8 (-2)
#define NAJWA_NOT_INITIALIZED (-3)
#define NAJWA_ALREADY_INITIALIZED (-4)
#define NAJWA_INTERNAL_ERROR (-5)
#define NAJWA_PANIC (-99)
#define NAJWA_CONTACT_NOT_FOUND 1
#define NAJWA_CONTACT_BLOCKED 2
#define NAJWA_NO_MAILBOX_CAPABILITY 3
#define NAJWA_NO_SIGNED_PREKEY 4
#define NAJWA_PSEUDONYM_MISMATCH 5
#define NAJWA_UNKNOWN_PSEUDONYM 6
#define NAJWA_DUPLICATE_MESSAGE 7
#define NAJWA_NO_MATCHING_SESSION 8
#define NAJWA_TIMESTAMP_OUT_OF_RANGE 9
#define NAJWA_RATE_LIMIT_EXCEEDED 10
#define NAJWA_RATCHET_ERROR 11
#define NAJWA_MESSAGE_ERROR 12
#define NAJWA_X3DH_ERROR 13
#define NAJWA_MAILBOX_ERROR 14
#define NAJWA_STORAGE_ERROR 15
#define NAJWA_SERIALIZATION_ERROR 16
#define NAJWA_TRANSPORT_ERROR 17
#define NAJWA_IDENTITY_ERROR 18
#define NAJWA_CRYPTO_ERROR 19
#define NAJWA_FILE_TRANSFER_ERROR 20
#define NAJWA_SANITIZE_ERROR 21
#define NAJWA_GROUP_ERROR 22
#define NAJWA_WEAK_PASSPHRASE 23

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* NAJWA_CORE_H */
