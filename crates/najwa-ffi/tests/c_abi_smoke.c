/* Compile and link this against the cdylib, not the Rust rlib. */
#include "najwa.h"
#include <assert.h>
#include <stddef.h>
#include <string.h>
int main(void) {
    assert(strncmp(najwa_version(), "najwa-ffi ", 10) == 0);
    assert(najwa_init(NULL) == NAJWA_NULL_POINTER);
    assert(najwa_identity_exists() == NAJWA_NOT_INITIALIZED);
    assert(najwa_create_identity(NULL) == NAJWA_NULL_POINTER);
    assert(najwa_unlock(NULL) == NAJWA_NULL_POINTER);
    assert(najwa_send_message(NULL, NULL) == NAJWA_NULL_POINTER);
    assert(najwa_poll_messages() != NAJWA_SUCCESS);
    assert(najwa_update_battery(-1, 0) == NAJWA_NULL_POINTER);
    char *contacts = najwa_list_contacts();
    assert(contacts && strcmp(contacts, "[]") == 0);
    najwa_free_string(contacts);
    char *messages = najwa_list_messages("0");
    assert(messages && strcmp(messages, "[]") == 0);
    najwa_free_string(messages);
    najwa_set_message_received_callback(NULL);
    najwa_set_message_status_callback(NULL);
    najwa_set_connection_status_callback(NULL);
    najwa_set_error_callback(NULL);
    najwa_set_feature_toggle_callback(NULL);
    najwa_set_event_callback(NULL);
    najwa_clear_all_callbacks();
    assert(najwa_cancel_operations(0) == NAJWA_SUCCESS);
    assert(najwa_lock() == NAJWA_SUCCESS);
    return 0;
}
