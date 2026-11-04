//! Bounded browser operations share the production messaging owner.
use najwa_ffi::desktop::DesktopClient;
use serde::Deserialize;
use serde_json::Value;
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    Status,
    Contacts,
    Messages {
        contact: String,
        #[serde(default)] before: Option<(i64, String)>,
        #[serde(default)] query: Option<String>,
    },
    Displayed {
        contact: String,
        ids: Vec<String>,
    },
    Send {
        contact: String,
        text: String,
        #[serde(default)]
        reply_to: Option<String>,
    },
    ManageContact { contact: String, action: String, #[serde(default)] name: String },
    InvitationDetails { invitation: String },
    DownloadFile { contact: String, message: String },
    SetTimer {
        contact: String,
        seconds: u32,
    },
    AddMailbox {
        onion: String,
    },
    SelectMailbox {
        onion: String,
    },
    ForgetMailbox {
        onion: String,
    },
    SetDeliveryMode {
        mode: String,
    },
    RetryMailbox {
        onion: String,
    },
    Invitation {
        name: String,
    },
    AcceptInvitation {
        invitation: String,
        name: String,
        #[serde(default)]
        confirmed: bool,
    },
    Verify {
        contact: String,
        safety: String,
        verified: bool,
    },
    Sync,
    Reconnect,
}

pub fn execute(
    client: &DesktopClient,
    operation: Operation,
) -> Result<Value, najwa_ffi::desktop::DesktopError> {
    if !operation.bounded() {
        return Err(najwa_ffi::desktop::DesktopError {
            code: "invalid_request",
        });
    }
    match operation {
        Operation::Status => Ok(serde_json::to_value(client.status()).unwrap()),
        Operation::Contacts => client.contacts().map(|v| serde_json::to_value(v).unwrap()),
        Operation::Messages { contact, before, query } => {
            let rows = if before.is_none() && query.is_none() { client.messages(&contact) }
                else { client.message_history(&contact, before, query.as_deref()) };
            rows.map(|v| serde_json::to_value(v).unwrap())
        }
        Operation::Displayed { contact, ids } => {
            client.displayed(&contact, &ids).map(|_| Value::Null)
        }
        Operation::Send {
            contact,
            text,
            reply_to,
        } => client
            .send_reply(&contact, &text, reply_to.as_deref())
            .map(Value::String),
        Operation::ManageContact {
            contact,
            action,
            name,
        } => client
            .manage_contact(&contact, &action, &name)
            .map(|_| Value::Null),
        Operation::InvitationDetails { invitation } => client.invitation_details(&invitation),
        Operation::DownloadFile { contact, message } => client.download_file(&contact, &message),
        Operation::SetTimer { contact, seconds } => {
            client.set_timer(&contact, seconds).map(|_| Value::Null)
        }
        Operation::AddMailbox { onion } => client.add_mailbox(&onion).map(|_| Value::Null),
        Operation::SelectMailbox { onion } => client.select_mailbox(&onion).map(|_| Value::Null),
        Operation::ForgetMailbox { onion } => client.forget_mailbox(&onion).map(|_| Value::Null),
        Operation::SetDeliveryMode { mode } => client.set_delivery_mode(&mode).map(|_| Value::Null),
        Operation::RetryMailbox { onion } => client.retry_mailbox(&onion).map(|_| Value::Null),
        Operation::Invitation { name } => client.invitation(&name).map(Value::String),
        Operation::AcceptInvitation { invitation, name, confirmed } => client
            .accept_invitation(&invitation, &name, confirmed)
            .map(Value::String),
        Operation::Verify {
            contact,
            safety,
            verified,
        } => client
            .verify(&contact, &safety, verified)
            .map(|_| Value::Null),
        Operation::Sync => client.sync().map(|_| Value::Null),
        Operation::Reconnect => {
            client.reconnect();
            Ok(Value::Null)
        }
    }
}
impl Operation {
    fn bounded(&self) -> bool {
        let id = |v: &str| !v.is_empty() && v.len() <= 19 && v.bytes().all(|b| b.is_ascii_digit());
        match self {
            Self::Messages { contact, before, query } => id(contact)
                && before.as_ref().is_none_or(|(timestamp, row)| *timestamp >= 0 && id(row))
                && query.as_ref().is_none_or(|q| !q.trim().is_empty() && q.len() <= 512),
            Self::Displayed { contact, ids } => {
                id(contact) && ids.len() <= 200 && ids.iter().all(|v| id(v))
            }
            Self::Send {
                contact,
                text,
                reply_to,
            } => {
                id(contact)
                    && !text.trim().is_empty()
                    && text.len() <= 16_000
                    && reply_to
                        .as_ref()
                        .is_none_or(|v| v.len() == 32 && v.bytes().all(|b| b.is_ascii_hexdigit()))
            }
            Self::ManageContact {
                contact,
                action,
                name,
            } => {
                id(contact)
                    && matches!(action.as_str(), "block" | "unblock" | "delete" | "rename")
                    && name.len() <= 128
                    && (action != "rename" || !name.trim().is_empty())
            }
            Self::InvitationDetails { invitation } => invitation.len() <= 4096,
            Self::DownloadFile { contact, message } => id(contact) && id(message),
            Self::SetTimer { contact, seconds } => id(contact) && (*seconds == 0 || *seconds >= 30),
            Self::AddMailbox { onion }
            | Self::SelectMailbox { onion }
            | Self::ForgetMailbox { onion }
            | Self::RetryMailbox { onion } => onion.len() <= 62,
            Self::SetDeliveryMode { mode } => matches!(mode.as_str(), "responsive" | "privacy"),
            Self::Invitation { name } => !name.trim().is_empty() && name.len() <= 128,
            Self::AcceptInvitation { invitation, name, .. } => {
                invitation.len() <= 4096 && !name.trim().is_empty() && name.len() <= 128
            }
            Self::Verify {
                contact, safety, ..
            } => id(contact) && safety.len() == 39,
            _ => true,
        }
    }
}

#[cfg(test)]
mod history_boundary_tests {
    use super::*;

    #[test]
    fn existing_message_requests_remain_valid_and_history_inputs_are_bounded() {
        let old: Operation = serde_json::from_value(serde_json::json!({"kind":"messages","contact":"1"})).unwrap();
        assert!(old.bounded());
        let page: Operation = serde_json::from_value(serde_json::json!({"kind":"messages","contact":"1","before":[100,"9007199254740993"],"query":"literal %_"})).unwrap();
        assert!(page.bounded());
        for value in [
            serde_json::json!({"kind":"messages","contact":"1","before":[-1,"2"]}),
            serde_json::json!({"kind":"messages","contact":"1","before":[100,"bad"]}),
            serde_json::json!({"kind":"messages","contact":"1","query":" "}),
            serde_json::json!({"kind":"messages","contact":"1","query":"x".repeat(513)}),
        ] {
            let operation: Operation = serde_json::from_value(value).unwrap();
            assert_eq!(execute(&DesktopClient, operation).unwrap_err().code, "invalid_request");
        }
        assert!(serde_json::from_value::<Operation>(serde_json::json!({"kind":"messages","contact":"1","before":[100,"2","extra"]})).is_err());
        assert!(serde_json::from_value::<Operation>(serde_json::json!({"kind":"messages","contact":"1","path":"private.db"})).is_err());
    }
}
