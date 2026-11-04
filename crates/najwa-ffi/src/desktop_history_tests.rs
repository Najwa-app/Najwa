use super::*;
use najwa_storage::types::{ContentType as StoredType, MessageDirection, MessageStatus, NewContact, NewMessage};

fn fixture(test: impl FnOnce(&SqliteStorage, i64)) {
    let _serial = crate::callback::tests::test_lock().lock().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let db = state::open_storage(dir.path(), &crate::state::test_key(14)).unwrap();
    let cid = db.create_contact(&NewContact {
        pseudonym: [1; 32], their_ik_pub: Ed25519KeyPair::from_seed(&[8; 32]).public().to_bytes(),
        their_device_pub: [2; 32], our_pseudonym: [3; 32], display_name: Some("History peer".into()),
    }).unwrap();
    let mut app = state::AppState::new(dir.path().into()).unwrap();
    app.identity = Some(Identity {keypair: Ed25519KeyPair::from_seed(&[7; 32]), created_at: 1, version: 2});
    app.storage = Some(db.clone());app.db_key = Some(crate::state::test_key(14));
    *state_cell().write().unwrap() = Some(app);
    assert!(state::allow_operations());
    test(&db, cid);
    DesktopClient.lock().unwrap();
    assert_eq!(DesktopClient.message_history(&cid.to_string(), Some((1,"1".into())),None).unwrap_err().code,"locked");
    drop(state_cell().write().unwrap().take());
}

fn message(cid: i64, n: u32, text: &str) -> NewMessage {
    let mut id=[0;16];id[..4].copy_from_slice(&n.to_be_bytes());
    NewMessage {
        contact_id:cid,msg_id:id,direction:MessageDirection::Received,content_type:StoredType::Text,
        flags:0,content:text.as_bytes().to_vec(),file_path:None,timestamp:100,
        received_at:Some(100),status:MessageStatus::Delivered,reply_to_msg_id:None,
        disappear_timer:None,encrypted_blob:None,group_id:None,sender_display_name:None,
        origin_timestamp_ms:None,retry_wire_blob:None,
    }
}

#[test]
fn an_undecodable_file_record_lists_as_an_unavailable_file() {
    fixture(|db,cid| {
        db.save_message(&message(cid,1,"still visible")).unwrap();
        let mut bad=message(cid,2,"");bad.content_type=StoredType::FileMetadata;
        bad.content=vec![1;70]; // filename_len 257 fails S11 §2.2.1
        db.save_message(&bad).unwrap();
        let contact=cid.to_string();
        for list in [DesktopClient.messages(&contact).unwrap(),DesktopClient.message_history(&contact,None,None).unwrap()] {
            assert_eq!(list.len(),2);
            let file=list.iter().find_map(|m|m.attachment.as_ref()).unwrap();
            assert!(!file.supported && !file.complete);
        }
    });
}

#[test]
fn history_pages_use_stable_64_bit_cursors_and_never_mark_messages_read() {
    fixture(|db,cid| {
        for n in 1..=430 { db.save_message(&message(cid,n,&format!("History {n}"))).unwrap(); }
        let contact=cid.to_string();
        let first=DesktopClient.messages(&contact).unwrap();assert_eq!(first.len(),200);
        assert_eq!(first[0].text,"History 430");
        let boundary=first.last().unwrap();
        let second=DesktopClient.message_history(&contact,Some((boundary.timestamp as i64,boundary.id.clone())),None).unwrap();
        assert_eq!(second.len(),200);assert_eq!(second[0].text,"History 230");
        let boundary=second.last().unwrap();
        let last=DesktopClient.message_history(&contact,Some((boundary.timestamp as i64,boundary.id.clone())),None).unwrap();
        assert_eq!(last.len(),30);assert_eq!(last.last().unwrap().text,"History 1");
        assert_eq!(db.count_unread_messages(cid).unwrap(),430);
        assert!(DesktopClient.message_history(&contact,Some((-1,"1".into())),None).is_err());
        assert!(DesktopClient.message_history(&contact,Some((100,"9223372036854775808".into())),None).is_err());
        assert_eq!(DesktopClient.message_history("99999",None,Some("history")).unwrap_err().code,"contact_missing");
    });
}

#[test]
fn search_is_bounded_contact_scoped_and_excludes_timed_expired_and_internal_rows() {
    fixture(|db,cid| {
        for n in 1..=220 {db.save_message(&message(cid,n,"Needle %_ café")).unwrap();}
        let mut reply=message(cid,221,"");reply.content_type=StoredType::TextReply;
        reply.content=najwa_protocol::message::TextReplyContent {reply_to_msg_id:[0;16],text:"A needle reply".into()}.to_bytes();
        db.save_message(&reply).unwrap();
        let mut timed=message(cid,222,"needle disappearing");timed.flags=1;timed.disappear_timer=Some(30);
        db.save_message(&timed).unwrap();
        let expired=db.save_message(&message(cid,223,"needle expired")).unwrap();
        db.set_message_disappear_at(expired,(najwa_crypto::time::now_ms()-1) as u64).unwrap();
        let mut chunk=message(cid,224,"needle internal file bytes");chunk.content_type=StoredType::FileChunk;db.save_message(&chunk).unwrap();
        let other=db.create_contact(&NewContact {pseudonym:[4;32],their_ik_pub:[5;32],their_device_pub:[6;32],our_pseudonym:[7;32],display_name:None}).unwrap();
        db.save_message(&message(other,225,"needle other contact")).unwrap();
        let first=DesktopClient.message_history(&cid.to_string(),None,Some("NEEDLE")).unwrap();
        assert_eq!(first.len(),200);assert_eq!(first[0].text,"A needle reply");
        let boundary=first.last().unwrap();
        let last=DesktopClient.message_history(&cid.to_string(),Some((boundary.timestamp as i64,boundary.id.clone())),Some("needle")).unwrap();
        assert_eq!(last.len(),21);
        assert_eq!(DesktopClient.message_history(&cid.to_string(),None,Some("%_ café")).unwrap().len(),200);
        assert!(DesktopClient.message_history(&cid.to_string(),None,Some(" ")).is_err());
        assert!(DesktopClient.message_history(&cid.to_string(),None,Some(&"x".repeat(513))).is_err());
        let contact=DesktopClient.contacts().unwrap().into_iter().find(|c|c.id==cid.to_string()).unwrap();
        assert_eq!(contact.preview.as_deref(),Some("Disappearing message"));
        assert_eq!(contact.unread,222); // 221 durable text/replies + one unexpired timed row.
    });
}

#[test]
fn conversation_preview_uses_the_latest_visible_message_and_truncates_safely() {
    fixture(|db,cid| {
        let mut first=message(cid,1,&"é".repeat(300));first.timestamp=100;db.save_message(&first).unwrap();
        let mut chunk=message(cid,2,"internal bytes");chunk.content_type=StoredType::FileChunk;chunk.timestamp=200;db.save_message(&chunk).unwrap();
        let mut expired=message(cid,3,"expired secret");expired.timestamp=300;
        let id=db.save_message(&expired).unwrap();db.set_message_disappear_at(id,(najwa_crypto::time::now_ms()-1) as u64).unwrap();
        let contact=DesktopClient.contacts().unwrap().pop().unwrap();
        assert_eq!(contact.last_message_at,Some(100));assert_eq!(contact.preview.unwrap(),"é".repeat(160));
        assert_eq!(contact.unread,1);assert_eq!(contact.repair_status,None);
    });
}
