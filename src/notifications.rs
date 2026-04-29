#![allow(dead_code)]

use chrono::{DateTime, NaiveDateTime, Utc};
use log::warn;
use rmpv::Value;
use serde::{Deserialize, Serialize};
use worker::{wasm_bindgen::JsValue, Env, Method, Request, RequestInit};

use crate::push;

const INTERNAL_FANOUT_URL: &str = "https://notify.internal/fanout";
pub const RECORD_SEPARATOR: u8 = 0x1e;
pub const INITIAL_RESPONSE: [u8; 3] = [b'{', b'}', RECORD_SEPARATOR];
pub const USER_KIND_TAG: &str = "k:user";
pub const ANONYMOUS_KIND_TAG: &str = "k:anon";

// ── UpdateType ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(i32)]
pub enum UpdateType {
    SyncCipherUpdate = 0,
    SyncCipherCreate = 1,
    SyncLoginDelete = 2,
    SyncFolderDelete = 3,
    SyncCiphers = 4,
    SyncVault = 5,
    SyncOrgKeys = 6,
    SyncFolderCreate = 7,
    SyncFolderUpdate = 8,
    SyncSettings = 10,
    LogOut = 11,
    SyncSendCreate = 12,
    SyncSendUpdate = 13,
    SyncSendDelete = 14,
    AuthRequest = 15,
    AuthRequestResponse = 16,
    None = 100,
}

// ── Connection model ────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionKind {
    User,
    Anonymous,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionAttachment {
    pub kind: ConnectionKind,
    pub user_id: Option<String>,
    pub token: Option<String>,
    pub device_id: Option<String>,
    pub protocol_initialized: bool,
    pub connected_at: String,
}

impl ConnectionAttachment {
    pub fn user(user_id: String, device_id: Option<String>, connected_at: String) -> Self {
        Self {
            kind: ConnectionKind::User,
            user_id: Some(user_id),
            token: None,
            device_id,
            protocol_initialized: false,
            connected_at,
        }
    }

    pub fn anonymous(token: String, connected_at: String) -> Self {
        Self {
            kind: ConnectionKind::Anonymous,
            user_id: None,
            token: Some(token),
            device_id: None,
            protocol_initialized: false,
            connected_at,
        }
    }

    pub fn matches_selector(&self, selector: &PublishSelector) -> bool {
        match selector {
            PublishSelector::ByUser { user_id } => {
                self.kind == ConnectionKind::User
                    && self.user_id.as_deref() == Some(user_id.as_str())
            }
            PublishSelector::ByAnonymousToken { token } => {
                self.kind == ConnectionKind::Anonymous
                    && self.token.as_deref() == Some(token.as_str())
            }
        }
    }
}

// ── Selector ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PublishSelector {
    ByUser { user_id: String },
    ByAnonymousToken { token: String },
}

impl PublishSelector {
    pub fn user(user_id: impl Into<String>) -> Self {
        Self::ByUser {
            user_id: user_id.into(),
        }
    }

    pub fn anonymous(token: impl Into<String>) -> Self {
        Self::ByAnonymousToken {
            token: token.into(),
        }
    }

    pub fn tag(&self) -> String {
        match self {
            PublishSelector::ByUser { user_id } => user_tag(user_id),
            PublishSelector::ByAnonymousToken { token } => anonymous_tag(token),
        }
    }
}

// ── Tag helpers ─────────────────────────────────────────────────────

pub fn user_tag(user_id: &str) -> String {
    format!("u:{user_id}")
}

pub fn anonymous_tag(token: &str) -> String {
    format!("a:{token}")
}

// ── Protocol helpers ────────────────────────────────────────────────

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct InitialMessage {
    protocol: String,
    version: i32,
}

pub fn is_initial_message(message: &str) -> bool {
    let message = message
        .strip_suffix(RECORD_SEPARATOR as char)
        .unwrap_or(message);

    serde_json::from_str::<InitialMessage>(message).ok()
        == Some(InitialMessage {
            protocol: "messagepack".to_string(),
            version: 1,
        })
}

// ── MessagePack helpers (used by NotifyDo) ──────────────────────────

pub fn create_ping() -> Vec<u8> {
    serialize(&Value::Array(vec![6.into()]))
}

// ── DO fan-out protocol ─────────────────────────────────────────────

#[derive(Serialize)]
struct DoFanoutRequest<'a> {
    selector: &'a PublishSelector,
    message: String,
}

async fn send_ws_to_do(env: &Env, selector: &PublishSelector, ws_bytes: &[u8]) {
    use base64::{engine::general_purpose::STANDARD, Engine};

    let selector_tag = selector.tag();
    let namespace = match env.durable_object("NOTIFY_DO") {
        Ok(namespace) => namespace,
        Err(error) => {
            warn!("Skipping ws notification for {selector_tag}: NOTIFY_DO lookup failed: {error}");
            return;
        }
    };
    let stub = match namespace.get_by_name("global") {
        Ok(stub) => stub,
        Err(error) => {
            warn!("Skipping ws notification for {selector_tag}: DO stub lookup failed: {error}");
            return;
        }
    };

    let body = match serde_json::to_string(&DoFanoutRequest {
        selector,
        message: STANDARD.encode(ws_bytes),
    }) {
        Ok(body) => body,
        Err(error) => {
            warn!("Skipping ws notification for {selector_tag}: payload encode failed: {error}");
            return;
        }
    };

    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_body(Some(JsValue::from_str(&body)));

    let mut request = match Request::new_with_init(INTERNAL_FANOUT_URL, &init) {
        Ok(request) => request,
        Err(error) => {
            warn!("Skipping ws notification for {selector_tag}: request creation failed: {error}");
            return;
        }
    };
    let headers = match request.headers_mut() {
        Ok(headers) => headers,
        Err(error) => {
            warn!("Skipping ws notification for {selector_tag}: headers init failed: {error}");
            return;
        }
    };
    if let Err(error) = headers.set("Content-Type", "application/json") {
        warn!("Skipping ws notification for {selector_tag}: header set failed: {error}");
        return;
    }

    let mut response = match stub.fetch_with_request(request).await {
        Ok(response) => response,
        Err(error) => {
            warn!("Skipping ws notification for {selector_tag}: DO fanout failed: {error}");
            return;
        }
    };
    if !(200..300).contains(&response.status_code()) {
        let status = response.status_code();
        let body = response.text().await.unwrap_or_else(|_| String::new());
        warn!("Skipping ws notification for {selector_tag}: NotifyDo fanout failed with status {status}: {body}");
    }
}

// ── Publish helpers (called by handlers) ────────────────────────────

pub async fn publish_user_update(
    env: &Env,
    user_id: &str,
    update_type: UpdateType,
    date: &str,
    context_id: Option<&str>,
) {
    let ws_bytes = create_update(
        vec![
            ("UserId".into(), user_id.into()),
            ("Date".into(), serialize_date(parse_timestamp(date))),
        ],
        update_type as i32,
        context_id,
    );
    let selector = PublishSelector::user(user_id);
    send_ws_to_do(env, &selector, &ws_bytes).await;
    push::push_user_update(env, user_id, update_type as i32, date, context_id).await;
}

pub async fn publish_user_logout(env: &Env, user_id: &str, date: &str, context_id: Option<&str>) {
    publish_user_update(env, user_id, UpdateType::LogOut, date, context_id).await
}

pub async fn publish_folder_update(
    env: &Env,
    user_id: &str,
    update_type: UpdateType,
    folder_id: &str,
    revision_date: &str,
    context_id: Option<&str>,
) {
    let ws_bytes = create_update(
        vec![
            ("Id".into(), folder_id.into()),
            ("UserId".into(), user_id.into()),
            (
                "RevisionDate".into(),
                serialize_date(parse_timestamp(revision_date)),
            ),
        ],
        update_type as i32,
        context_id,
    );
    let selector = PublishSelector::user(user_id);
    send_ws_to_do(env, &selector, &ws_bytes).await;
    push::push_folder_update(
        env,
        user_id,
        update_type as i32,
        folder_id,
        revision_date,
        context_id,
    )
    .await;
}

pub async fn publish_cipher_update(
    env: &Env,
    user_id: &str,
    update_type: UpdateType,
    cipher_id: &str,
    revision_date: &str,
    context_id: Option<&str>,
) {
    let ws_bytes = create_update(
        vec![
            ("Id".into(), cipher_id.into()),
            // Org feature is not supported,
            // so we simply set all related parameters to null.
            ("UserId".into(), user_id.into()),
            ("OrganizationId".into(), Value::Nil),
            ("CollectionIds".into(), Value::Nil),
            (
                "RevisionDate".into(),
                serialize_date(parse_timestamp(revision_date)),
            ),
        ],
        update_type as i32,
        context_id,
    );
    let selector = PublishSelector::user(user_id);
    send_ws_to_do(env, &selector, &ws_bytes).await;
    push::push_cipher_update(
        env,
        user_id,
        update_type as i32,
        cipher_id,
        revision_date,
        context_id,
    )
    .await;
}

pub async fn publish_send_update(
    env: &Env,
    user_id: &str,
    update_type: UpdateType,
    send_id: &str,
    revision_date: &str,
    context_id: Option<&str>,
) {
    let ws_bytes = create_update(
        vec![
            ("Id".into(), send_id.into()),
            ("UserId".into(), user_id.into()),
            (
                "RevisionDate".into(),
                serialize_date(parse_timestamp(revision_date)),
            ),
        ],
        update_type as i32,
        context_id,
    );
    let selector = PublishSelector::user(user_id);
    send_ws_to_do(env, &selector, &ws_bytes).await;
    push::push_send_update(
        env,
        user_id,
        update_type as i32,
        send_id,
        revision_date,
        context_id,
    )
    .await;
}

pub async fn publish_auth_request(
    env: &Env,
    user_id: &str,
    auth_request_id: &str,
    context_id: Option<&str>,
) {
    let ws_bytes = create_update(
        vec![
            ("Id".into(), auth_request_id.into()),
            ("UserId".into(), user_id.into()),
        ],
        UpdateType::AuthRequest as i32,
        context_id,
    );
    let selector = PublishSelector::user(user_id);
    send_ws_to_do(env, &selector, &ws_bytes).await;
    push::push_auth_request(env, user_id, auth_request_id, context_id).await;
}

pub async fn publish_auth_response(
    env: &Env,
    user_id: &str,
    auth_request_id: &str,
    context_id: Option<&str>,
) {
    let ws_bytes = create_update(
        vec![
            ("Id".into(), auth_request_id.into()),
            ("UserId".into(), user_id.into()),
        ],
        UpdateType::AuthRequestResponse as i32,
        context_id,
    );
    let selector = PublishSelector::user(user_id);
    send_ws_to_do(env, &selector, &ws_bytes).await;
    push::push_auth_response(env, user_id, auth_request_id, context_id).await;
}

pub async fn publish_anonymous_update(
    env: &Env,
    token: &str,
    user_id: &str,
    auth_request_id: &str,
) {
    let ws_bytes = create_anonymous_update(
        vec![
            ("Id".into(), auth_request_id.into()),
            ("UserId".into(), user_id.into()),
        ],
        UpdateType::AuthRequestResponse as i32,
        user_id,
    );
    let selector = PublishSelector::anonymous(token);
    send_ws_to_do(env, &selector, &ws_bytes).await;
}

// ── MessagePack internals ───────────────────────────────────────────

fn create_update(
    payload: Vec<(Value, Value)>,
    update_type: i32,
    context_id: Option<&str>,
) -> Vec<u8> {
    use rmpv::Value as V;

    let value = V::Array(vec![
        1.into(),
        V::Map(vec![]),
        V::Nil,
        "ReceiveMessage".into(),
        V::Array(vec![V::Map(vec![
            ("ContextId".into(), convert_option(context_id)),
            ("Type".into(), update_type.into()),
            ("Payload".into(), payload.into()),
        ])]),
    ]);

    serialize(&value)
}

fn create_anonymous_update(
    payload: Vec<(Value, Value)>,
    update_type: i32,
    user_id: &str,
) -> Vec<u8> {
    use rmpv::Value as V;

    let value = V::Array(vec![
        1.into(),
        V::Map(vec![]),
        V::Nil,
        "AuthRequestResponseRecieved".into(),
        V::Array(vec![V::Map(vec![
            ("Type".into(), update_type.into()),
            ("Payload".into(), payload.into()),
            ("UserId".into(), user_id.into()),
        ])]),
    ]);

    serialize(&value)
}

fn serialize(value: &Value) -> Vec<u8> {
    use rmpv::encode::write_value;

    let mut buffer = Vec::new();
    write_value(&mut buffer, value).expect("msgpack encoding should not fail");

    let mut size = buffer.len();
    let mut prefix = Vec::new();

    loop {
        let mut size_part = size & 0x7f;
        size >>= 7;

        if size > 0 {
            size_part |= 0x80;
        }

        prefix.push(size_part as u8);

        if size == 0 {
            break;
        }
    }

    prefix.append(&mut buffer);
    prefix
}

fn serialize_date(date: NaiveDateTime) -> Value {
    let seconds = date.and_utc().timestamp();
    let nanos = i64::from(date.and_utc().timestamp_subsec_nanos());
    let timestamp = (nanos << 34) | seconds;

    Value::Ext(-1, timestamp.to_be_bytes().to_vec())
}

fn convert_option<T: Into<Value>>(option: Option<T>) -> Value {
    match option {
        Some(value) => value.into(),
        None => Value::Nil,
    }
}

fn parse_timestamp(date: &str) -> NaiveDateTime {
    if date.is_empty() {
        return Utc::now().naive_utc();
    }

    DateTime::parse_from_rfc3339(date)
        .map(|value| value.naive_utc())
        .unwrap_or_else(|error| {
            warn!("Failed to parse RFC3339 timestamp '{date}': {error}");
            Utc::now().naive_utc()
        })
}
