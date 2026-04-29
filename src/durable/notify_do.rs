use serde::{Deserialize, Serialize};
use worker::{
    durable_object, DurableObject, Env, Method, Request, Response, Result, State, WebSocket,
    WebSocketIncomingMessage, WebSocketPair,
};

use crate::{
    auth, db,
    notifications::{
        self, ConnectionAttachment, PublishSelector, ANONYMOUS_KIND_TAG, INITIAL_RESPONSE,
        USER_KIND_TAG,
    },
};

#[durable_object]
pub struct NotifyDo {
    state: State,
    env: Env,
}

#[derive(Debug, Default, Deserialize)]
struct HubQuery {
    access_token: Option<String>,
    token: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct FanoutStats {
    matched: usize,
    sent: usize,
    pruned: usize,
}

#[derive(Deserialize)]
struct DoFanoutRequest {
    selector: PublishSelector,
    message: String,
}

impl DurableObject for NotifyDo {
    fn new(state: State, env: Env) -> Self {
        Self { state, env }
    }

    async fn fetch(&self, mut req: Request) -> Result<Response> {
        console_error_panic_hook::set_once();
        let _ = console_log::init_with_level(log::Level::Debug);

        match (req.method(), req.path().as_str()) {
            (Method::Get, "/notifications/hub") | (Method::Get, "/hub") => {
                self.handle_user_hub(req).await
            }
            (Method::Get, "/notifications/anonymous-hub") | (Method::Get, "/anonymous-hub") => {
                self.handle_anonymous_hub(req).await
            }
            (Method::Post, "/fanout") => self.handle_fanout(&mut req).await,
            _ => Response::error("Not found", 404),
        }
    }

    async fn websocket_message(
        &self,
        ws: WebSocket,
        message: WebSocketIncomingMessage,
    ) -> Result<()> {
        let Some(mut attachment) = self.deserialize_attachment(&ws) else {
            self.close_socket(&ws, 1008, "missing connection attachment");
            return Ok(());
        };

        match message {
            WebSocketIncomingMessage::String(text) => {
                if notifications::is_initial_message(&text) {
                    attachment.protocol_initialized = true;
                    ws.serialize_attachment(&attachment)?;
                    ws.send_with_bytes(INITIAL_RESPONSE)?;
                }
            }
            WebSocketIncomingMessage::Binary(bytes) => {
                ws.send_with_bytes(bytes)?;
            }
        }

        Ok(())
    }

    async fn websocket_close(
        &self,
        _ws: WebSocket,
        code: usize,
        reason: String,
        was_clean: bool,
    ) -> Result<()> {
        log::info!("NotifyDo websocket closed: code={code}, clean={was_clean}, reason={reason}");
        Ok(())
    }

    async fn websocket_error(&self, ws: WebSocket, error: worker::Error) -> Result<()> {
        log::error!("NotifyDo websocket error: {error}");
        self.close_socket(&ws, 1011, "websocket error");
        Ok(())
    }
}

impl NotifyDo {
    // ── Hub handlers ────────────────────────────────────────────────

    async fn handle_user_hub(&self, req: Request) -> Result<Response> {
        if !self.is_websocket_upgrade(&req) {
            return Response::error("Expected WebSocket", 426);
        }

        let query = req.query::<HubQuery>().unwrap_or_default();
        let token = match query
            .access_token
            .or(auth::bearer_token_from_headers(req.headers())
                .ok()
                .flatten())
        {
            Some(token) => token,
            None => return Response::error("Missing access token", 401),
        };

        let claims = match auth::decode_access_token(&self.env, &token).await {
            Ok(claims) => claims,
            Err(error) => {
                log::warn!("NotifyDo rejected websocket token: {error}");
                return Response::error("Invalid token", 401);
            }
        };

        let pair = WebSocketPair::new()?;
        let attachment =
            ConnectionAttachment::user(claims.sub.clone(), Some(claims.device), db::now_string());
        pair.server.serialize_attachment(&attachment)?;

        let user_tag = notifications::user_tag(&claims.sub);
        let tags = [user_tag.as_str(), USER_KIND_TAG];
        self.state.accept_websocket_with_tags(&pair.server, &tags);

        Response::from_websocket(pair.client)
    }

    async fn handle_anonymous_hub(&self, req: Request) -> Result<Response> {
        if !self.is_websocket_upgrade(&req) {
            return Response::error("Expected WebSocket", 426);
        }

        let query = req.query::<HubQuery>().unwrap_or_default();
        let Some(token) = query.token.filter(|value| !value.is_empty()) else {
            return Response::error("Missing token", 400);
        };

        if self
            .env
            .var("ANONYMOUS_HUB_ENABLED")
            .ok()
            .is_none_or(|value| value.to_string() != "true")
        {
            return Response::error("Anonymous hub is not enabled", 403);
        }

        let pair = WebSocketPair::new()?;
        let attachment = ConnectionAttachment::anonymous(token.clone(), db::now_string());
        pair.server.serialize_attachment(&attachment)?;

        let anonymous_tag = notifications::anonymous_tag(&token);
        let tags = [anonymous_tag.as_str(), ANONYMOUS_KIND_TAG];
        self.state.accept_websocket_with_tags(&pair.server, &tags);

        Response::from_websocket(pair.client)
    }

    // ── Fan-out (pre-built bytes from Worker) ───────────────────────

    async fn handle_fanout(&self, req: &mut Request) -> Result<Response> {
        use base64::{engine::general_purpose::STANDARD, Engine};

        let body: DoFanoutRequest = req.json().await.map_err(|e| {
            log::warn!("Invalid fanout payload: {e}");
            worker::Error::RustError("Invalid fanout payload".into())
        })?;

        let ws_bytes = STANDARD.decode(&body.message).map_err(|e| {
            log::warn!("Invalid base64 in fanout message: {e}");
            worker::Error::RustError("Invalid base64".into())
        })?;

        let stats = self.ws_fanout(&body.selector, &ws_bytes);
        Response::from_json(&stats)
    }

    // ── WS fan-out ──────────────────────────────────────────────────

    fn ws_fanout(&self, selector: &PublishSelector, message: &[u8]) -> FanoutStats {
        let mut stats = FanoutStats {
            matched: 0,
            sent: 0,
            pruned: 0,
        };

        for ws in self.state.get_websockets_with_tag(&selector.tag()) {
            stats.matched += 1;

            let Some(attachment) = self.deserialize_attachment(&ws) else {
                stats.pruned += 1;
                self.close_socket(&ws, 1008, "invalid connection attachment");
                continue;
            };

            if !attachment.protocol_initialized {
                log::warn!("NotifyDo websocket protocol not initialized; skipping");
                continue;
            }

            if !attachment.matches_selector(selector) {
                log::warn!("NotifyDo selector mismatch despite tag match; skipping");
                continue;
            }

            if let Err(error) = ws.send_with_bytes(message) {
                stats.pruned += 1;
                log::warn!("NotifyDo failed to fan out websocket message: {error}");
                self.close_socket(&ws, 1011, "send failed");
                continue;
            }

            stats.sent += 1;
        }

        stats
    }

    // ── Utility ─────────────────────────────────────────────────────

    fn deserialize_attachment(&self, ws: &WebSocket) -> Option<ConnectionAttachment> {
        match ws.deserialize_attachment::<ConnectionAttachment>() {
            Ok(attachment) => attachment,
            Err(error) => {
                log::warn!("NotifyDo failed to deserialize websocket attachment: {error}");
                None
            }
        }
    }

    fn close_socket(&self, ws: &WebSocket, code: u16, reason: &str) {
        if let Err(error) = ws.close(Some(code), Some(reason)) {
            log::warn!("NotifyDo failed to close websocket: {error}");
        }
    }

    fn is_websocket_upgrade(&self, req: &Request) -> bool {
        req.headers()
            .get("Upgrade")
            .ok()
            .flatten()
            .map(|value| value.eq_ignore_ascii_case("websocket"))
            .unwrap_or(false)
    }
}
