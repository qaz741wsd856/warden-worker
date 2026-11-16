use std::sync::Arc;

use axum::{extract::DefaultBodyLimit, Extension};
use tower_http::cors::{Any, CorsLayer};
use tower_service::Service;
use worker::*;

mod auth;
mod background;
mod client_context;
mod crypto;
mod db;
mod durable;
mod error;
mod handlers;
mod models;
mod notifications;
mod push;
mod router;

/// Base URL extracted from the incoming request, used for config endpoint.
#[derive(Clone)]
pub struct BaseUrl(pub String);

#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: Context) -> Result<web_sys::Response> {
    console_error_panic_hook::set_once();
    let _ = console_log::init_with_level(log::Level::Debug);

    let url = req.url()?;
    let method = req.method();
    let path = url.path().to_string();

    if handlers::streaming::is_streaming_route(&method, &path) {
        return Ok(handlers::streaming::handle(req, &env, &method, &path, &url)
            .await
            .into());
    }

    let http_req: HttpRequest = req.try_into()?;

    let base_url = env
        .var("BASE_URL")
        .ok()
        .map(|v| v.to_string().trim_end_matches('/').to_string())
        .unwrap_or_else(|| {
            let uri = http_req.uri().clone();
            format!(
                "{}://{}",
                uri.scheme_str().unwrap_or("https"),
                uri.authority().map(|a| a.as_str()).unwrap_or("localhost")
            )
        });

    let env = Arc::new(env);

    let cors = CorsLayer::new()
        .allow_methods(Any)
        .allow_headers(Any)
        .allow_origin(Any);

    const BODY_LIMIT: usize = 5 * 1024 * 1024;

    let mut app = router::api_router((*env).clone())
        .layer(Extension(BaseUrl(base_url)))
        .layer(cors)
        .layer(DefaultBodyLimit::max(BODY_LIMIT));

    let resp = app.call(http_req).await?;
    worker::response_to_wasm(resp)
}

/// Scheduled event handler for cron-triggered tasks.
///
/// This handler is triggered by Cloudflare's cron triggers configured in wrangler.toml.
/// It performs automatic cleanup of soft-deleted ciphers that have exceeded the
/// retention period (default: 30 days, configurable via TRASH_AUTO_DELETE_DAYS env var).
#[event(scheduled)]
pub async fn scheduled(_event: ScheduledEvent, env: Env, _ctx: ScheduleContext) {
    console_error_panic_hook::set_once();
    let _ = console_log::init_with_level(log::Level::Debug);

    run_scheduled_purges(&env).await;
}

/// Runs every cron-triggered cleanup task.
///
/// Called from the `scheduled` handler (fallback) and from `HeavyDo` (preferred, since the
/// Durable Object has a much larger CPU budget than a Free plan Worker invocation).
pub(crate) async fn run_scheduled_purges(env: &Env) {
    fn log_purge_result(name: &str, result: Result<u32, worker::Error>) {
        match result {
            Ok(count) => log::info!("Purge {name} completed: {count} record(s) removed"),
            Err(e) => log::error!("Purge {name} failed: {e:?}"),
        }
    }

    log_purge_result(
        "stale pending attachments",
        handlers::purge::purge_stale_pending_attachments(env).await,
    );
    log_purge_result(
        "soft-deleted ciphers",
        handlers::purge::purge_deleted_ciphers(env).await,
    );
    log_purge_result(
        "stale pending sends",
        handlers::purge::purge_stale_pending_sends(env).await,
    );
    log_purge_result(
        "expired sends",
        handlers::purge::purge_expired_sends(env).await,
    );
    log_purge_result(
        "expired auth requests",
        handlers::purge::purge_expired_auth_requests(env).await,
    );
}
