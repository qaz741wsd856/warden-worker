use axum::{extract::DefaultBodyLimit, Extension};
use tower_http::cors::{Any, CorsLayer};
use tower_service::Service;
use worker::{durable_object, DurableObject, Env, HttpRequest, Request, Response, Result, State};

use crate::{router, BaseUrl};

/// Durable Object used to run CPU-heavy API flows with a higher CPU budget.
///
/// This DO intentionally reuses the existing axum router so we don't have to duplicate business
/// logic in a separate code path.
#[durable_object]
pub struct HeavyDo {
    state: State,
    env: Env,
}

impl DurableObject for HeavyDo {
    fn new(state: State, env: Env) -> Self {
        Self { state, env }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        // Set up logging/panic hook (idempotent).
        console_error_panic_hook::set_once();
        let _ = console_log::init_with_level(log::Level::Debug);

        // Keep fields used to avoid "unused" warnings even if we don't currently rely on them.
        let _ = &self.state;

        // Internal cron entry point. Only reachable through a DO stub: the public Worker never
        // forwards this path (it is not in the offload list in src/entry.js).
        if req.method() == worker::Method::Post && req.path() == "/__internal/scheduled" {
            crate::run_scheduled_purges(&self.env).await;
            return Response::ok("ok");
        }

        // Convert worker::Request -> worker::HttpRequest so we can reuse axum Router.
        let http_req: HttpRequest = req.try_into()?;

        // Extract base URL for /api/config endpoint (matches src/lib.rs behavior).
        let uri = http_req.uri().clone();
        let base_url = format!(
            "{}://{}",
            uri.scheme_str().unwrap_or("https"),
            uri.authority().map(|a| a.as_str()).unwrap_or("localhost")
        );

        // Allow all origins for CORS, matching the main worker.
        let cors = CorsLayer::new()
            .allow_methods(Any)
            .allow_headers(Any)
            .allow_origin(Any);

        // Match the main worker's default body limit (5MB) for regular API requests.
        const BODY_LIMIT: usize = 5 * 1024 * 1024;

        // Reuse the existing router stack.
        let mut app = router::api_router(self.env.clone())
            .layer(Extension(BaseUrl(base_url)))
            .layer(cors)
            .layer(DefaultBodyLimit::max(BODY_LIMIT));

        let http_resp = app.call(http_req).await?;

        // Convert http::Response -> worker::Response for the DO runtime.
        http_resp.try_into()
    }
}
