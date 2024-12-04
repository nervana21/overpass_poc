pub mod api_ovp;

use axum::{
    routing::{get, post},
    Router,
    Extension,
    Json,
};
use std::net::SocketAddr;
use tower_http::cors::{CorsLayer, Any};
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() {
    // Load environment variables
    dotenv::dotenv().ok();
    
    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| "info".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Create database connection pool
    let db_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set");
    
    let pool = sqlx::PgPool::connect(&db_url)
        .await
        .expect("Failed to connect to database");

    // Migrate database
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("Failed to migrate database");

    // Build our application with routes
    let app = Router::new()
        .route("/", get(health_check))
        .route("/api/channels", post(create_channel))
        .route("/api/channels/:id/state", get(get_channel_state))
        .route("/api/channels/:id/process", post(process_boc))
        // Add CORS layer
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any)
        )
        // Add tracing
        .layer(TraceLayer::new_for_http())
        // Add database connection pool
        .layer(Extension(pool));

    // Run our application
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    tracing::info!("listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();    
}// Health check endpoint
async fn health_check() -> &'static str {
    "OK"
}

// Channel creation endpoint
async fn create_channel() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "not implemented" }))
}

// Get channel state endpoint
async fn get_channel_state() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "not implemented" }))
}

// Process BOC endpoint
async fn process_boc() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "not implemented" }))
}