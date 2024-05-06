use std::sync::RwLock;

use actix_web::{post, web, HttpResponse, Responder};
use serde::Deserialize;
use serde_json::json;

use crate::AppState;

#[derive(Deserialize, Debug)]
struct RefreshTokenContainer {
    #[serde(rename = "refreshToken")]
    refresh_token: String,
}

#[post("/api/v1/refresh")]
async fn refresh_handler(
    app_state: web::Data<RwLock<AppState>>,
    refresh_token: web::Json<RefreshTokenContainer>,
) -> impl Responder {
    let app_state = app_state.read().expect("Failed to read app state");
    let jwt = refresh_token.refresh_token.clone();
    // if there is a public key use this for verification, otherwise fall back to the secret key, i.e. HS256 case etc.
    let verification_key = if let Some(key) = &app_state.jwt_public_key {
        key
    } else {
        &app_state.jwt_secret_key
    };
    let mut token = if let Ok(token) =
        app_state
            .jwt_builder
            .parse_refresh_token(&jwt, verification_key, &app_state.jwt_algorithm)
    {
        token
    } else {
        return HttpResponse::Unauthorized().body("Invalid token");
    };

    // override token data to issue different tokens
    token.properties.insert(
        "issued_at".to_string(),
        json!(chrono::Utc::now().timestamp()),
    );

    let access_token = match app_state
        .jwt_builder
        .new_id_token(&token.subject, &token.name, &token.properties, &token.nonce)
        .to_jwt(&app_state.jwt_secret_key, &app_state.jwt_algorithm)
    {
        Ok(token) => token,
        Err(_) => return HttpResponse::Unauthorized().body("Invalid token"),
    };
    let refresh_token = match app_state
        .jwt_builder
        .new_refresh_token(&token.subject, &token.name, &token.properties, &token.nonce)
        .to_jwt(&app_state.jwt_secret_key, &app_state.jwt_algorithm)
    {
        Ok(token) => token,
        Err(_) => return HttpResponse::Unauthorized().body("Invalid token"),
    };
    HttpResponse::Ok().json(json!({
        "accessToken": access_token,
        "refreshToken": refresh_token,
    }))
}
