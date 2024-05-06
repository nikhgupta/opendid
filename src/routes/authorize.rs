use std::sync::{RwLock, RwLockReadGuard};
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use actix_session::Session;
use actix_web::{get, web, HttpResponse};
use log::info;
use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::box_;

use crate::{
    constants::AUTHORIZATION_CODE_NAME, constants::OIDC_SESSION_KEY, routes::error::Error, AppState,
};

#[derive(Serialize, Deserialize, Debug)]
pub struct CodeAuthorizationData {
    pub client_id: String,
    pub redirect_uri: String,
    pub expires_at: u64,
    pub nonce: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthorizeQueryParameters {
    pub client_id: String,
    pub redirect_uri: String,
    pub response_type: String,
    pub scope: String,
    pub state: String,
    pub nonce: String,
}

/// This handler is the oauth entrypoint. It parses the query parameters and checks if the client_id and redirect_uri are valid.
/// after that it stores the query parameters in the session and redirects the user to the login page.
#[get("/api/v1/authorize")]
async fn authorize_handler(
    session: Session,
    app_state: web::Data<RwLock<AppState>>,
    query: web::Query<AuthorizeQueryParameters>,
) -> Result<HttpResponse, Error> {
    log::info!("GET authorize handler");
    let app_state = app_state.read()?;
    let redirect_urls = &app_state
        .client_configs
        .get(&query.client_id)
        .ok_or(Error::OauthInvalidClientId)?
        .redirect_urls;

    let are_requirements_empty = &app_state
        .client_configs
        .get(&query.client_id)
        .ok_or(Error::OauthInvalidClientId)?
        .requirements
        .is_empty();

    let is_redirect_uri_in_query = redirect_urls.contains(&query.redirect_uri);
    let is_authorization_code = query.response_type == "code";
    session.insert(OIDC_SESSION_KEY, query.clone().into_inner())?;

    if is_authorization_code {
        info!("Authorization code flow");
        let authorization_code =
            generate_authorization_code(&session, &app_state, query.clone().into_inner())?;
        session.insert(AUTHORIZATION_CODE_NAME, authorization_code.clone())?;
    } else {
        info!("Implicit flow");
        // delete the authorization code from the session if it exists
        session.remove(AUTHORIZATION_CODE_NAME);
    }

    match (are_requirements_empty, is_redirect_uri_in_query) {
        (true, true) => {
            let redirect_uri_with_nonce = format!("/?nonce={}", query.nonce);
            Ok(HttpResponse::Found()
                .append_header(("Location", redirect_uri_with_nonce))
                .finish())
        }
        (false, true) => Ok(HttpResponse::Found()
            .append_header(("Location", "/"))
            .finish()),
        _ => Err(Error::OauthInvalidRedirectUri),
    }
}

fn generate_authorization_code(
    session: &Session,
    app_state: &RwLockReadGuard<AppState>,
    query: AuthorizeQueryParameters,
) -> Result<String, Error> {
    let oidc_context = session
        .get::<AuthorizeQueryParameters>(OIDC_SESSION_KEY)
        .map_err(|_| Error::OauthNoSession)?
        .ok_or(Error::OauthInvalidClientId)?;

    let data = CodeAuthorizationData {
        client_id: query.client_id,
        redirect_uri: query.redirect_uri,
        nonce: oidc_context.nonce,
        expires_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::OauthInvalidAuthorizationCode)?
            .as_secs()
            + 600,
    };

    let nonce = box_::gen_nonce();
    let serialized_data = serde_json::to_vec(&data).unwrap();
    let secret_key = app_state.session_secret_key.clone();
    let pub_key = secret_key.public_key();
    let encrypted_data = box_::seal(&serialized_data, &nonce, &pub_key, &secret_key);

    Ok(format!(
        "{}-{}",
        hex::encode(nonce),
        hex::encode(encrypted_data)
    ))
}

pub fn validate_authorization_code(
    app_state: &RwLockReadGuard<AppState>,
    code: &str,
) -> Result<CodeAuthorizationData, Error> {
    let parts: Vec<&str> = code.split('-').collect();
    let nonce = parts[0];
    let encrypted_data = hex::decode(parts[1]).map_err(|_| Error::OauthInvalidAuthorizationCode)?;
    let nonce = box_::Nonce::from_slice(
        &hex::decode(nonce).map_err(|_| Error::OauthInvalidAuthorizationCode)?,
    )
    .ok_or(Error::OauthInvalidAuthorizationCode)?;
    let secret_key = app_state.session_secret_key.clone();
    let public_key = secret_key.public_key();
    let serialized_data = box_::open(&encrypted_data, &nonce, &public_key, &secret_key)
        .map_err(|_| Error::OauthInvalidAuthorizationCode)?;

    let data: CodeAuthorizationData = serde_json::from_slice(&serialized_data)
        .map_err(|_| Error::OauthInvalidAuthorizationCode)?;

    let expiry = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::OauthInvalidAuthorizationCode)?
        .as_secs();

    if data.expires_at < expiry {
        return Err(Error::OauthInvalidAuthorizationCode);
    }

    Ok(data)
}
