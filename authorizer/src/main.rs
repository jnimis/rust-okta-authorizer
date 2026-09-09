use aws_lambda_events::apigw::{
    ApiGatewayCustomAuthorizerRequestTypeRequest,
    ApiGatewayCustomAuthorizerResponse
};

use aws_sdk_dynamodb::Client;
use dynamo_service::fetch_auths_for_user;
use lambda_runtime::{run, service_fn, Error, LambdaEvent};
use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use tracing::{debug, info, error};
use chrono::Local;

use crate::iam_policy::formatted_auth_response;
use cornercam_shared::user_service::GymAuth;

mod dynamo_service;
mod jwt_service;
mod iam_policy;

enum AuthPages {
    TermsConditions,
    SelectAGym,
    NeedAuthorization,
    Payment,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AuthResponse {
    auths: String, // Vec<GymAuth>
    gyms: String, // Vec<u32>
    next_page: String,
    error: String,
}

#[derive(Deserialize, Serialize, Debug)]
struct JWTK {
    kid: String,
    kty: String,
    alg: String,
    #[serde(rename = "use")]
    uses: String,
    e: String,
    n: String,
}

#[derive(Deserialize, Serialize, Debug)]
struct JWTKResponse {
    keys: Vec<JWTK>,
}

//stored keys

#[derive(Serialize, Deserialize, Debug)]
pub struct StoredKeys {
    keys: HashMap<String, JWTK>,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct Claims {
    aud: Vec<String>, // Optional. Audience
    exp: usize, // Required (validate_exp defaults to true in validation). Expiration time (as UTC timestamp)
    iat: usize, // Optional. Issued at (as UTC timestamp)
    iss: String, // Optional. Issuer
    sub: String,      // Optional. Subject (whom token refers to)
    scope: String,
    azp: String,
    cornercamemail: String, // specific to CornerCam implementation
}

async fn function_handler(
    current_keys: &StoredKeys,
    dynamo_client: &Client,
    event: LambdaEvent<ApiGatewayCustomAuthorizerRequestTypeRequest>,
) -> Result<ApiGatewayCustomAuthorizerResponse<AuthResponse>, Error> {

    debug!("headers: {:?}", event.payload.headers);
    let forced_error = std::env::var("FORCE_ERROR").unwrap_or_else(|_| "NONE".to_string());

    let token  = event.payload.headers
        .get("Authorization")
        .expect("couldn't get Authorization header from request")
        .to_str()
        .expect("couldn't convert Authorization header value to str type");
    let clean_token = token
        .strip_prefix("Bearer ")
        .unwrap_or(token);
    let method_arn = event.payload.method_arn.expect("no method ARN in request object");

    debug!("clean token: {}", clean_token);
    let token_data: Result<jsonwebtoken::TokenData<Claims>, anyhow::Error> = jwt_service::validate_token(clean_token, current_keys);

    let user_id = &token_data
        .as_ref()
        .expect("invalid claims on TokenData object")
        .claims.cornercamemail.clone();
    info!("user: {}", user_id);

    if forced_error != "NONE" {
        error!(error_code = forced_error.clone(), "configured to emit an error: {}", forced_error);
        let message = error_message_for_forced_error(&forced_error).to_string();
        let response: ApiGatewayCustomAuthorizerResponse<AuthResponse> = iam_policy:: not_allowed(
            user_id,
            "FORCED_ERROR".to_string(), 
            method_arn,
            vec![], 
            forced_error, 
            message)?;
        return Ok(response);
    }

    let route_key = method_arn.rsplit('/').next().unwrap_or("");
    info!("route key: {}", route_key);

    match route_key {
        "gyms" => {
            let auths = fetch_auths_for_user(dynamo_client, &user_id).await.unwrap_or(vec![]);
            let response: ApiGatewayCustomAuthorizerResponse<AuthResponse> = iam_policy:: prepare_response(
                token_data, 
                method_arn,
                response_from_auths(auths),
                user_id
            )?;
            return Ok(response)
        }
        "auth-request" => {
            // authentication is enough to be authorized for this route
            let response: ApiGatewayCustomAuthorizerResponse<AuthResponse> = iam_policy:: prepare_response(
                token_data, 
                method_arn,
                response_from_auths(vec![]),
                user_id
            )?;
            return Ok(response)
        }
        _ => {
            // for all other routes, authorize the request
            let gym_id = gym_id_from_headers(&event.payload.headers);
            info!("gym_id: {}", gym_id);
                
            Ok(authorize_request(dynamo_client, user_id, gym_id, method_arn, token_data).await?)
        }
    }
}

async fn authorize_request(dynamo_client: &Client, 
        user_id: &String, 
        gym_id: &str, 
        method_arn: String, 
        token_data: Result<jsonwebtoken::TokenData<Claims>, anyhow::Error>) 
            -> Result<ApiGatewayCustomAuthorizerResponse<AuthResponse>, Error> {
    let user_auths = fetch_auths_for_user(dynamo_client, &user_id).await;
    let is_admin_path = is_admin_path(&method_arn);
    let is_super_admin_path = is_super_admin_path(&method_arn);
    match user_auths {
        Err(e) => {
            // determine if error is system error or just no auths found
            // select a gym page (user with gyms)
            error!("ERROR fetching auths: {}", e);
            let response: ApiGatewayCustomAuthorizerResponse<AuthResponse> = iam_policy:: not_allowed(
                user_id,
                "AUTH_FETCH_ERROR".to_string(),
                method_arn,
                vec![], 
                "LOGIN".to_string(), 
                "ERROR 108: System error while fetching authorization information".to_string())?;
            return Ok(response);        }
        Ok(auths) => {
            info!("num auths: {}", auths.iter().count());
            if auths.iter().count() == 0 {
                // select a gym page (user with no gyms)
                let response: ApiGatewayCustomAuthorizerResponse<AuthResponse> = iam_policy:: not_allowed(
                    user_id,
                    "NO_AUTHS_FOUND".to_string(), 
                    method_arn,
                    auths, 
                    "SELECT_GYM".to_string(), 
                    "This user hasn't been approved for any gyms yet".to_string())?;
                return Ok(response);
            }
            let auths_iter = &auths;
            for auth in auths_iter.iter().cloned() {
                let is_valid_auth = is_auth_valid(&auth, is_admin_path, is_super_admin_path);
                if gym_id == "0" && auth.is_default && is_valid_auth {
                    // happy path for single gym auth
                    info!("default gym success");
                    let response: ApiGatewayCustomAuthorizerResponse<AuthResponse> = iam_policy:: prepare_response(
                        token_data, 
                        method_arn,
                        response_from_auths(auths),
                        user_id
                    )?;
                    return Ok(response)
                } else if auth_matches_gym(auth, gym_id) && is_valid_auth {
                    // happy path for single gym auth
                    info!("specific gym success");
                    let response: ApiGatewayCustomAuthorizerResponse<AuthResponse> = iam_policy:: prepare_response(
                        token_data, 
                        method_arn,
                        response_from_auths(auths),
                        user_id
                    )?;
                    return Ok(response)
                }
            }
            // select a gym page (user with gyms)
            let mut reason = "";
            let mut error_message = "";
            if gym_id == "0" { 
                reason = "NO_DEFAULT_GYM";
            } else {
                reason = "NO_VALID_AUTH_FOR_GYM";
                error_message = "You aren't authorized to access the selected gym";
            }
            let response: ApiGatewayCustomAuthorizerResponse<AuthResponse> = iam_policy:: not_allowed(
                user_id,
                reason.to_string(), 
                method_arn,
                auths, 
                "SELECT_GYM".to_string(), 
                error_message.to_string())?;
            return Ok(response);
        }
    }
}

fn error_message_for_forced_error(forced_error: &String) -> &str {
    match forced_error.as_str() {
        "SELECT_GYM" => "Artificial error to redirect to select gym page",
        _ => "Artificial error"
    }
}

fn response_from_auths(auths: Vec<GymAuth>) -> AuthResponse {
    formatted_auth_response(
        &auths,
        "".to_string(),
        "".to_string()
    )
}

// returns the &str value of the header "gym", or "0" if there is no parseable header
fn gym_id_from_headers(headers: &aws_lambda_events::http::HeaderMap) -> &str {
    let Some(gym_header) = headers.get("gym") else {
        info!("no gym header received");
        return "0"
    };
    let gym_id = gym_header.to_str().unwrap_or({
        "0"
    });
    if gym_id == "0" {
        error!("ERROR 152: received unparseable `gym` header");
    }
    return gym_id;
}

fn is_auth_valid(gym_auth: &GymAuth, is_admin_path: bool, is_super_admin_path: bool) -> bool {
    let dt = today();
    if is_admin_path && !(gym_auth.role == "ADMIN" || gym_auth.role == "SUPER_ADMIN") {
        return false;
    }
    if is_super_admin_path && !(gym_auth.role == "SUPER_ADMIN") {
        return false;
    }
    let Some(access_date) = gym_auth.access_expires.as_option() else {
        debug!("no access date, which means the auth hasn't been approved by the gym");
        return false;
    };
    debug!("today: {}; access_expires: {}", dt, access_date);
    *access_date >= *dt
}

fn is_admin_path(method_arn: &str) -> bool {
    // Exclude super-admin routes so they are not treated as normal admin paths.
    method_arn.contains("admin") && !method_arn.contains("super-admin")
}

fn is_super_admin_path(method_arn: &str) -> bool {
    method_arn.contains("super-admin")
}

fn auth_matches_gym(gym_auth: GymAuth, gym_id: &str) -> bool {
    gym_auth.gym_id == format!("GYM#{gym_id}")
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    cornercam_shared::lambda_config::initialize_logging();

    let table_name = std::env::var("KEYS_TABLE_NAME").unwrap();
    
    let jwks_endpoint = std::env::var("JWKS_ENDPOINT").unwrap();

    let cc_environment = std::env::var("ENVIRONMENT").unwrap();

    let dynamo_client = dynamo_service::get_dynamo_client().await;

    info!("getting keys from dynamo");

    let keys_from_dynamo = dynamo_service::get_keys_from_dynamo(&dynamo_client, &table_name).await;

    // if keys are present in dynamo - use them
    // if not, get them from a jwks endpoint and store in dynamo
    let stored_keys: StoredKeys = match keys_from_dynamo {
        Ok(keys_dynamo) => {
            info!("got keys from dynamo");
            jwtk_response_to_map(keys_dynamo)
        }
        Err(_) => {
            error!("no keys in dynamo - getting them from auth0 and storing in dynamo");
            let keys_resp = get_keys_from_jwks_endpoint(jwks_endpoint).await.unwrap();
            // ignoring result of putting record to dynamo
            let _ =
                dynamo_service::store_keys_in_dynamo(&dynamo_client, &table_name, &keys_resp).await;
            jwtk_response_to_map(keys_resp)
        }
    };

    // run(service_fn(function_handler)).await
    run(service_fn(|event| function_handler(&stored_keys, &dynamo_client, event))).await
}

fn jwtk_response_to_map(keys_resp: JWTKResponse) -> StoredKeys {
    keys_resp.keys.into_iter().fold(
        StoredKeys {
            keys: HashMap::new(),
        },
        |mut acc, key| {
            acc.keys.insert(key.kid.clone(), key);
            acc
        },
    )
}

async fn get_keys_from_jwks_endpoint(endpoint: String) -> anyhow::Result<JWTKResponse> {
    let result = reqwest::get(endpoint).await?.json::<JWTKResponse>().await?;
    Ok(result)
}

fn today() -> String {
    Local::now().format("%Y-%m-%d").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lambda_events::http::{HeaderMap, HeaderValue};
    use chrono::Duration;
    use cornercam_shared::user_service::AccessExpires;

    fn date_offset_from_today(days: i64) -> String {
        (Local::now() + Duration::days(days))
            .format("%Y-%m-%d")
            .to_string()
    }

    fn sample_auth(role: &str, access_expires: Option<&str>) -> GymAuth {
        GymAuth {
            user_id: "user@example.com".to_string(),
            gym_id: "GYM#42".to_string(),
            role: role.to_string(),
            access_expires: AccessExpires(access_expires.map(str::to_string)),
            is_default: false,
        }
    }

    #[test]
    fn is_auth_valid_accepts_future_and_today_expiry() {
        let future = sample_auth("USER", Some(&date_offset_from_today(30)));
        let expires_today = sample_auth("USER", Some(&today()));

        assert!(is_auth_valid(&future, false, false));
        assert!(is_auth_valid(&expires_today, false, false));
    }

    #[test]
    fn is_auth_valid_rejects_past_expiry() {
        let expired = sample_auth("USER", Some(&date_offset_from_today(-1)));
        assert!(!is_auth_valid(&expired, false, false));
    }

    #[test]
    fn is_auth_valid_rejects_missing_access_expires() {
        let unapproved = sample_auth("USER", None);
        assert!(!is_auth_valid(&unapproved, false, false));
    }

    #[test]
    fn is_auth_valid_admin_path_requires_admin_role() {
        let expires = date_offset_from_today(30);
        let user = sample_auth("USER", Some(&expires));
        let other_strange_role = sample_auth("OTHER_STRANGE_ROLE", Some(&expires));
        let admin = sample_auth("ADMIN", Some(&expires));
        let super_admin = sample_auth("SUPER_ADMIN", Some(&expires));

        assert!(!is_auth_valid(&user, true, false));
        assert!(is_auth_valid(&admin, true, false));
        assert!(is_auth_valid(&super_admin, true, false));
        assert!(!is_auth_valid(&other_strange_role, true, false));
    }

    #[test]
    fn is_auth_valid_super_admin_path_requires_super_admin_role() {
        // Super-admin paths are not admin paths (see is_admin_path), so flags are (false, true).
        let expires = date_offset_from_today(30);
        let user = sample_auth("USER", Some(&expires));
        let admin = sample_auth("ADMIN", Some(&expires));
        let super_admin = sample_auth("SUPER_ADMIN", Some(&expires));

        assert!(!is_auth_valid(&user, false, true));
        assert!(!is_auth_valid(&admin, false, true));
        assert!(is_auth_valid(&super_admin, false, true));
    }

    #[test]
    fn is_auth_valid_super_admin_can_access_admin_paths() {
        let expires = date_offset_from_today(30);
        let super_admin = sample_auth("SUPER_ADMIN", Some(&expires));
        assert!(is_auth_valid(&super_admin, true, false));
    }

    #[test]
    fn is_auth_valid_non_admin_path_allows_user_role() {
        let user = sample_auth("USER", Some(&date_offset_from_today(30)));
        assert!(is_auth_valid(&user, false, false));
    }

    #[test]
    fn is_auth_valid_admin_role_still_needs_valid_expiry() {
        let expired_admin = sample_auth("ADMIN", Some(&date_offset_from_today(-1)));
        let unapproved_admin = sample_auth("SUPER_ADMIN", None);

        assert!(!is_auth_valid(&expired_admin, true, false));
        assert!(!is_auth_valid(&unapproved_admin, false, true));
    }

    #[test]
    fn is_admin_path_detects_admin_but_not_super_admin() {
        assert!(is_admin_path(
            "arn:aws:execute-api:us-east-1:123:api/prod/GET/admin/gyms"
        ));
        assert!(is_admin_path("/admin"));
        assert!(!is_admin_path("/super-admin"));
        assert!(!is_admin_path(
            "arn:aws:execute-api:us-east-1:123:api/prod/GET/super-admin/users"
        ));
        assert!(!is_admin_path(
            "arn:aws:execute-api:us-east-1:123:api/prod/GET/gyms"
        ));
        assert!(!is_admin_path(
            "arn:aws:execute-api:us-east-1:123:api/prod/GET/auth-request"
        ));
    }

    #[test]
    fn is_super_admin_path_detects_super_admin_substring() {
        assert!(is_super_admin_path(
            "arn:aws:execute-api:us-east-1:123:api/prod/GET/super-admin/users"
        ));
        assert!(is_super_admin_path("/super-admin"));
        assert!(!is_super_admin_path(
            "arn:aws:execute-api:us-east-1:123:api/prod/GET/admin/gyms"
        ));
        assert!(!is_super_admin_path(
            "arn:aws:execute-api:us-east-1:123:api/prod/GET/gyms"
        ));
    }

    #[test]
    fn admin_and_super_admin_path_flags_are_mutually_exclusive() {
        let admin_arn = "arn:aws:execute-api:us-east-1:123:api/prod/GET/admin/gyms";
        let super_arn = "arn:aws:execute-api:us-east-1:123:api/prod/GET/super-admin/users";

        assert!(is_admin_path(admin_arn) && !is_super_admin_path(admin_arn));
        assert!(!is_admin_path(super_arn) && is_super_admin_path(super_arn));
    }

    #[test]
    fn auth_matches_gym_compares_prefixed_gym_id() {
        let auth = sample_auth("USER", Some(&today()));
        assert!(auth_matches_gym(auth.clone(), "42"));
        assert!(!auth_matches_gym(auth.clone(), "99"));
        assert!(!auth_matches_gym(auth, "GYM#42"));
    }

    #[test]
    fn gym_id_from_headers_defaults_to_zero_when_missing() {
        let headers = HeaderMap::new();
        assert_eq!(gym_id_from_headers(&headers), "0");
    }

    #[test]
    fn gym_id_from_headers_reads_gym_header() {
        let mut headers = HeaderMap::new();
        headers.insert("gym", HeaderValue::from_static("42"));
        assert_eq!(gym_id_from_headers(&headers), "42");
    }

}
