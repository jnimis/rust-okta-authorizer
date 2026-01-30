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

mod dynamo_service;
mod jwt_service;
mod iam_policy;

enum AuthPages {
    TermsConditions,
    SelectAGym,
    NeedAuthorization,
    Payment,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[allow(non_snake_case)]
pub struct GymAuth {
    PK: String,
    SK: String,
    pub access_expires: String,
    #[serde(default = "bool::default")]
    is_default: bool,
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
    
    let gym_id = gym_id_from_headers(&event.payload.headers);
    info!("gym_id: {}", gym_id);

    let user_auths = fetch_auths_for_user(dynamo_client, &user_id).await;
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
                    vec![], 
                    "SELECT_GYM".to_string(), 
                    "".to_string())?;
                return Ok(response);
            }
            let auths_iter = &auths;
            for auth in auths_iter.iter().cloned() {
                if gym_id == "0" && auth.is_default && is_auth_valid(&auth) {
                    // happy path for single gym auth
                    let response: ApiGatewayCustomAuthorizerResponse<AuthResponse> = iam_policy:: prepare_response(
                        token_data, 
                        method_arn,
                        response_from_auths(auths),
                        user_id
                    )?;
                    return Ok(response)
                } else if auth_matches_gym(auth, gym_id) {
                    // happy path for single gym auth
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
            let response: ApiGatewayCustomAuthorizerResponse<AuthResponse> = iam_policy:: not_allowed(
                user_id,
                if gym_id == "0" { "NO_DEFAULT_GYM".to_string() } else { "NO_VALID_AUTH_FOR_GYM".to_string() }, 
                method_arn,
                auths, 
                vec![], 
                "SELECT_GYM".to_string(), 
                "".to_string())?;
            return Ok(response);
        }
    }
}

fn response_from_auths(auths: Vec<GymAuth>) -> AuthResponse {
    formatted_auth_response(
        auths,
        vec![],
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

fn is_auth_valid(gym_auth: &GymAuth) -> bool {
    let dt = format!("{}", Local::now().format("%Y-%m-%d"));
    gym_auth.access_expires >= dt 
}

fn auth_matches_gym(gym_auth: GymAuth, gym_id: &str) -> bool {
    gym_auth.SK == format!("GYM#{gym_id}")
}

#[tokio::main]
async fn main() -> Result<(), Error> {

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

    let log_level_string = std::env::var("LOG_LEVEL").unwrap_or("ERROR".to_string());
    let log_level = match log_level_string.as_str() {
        "DEBUG" => tracing::Level::DEBUG,
        "INFO" => tracing::Level::INFO,
        _ => tracing::Level::ERROR
    };

    tracing_subscriber::fmt() // .json()
        .with_max_level(log_level)
        .with_target(false)         // disable printing the name of the module in every log line.
        // .with_current_span(false)   // only available w JSON logs
        .with_ansi(false)           // don't include colors
        .init();

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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_get_keys_from_endpoint() {
        let endpoint = String::from("https://onemanband.auth0.com/.well-known/jwks.json");
        let keys = get_keys_from_jwks_endpoint(endpoint)
            .await.expect("error getting keys from endpoint");
        let map = jwtk_response_to_map(keys);
        assert_eq!(map.keys.get("NUQzQUMwOThGQjlFNDRFNEZDQTA2NzkzOTA0MzFFMThEQUFGRjhGQg").unwrap().alg, "RS256")
    }

    // #[tokio::test]
    // async fn test_load_data() {
    //     let data = load_test_data();
    //     assert_eq!(data, "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Ik5VUXpRVU13T1RoR1FqbEZORFJGTkVaRFFUQTJOemt6T1RBME16RkZNVGhFUVVGR1JqaEdRZyJ9.eyJjb3JuZXJjYW1lbWFpbCI6ImpvaG4ubmltaXNAZ21haWwuY29tIiwiaXNzIjoiaHR0cHM6Ly9vbmVtYW5iYW5kLmF1dGgwLmNvbS8iLCJzdWIiOiJnb29nbGUtb2F1dGgyfDEwNjY0NzM1NDk5NjcwMTMwNjIzMSIsImF1ZCI6WyJodHRwczovL2Nvcm5lcmNhbS5uZXQiLCJodHRwczovL29uZW1hbmJhbmQuYXV0aDAuY29tL3VzZXJpbmZvIl0sImlhdCI6MTc0MTU3NzMwNiwiZXhwIjoxNzQxNjYzNzA2LCJzY29wZSI6Im9wZW5pZCIsImF6cCI6InNlTk5aNzMybTh5TnFWZHRtdXdxRlV0QzZObHZMeUV3In0.pu9sJWdgWW9iWPFKp0vhIAAJb8jIlrgAzZxsIiKyjaaLFhqnfS4Ot4uac52tXY2hJfXkIVoKxUIDMZ4kXdz0z_aApY4PzZaCVsluVZKsj_9k1OCADr6MAsr50gE-8LJhtQrlm8T2cNjepmpFZNrXGKhOe38ZzfbO-sSaPq4PT2ZN5686l6Pe2CWFw3mHxYlInGN79MtSzdeXBNUWCZX-lhMHcVeRXVJnRfVu0Ab8JB4hKdLNhHtaKw35u35gkZ3ZPMe64AviyrOiSVgrsdWmVVw22T-Xoz8ZmP1oTAdBi0_mh2tbRuMftVWLxZEyEUVXcXZ0zE9ocSTkiKfiTOyuBg");
    // }
}
