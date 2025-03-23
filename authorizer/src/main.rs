use aws_lambda_events::apigw::{
    ApiGatewayCustomAuthorizerRequestTypeRequest,
    ApiGatewayCustomAuthorizerResponse
};

use aws_sdk_dynamodb::Client;
use dynamo_service::{fetch_auth_for_user, fetch_auths_for_user};
use lambda_runtime::{run, service_fn, Error, LambdaEvent};
use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use tracing::{info, error};
use chrono::Local;

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
pub struct GymAuth {
    PK: String,
    SK: String,
    pub access_expires: String,
    is_default: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AuthResponse {
    auths: Vec<GymAuth>,
    gyms: Vec<u32>,
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

#[derive(Deserialize, Serialize)]
pub struct Claims {
    aud: String, // Optional. Audience
    exp: usize, // Required (validate_exp defaults to true in validation). Expiration time (as UTC timestamp)
    iat: usize, // Optional. Issued at (as UTC timestamp)
    iss: String, // Optional. Issuer
    uid: String,
    sub: String,      // Optional. Subject (whom token refers to)
    scp: Vec<String>, // Optional. Scopes (permissions)>
    cornercamemail: String, // specific to CornerCam implementation
}

async fn function_handler(
    current_keys: &StoredKeys,
    dynamo_client: &Client,
    event: LambdaEvent<ApiGatewayCustomAuthorizerRequestTypeRequest>,
) -> Result<ApiGatewayCustomAuthorizerResponse<AuthResponse>, Error> {

    let token  = event.payload.headers
        .get("Authorization")
        .expect("couldn't get Authorization header from request")
        .to_str()
        .expect("couldn't convert Authorization header value to str type");

    let token_data: Result<jsonwebtoken::TokenData<Claims>, anyhow::Error> = jwt_service::validate_token(token, current_keys);
    let user_id = &token_data
        .expect("invalid claims on TokenData object")
        .claims.cornercamemail;
    
    let gym_id = event.payload.headers
        .get("gym");
    let user_auths = fetch_auths_for_user(dynamo_client, &user_id).await;
    match gym_id {
        None => {
            match user_auths {
                Err(e) => {
                    if auths.iter().count() == 0 {
                        // select a gym page (user with no gyms)
                    } else {
                         // select a gym page (user with gyms)
                    }
                }
                Ok(auths) => {
                    if auths.iter().count() == 0 {
                        // select a gym page (user with no gyms)
                    }
                    for auth in auths {
                        if (auth.is_default && is_auth_valid(auth)) {
                            // happy path for single gym auth
                        }
                    }
                    // select a gym page (user with gyms)
                }
            }
        }
        Some(gym_id) => {
            match user_auths {
                Err(e) => {

                }
                Ok(auths) => {
                    
                }
            }
            let user_auth = fetch_auth_for_user(dynamo_client, 
                user_id, 
                gym_id.to_str().expect("couldn't convert gym_id to str type"))
                .await;
            if let auth = user_auth.unwrap() {
                if is_auth_valid(auth) {
                    // happy path for single gym auth
                } else {
                    // user owes money
                }
            }
            // no auth for this user and gym
            // TODO: really query again? I don't think so... we should always get all auths
        }
    }

    
    let response: ApiGatewayCustomAuthorizerResponse<AuthResponse> = iam_policy:: prepare_response(token_data)?;

    return Ok(response)
}

fn is_auth_valid(gym_auth: GymAuth) -> bool {
    let dt = format!("{}", Local::now().format("%Y-%m-%d"));
    gym_auth.access_expires >= dt 
}

#[tokio::main]
async fn main() -> Result<(), Error> {

    let table_name = std::env::var("KEYS_TABLE_NAME").unwrap();
    
    let jwks_endpoint = std::env::var("JWKS_ENDPOINT").unwrap();

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
            error!("no keys in dynamo - getting them from okta and storing in  dynamo");
            let keys_resp = get_keys_from_jwks_endpoint(jwks_endpoint).await.unwrap();
            // ignoring result of putting record to dynamo
            let _ =
                dynamo_service::store_keys_in_dynamo(&dynamo_client, &table_name, &keys_resp).await;
            jwtk_response_to_map(keys_resp)
        }
    };

    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        // disable printing the name of the module in every log line.
        .with_target(false)
        // disabling time is handy because CloudWatch will add the ingestion time.
        .without_time()
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
