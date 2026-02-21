use aws_lambda_events::apigw::{
    ApiGatewayCustomAuthorizerPolicy, ApiGatewayCustomAuthorizerResponse, IamPolicyStatement,
};
use tracing::{info, debug};

use crate::{AuthResponse, Claims, GymAuth};

pub fn not_allowed(
    user: &String,
    reason: String,
    path_to_allow: String,
    auths: Vec<GymAuth>,
    next_page: String,
    error: String
) -> anyhow::Result<ApiGatewayCustomAuthorizerResponse<AuthResponse>> {
    info!("denied for reason: {}", reason);

    let statement = vec![IamPolicyStatement {
        effect: Some("Deny".to_string()),
        action: vec!["execute-api:Invoke".to_string()],
        resource: vec![path_to_allow],
    }];
    debug!("statement: {:?}", statement);

    let policy = ApiGatewayCustomAuthorizerPolicy {
        version: Some("2012-10-17".to_string()),
        statement,
    };
    debug!("policy: {:?}", policy);

    let resp = ApiGatewayCustomAuthorizerResponse {
        principal_id: Some(user.to_string()),
        policy_document: policy,
        context: formatted_auth_response(
            &auths,
            next_page,            
            error,
        ),
        usage_identifier_key: None,
    };
    debug!("resp: {:?}", resp);

    return Ok(resp);
}

pub fn formatted_auth_response(
    auths: &Vec<GymAuth>,
    next_page: String,
    error: String,
) -> AuthResponse {

    // convert arrays to strings, because the API Gateway API doesn't allow nested objects inside context
    let auths_string = auths.iter()
        .map(|auth| format!("{}|{}|{}|{}", auth.PK, auth.SK, auth.access_expires, auth.is_default))
        .collect();
    let gyms_string = auths.iter().map(|auth| auth.SK.strip_prefix("GYM#"))
        .flatten()
        .collect::<Vec<&str>>()
        .join("|");
    debug!("auths_string: {:?}", auths_string);
    debug!("gyms_string: {:?}", gyms_string);

    AuthResponse {
        auths: auths_string,
        error,
        gyms: gyms_string,
        next_page,
    }
}

pub fn prepare_response(
    validated_token: anyhow::Result<jsonwebtoken::TokenData<Claims>>,
    path_to_allow: String,
    auth_response: AuthResponse,
    user: &String
) -> anyhow::Result<ApiGatewayCustomAuthorizerResponse<AuthResponse>> {
    let policy = match validated_token {
        Ok(_token_data) => {
            let statement = vec![IamPolicyStatement {
                effect: Some("Allow".to_string()),
                action: vec!["execute-api:Invoke".to_string()],
                resource: vec![path_to_allow],
            }];

            ApiGatewayCustomAuthorizerPolicy {
                version: Some("2012-10-17".to_string()),
                statement,
            }
        }
        Err(e) => {
            println!("token validation failed with error: {:?}", e);

            let statement = vec![IamPolicyStatement {
                effect: Some("Deny".to_string()),
                action: vec!["execute-api:Invoke".to_string()],
                resource: vec![path_to_allow],
            }];

            ApiGatewayCustomAuthorizerPolicy {
                version: Some("2012-10-17".to_string()),
                statement,
            }
        }
    };
    // Prepare the response
    let resp = ApiGatewayCustomAuthorizerResponse {
        principal_id: Some(user.to_string()),
        policy_document: policy,
        context: auth_response,
        usage_identifier_key: None,
    };
    return Ok(resp);
}
