use anyhow::Error;
use anyhow::{anyhow, Context};
use serde_dynamo::from_items;

use super::GymAuth;
use super::JWTKResponse;
use std::env;

pub fn user_service_table_name() -> String {
    let key = "USER_SERVICE_TABLE_NAME";

    match env::var(key) {
        Ok(val) => return val,
        Err(e) => panic!("Can't find user service table name from env var with key {}: {}", key, e)
    }
}

pub async fn get_dynamo_client() -> aws_sdk_dynamodb::Client {
    let region_provider =
        aws_config::meta::region::RegionProviderChain::default_provider().or_else("us-east-1");

    let config = aws_config::from_env().region(region_provider).load().await;

    return aws_sdk_dynamodb::Client::new(&config);
}

pub(crate) async fn get_keys_from_dynamo(
    dynamo_client: &aws_sdk_dynamodb::Client,
    table_name: &String,
) -> anyhow::Result<JWTKResponse> {
    let keys_results = dynamo_client
        .get_item()
        .table_name(table_name)
        .key(
            "PK",
            aws_sdk_dynamodb::types::AttributeValue::S("#KEYS".to_string()),
        )
        .send()
        .await?;

    let keys_resp = keys_results.item.context("missing keys in Dynamo")?;

    let keys_json = keys_resp
        .get("keys")
        .context("missing keys attribute")?
        .as_s()
        .map_err(|_| anyhow!("Keys are not a string"))?;

    return Ok(serde_json::from_str(&keys_json)?);
}

pub(crate) async fn store_keys_in_dynamo(
    dynamo_client: &aws_sdk_dynamodb::Client,
    table_name: &String,
    keys: &JWTKResponse,
) -> anyhow::Result<()> {
    let keys_json = serde_json::to_string(&keys)?;

    dynamo_client
        .put_item()
        .table_name(table_name)
        .item(
            "PK",
            aws_sdk_dynamodb::types::AttributeValue::S("#KEYS".to_string()),
        )
        .item(
            "keys",
            aws_sdk_dynamodb::types::AttributeValue::S(keys_json),
        )
        .send()
        .await?;

    Ok(())
}

pub(crate) async fn fetch_auths_for_user(
    dynamo_client: &aws_sdk_dynamodb::Client,
    user_id: &String
) -> Result<Vec<GymAuth>, Error> {
    let pk = format!("USER#{user_id}");
    let sk = format!("GYM#");
    let results = dynamo_client
        .query()
        .table_name(user_service_table_name())
        .expression_attribute_values(":user_id", aws_sdk_dynamodb::types::AttributeValue::S(pk))
        .expression_attribute_values(":gym_id", aws_sdk_dynamodb::types::AttributeValue::S(sk))
        .key_condition_expression("PK = :user_id AND begins_with ( SK, :gym_id )")
        .send()
        .await.expect("ERROR when querying dynamoDB");

    if let Some(items) = results.items {
        let auths = from_items(items).expect("ERROR decoding items into GymAuth objects");
        Ok(auths)
    } else {
        Ok(vec![])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_fetch_auths_for_user() {
        let dynamo_client = get_dynamo_client().await;
        let user_id = String::from("john.nimis@gmail.com");
        let john_auth = fetch_auths_for_user(&dynamo_client, &user_id)
            .await
            .expect("unable to get response from dynamo");
        assert!(john_auth.iter().count() == 1);
        assert!(john_auth[0].access_expires == "2025-10-19");
    }

    // #[tokio::test]
    // async fn test_decode_header() {
    //     let token = load_test_data();
    //     let header = decode_header(&token).expect("can't unwrap decoded header");
    //     assert_eq!(header.alg, Algorithm::RS256);
    // }

    // #[tokio::test]
    // async fn test_load_data() {
    //     let data = load_test_data();
    //     assert_eq!(data, "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Ik5VUXpRVU13T1RoR1FqbEZORFJGTkVaRFFUQTJOemt6T1RBME16RkZNVGhFUVVGR1JqaEdRZyJ9.eyJjb3JuZXJjYW1lbWFpbCI6ImpvaG4ubmltaXNAZ21haWwuY29tIiwiaXNzIjoiaHR0cHM6Ly9vbmVtYW5iYW5kLmF1dGgwLmNvbS8iLCJzdWIiOiJnb29nbGUtb2F1dGgyfDEwNjY0NzM1NDk5NjcwMTMwNjIzMSIsImF1ZCI6WyJodHRwczovL2Nvcm5lcmNhbS5uZXQiLCJodHRwczovL29uZW1hbmJhbmQuYXV0aDAuY29tL3VzZXJpbmZvIl0sImlhdCI6MTc0MTU3NzMwNiwiZXhwIjoxNzQxNjYzNzA2LCJzY29wZSI6Im9wZW5pZCIsImF6cCI6InNlTk5aNzMybTh5TnFWZHRtdXdxRlV0QzZObHZMeUV3In0.pu9sJWdgWW9iWPFKp0vhIAAJb8jIlrgAzZxsIiKyjaaLFhqnfS4Ot4uac52tXY2hJfXkIVoKxUIDMZ4kXdz0z_aApY4PzZaCVsluVZKsj_9k1OCADr6MAsr50gE-8LJhtQrlm8T2cNjepmpFZNrXGKhOe38ZzfbO-sSaPq4PT2ZN5686l6Pe2CWFw3mHxYlInGN79MtSzdeXBNUWCZX-lhMHcVeRXVJnRfVu0Ab8JB4hKdLNhHtaKw35u35gkZ3ZPMe64AviyrOiSVgrsdWmVVw22T-Xoz8ZmP1oTAdBi0_mh2tbRuMftVWLxZEyEUVXcXZ0zE9ocSTkiKfiTOyuBg");
    // }
}
