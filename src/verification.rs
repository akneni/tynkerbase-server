use reqwest;
use anyhow::{anyhow, Result};
use serde_json;
use std::{collections::HashMap, time::Duration};


pub async fn verify_email(email: &str, api_key: &str) -> Result<bool> {
    let client = reqwest::ClientBuilder::new()
        .timeout(Duration::from_secs(60*5))
        .build()
        .map_err(|e| anyhow!("Error building http client -> {}", e))?;

    let endpoint = format!("https://api-bdc.net/data/email-verify?emailAddress={}&key={}", email, api_key);
    let res = client.get(&endpoint).send().await
        .map_err(|e| {
            let err_msg = format!("Error calling api -> {}", e).replace(api_key, "REDACTED");
            anyhow!("{}", err_msg)
        })?;
    
    let res = res.text().await.unwrap();
    

    let res: HashMap<String, String> = match serde_json::from_str(&res) {
        Ok(r) => r,
        Err(e) => return Err(anyhow!("Error -> {}", e)),
    };

    let c1: bool = res.get("isValid").unwrap_or(&"false".to_string()).parse().unwrap_or(false);
    let c2: bool = res.get("isKnownSpammerDomain").unwrap_or(&"false".to_string()).parse().unwrap_or(false);

    Ok(c1 && c2)
}