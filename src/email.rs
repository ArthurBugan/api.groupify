use reqwest::{Client, Request};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use std::collections::HashMap;

#[derive(Clone, Debug)]
pub struct EmailClient {
    http_client: Client,
    pub(crate) base_url: String,
    authorization_token: String,
}

#[derive(Debug, Serialize, Deserialize, FromRow, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SendEmailRequest {
    pub to: Vec<HashMap<String, String>>,
    pub template_id: i32,
    pub params: HashMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize, FromRow, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CreateContactRequest {
    email: String,
    list_ids: Vec<i32>,
}

impl EmailClient {
    pub fn new(base_url: String, authorization_token: String) -> Self {
        Self {
            http_client: Client::new(),
            base_url,
            authorization_token,
        }
    }

    pub async fn send_email(
        &self,
        recipient: &str,
        params: HashMap<String, String>,
        template_id: i32,
    ) -> Result<reqwest::Response, reqwest::Error> {
        let url = format!("{}/v3/smtp/email", self.base_url);
        let user_url = format!("{}/v3/contacts", self.base_url);

        // contact request
        let request_body = CreateContactRequest {
            list_ids: vec![2],
            email: recipient.to_string(),
        };

        let user_request = self
            .http_client
            .post(&user_url)
            .header("api-key", self.authorization_token.to_owned())
            .header("Accept", "application/json".to_owned())
            .header("Content-Type", "application/json".to_owned())
            .json(&request_body)
            .build()?;

        let curl_command = request_to_curl(&user_request);

        tracing::info!("user_request {}", curl_command.unwrap());

        self.http_client.execute(user_request).await?;

        // email request
        let mut to = HashMap::new();
        to.insert("name".to_owned(), "No name".to_owned());
        to.insert("email".to_owned(), recipient.to_owned());

        let request_body = SendEmailRequest {
            to: vec![to],
            template_id: template_id,
            params,
        };

        let request = self
            .http_client
            .post(&url)
            .header("api-key", self.authorization_token.to_owned())
            .header("Accept", "application/json".to_owned())
            .header("Content-Type", "application/json".to_owned())
            .json(&request_body)
            .build()?;

        let curl_command = request_to_curl(&request);

        tracing::info!("curl_command {}", curl_command.unwrap());

        let response = self.http_client.execute(request).await?;

        Ok(response)
    }
}

fn request_to_curl(request: &Request) -> Result<String, reqwest::Error> {
    let command = format!("curl -X {} '{}'", request.method(), request.url());

    // Add headers to the curl command
    let mut command = request
        .headers()
        .iter()
        .fold(command, |cmd, (name, value)| {
            format!(
                "{} -H '{}: {}'",
                cmd,
                name.as_str(),
                value.to_str().unwrap()
            )
        });

    // Add request body to the curl command
    if let Some(body) = request.body() {
        if let Some(Ok(body_str)) = body
            .as_bytes()
            .and_then(|bytes| Some(String::from_utf8(bytes.to_vec())))
        {
            command.push_str(&format!(" -d '{}'", body_str));
        }
    }

    Ok(command)
}
