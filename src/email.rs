use reqwest::{Client, Request};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use std::collections::HashMap;
use tracing::{info, error};

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

    #[tracing::instrument(
    name = "send_email",
    skip(self, params),
    fields(
        recipient = %recipient,
        template_id = template_id
    )
)]
    pub async fn send_email(
        &self,
        recipient: &str,
        params: HashMap<String, String>,
        template_id: i32,
    ) -> Result<reqwest::Response, reqwest::Error> {
        let url = format!("{}/v3/smtp/email", self.base_url);
        let user_url = format!("{}/v3/contacts", self.base_url);

        // Contact request
        let request_body = CreateContactRequest {
            list_ids: vec![2],
            email: recipient.to_string(),
        };

        let user_request = match self
            .http_client
            .post(&user_url)
            .header("api-key", self.authorization_token.to_owned())
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .json(&request_body)
            .build()
        {
            Ok(req) => req,
            Err(err) => {
                error!("Failed to build contact request: {:?}", err);
                return Err(err);
            }
        };

        if let Ok(curl_command) = request_to_curl(&user_request) {
            info!("user_request CURL: {}", curl_command);
        }

        if let Err(err) = self.http_client.execute(user_request).await {
            error!("Failed to send contact request: {:?}", err);
            return Err(err);
        }

        // Email request
        let mut to = HashMap::new();
        to.insert("name".to_owned(), "No name".to_owned());
        to.insert("email".to_owned(), recipient.to_owned());

        let request_body = SendEmailRequest {
            to: vec![to],
            template_id,
            params,
        };

        let email_request = match self
            .http_client
            .post(&url)
            .header("api-key", self.authorization_token.to_owned())
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .json(&request_body)
            .build()
        {
            Ok(req) => req,
            Err(err) => {
                error!("Failed to build email request: {:?}", err);
                return Err(err);
            }
        };

        if let Ok(curl_command) = request_to_curl(&email_request) {
            info!("email_request CURL: {}", curl_command);
        }

        match self.http_client.execute(email_request).await {
            Ok(response) => Ok(response),
            Err(err) => {
                error!("Failed to send email: {:?}", err);
                Err(err)
            }
        }
    }
}

fn request_to_curl(request: &Request) -> Result<String, reqwest::Error> {
    let mut command = format!("curl -X {} '{}'", request.method(), request.url());

    for (name, value) in request.headers().iter() {
        if let Ok(val_str) = value.to_str() {
            command.push_str(&format!(" -H '{}: {}'", name.as_str(), val_str));
        } else {
            command.push_str(&format!(" -H '{}: <binary>'", name.as_str()));
        }
    }

    if let Some(body) = request.body() {
        if let Some(bytes) = body.as_bytes() {
            if let Ok(body_str) = std::str::from_utf8(bytes) {
                command.push_str(&format!(" -d '{}'", body_str));
            } else {
                command.push_str(" -d '<non-utf8 body>'");
            }
        } else {
            command.push_str(" -d '<streaming body not shown>'");
        }
    }

    Ok(command)
}
