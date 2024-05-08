use reqwest::{Client, Request, Response};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool, Row};
use std::collections::{BTreeMap, HashMap};

#[derive(Clone, Debug)]
pub struct EmailClient {
    http_client: Client,
    pub(crate) base_url: String,
    sender: String,
    authorization_token: String,
}

#[derive(Debug, Serialize, Deserialize, FromRow, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct SendEmailRequest {
    pub from: String,
    pub to: String,
    pub message_stream: String,
    pub template_id: String,
    pub template_model: HashMap<String, String>,
}

impl EmailClient {
    pub fn new(base_url: String, sender: String, authorization_token: String) -> Self {
        Self {
            http_client: Client::new(),
            base_url,
            sender,
            authorization_token,
        }
    }

    pub async fn send_email(
        &self,
        recipient: &str,
        message_stream: &str,
        template_model: HashMap<String, String>,
        template_id: &str,
    ) -> Result<reqwest::Response, reqwest::Error> {
        let url = format!("{}/email/withTemplate", self.base_url);

        let request_body = SendEmailRequest {
            from: self.sender.to_owned(),
            to: recipient.to_owned(),
            message_stream: message_stream.to_owned(),
            template_id: template_id.to_owned(),
            template_model,
        };

        let request = self
            .http_client
            .post(&url)
            .header(
                "X-Postmark-Server-Token",
                self.authorization_token.to_owned(),
            )
            .header("Accept", "application/json".to_owned())
            .header("Content-Type", "application/json".to_owned())
            .json(&request_body)
            .build()?;

        let curl_command = request_to_curl(&request);

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
