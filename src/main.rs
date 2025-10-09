//! OHTTP Proxy Server
//!
//! A SOCKS5 proxy server that routes traffic through OHTTP (Oblivious HTTP) relays
//! for enhanced privacy and anonymity. This proxy accepts SOCKS5 connections and
//! forwards them through encrypted OHTTP tunnels to protect client metadata.

use bhttp::{Message, Mode};
use bytes::BytesMut;
use clap::Parser;
use clap_verbosity_flag::{InfoLevel, Verbosity};
use ohttp::ClientRequest;
use reqwest::{
    Client, ClientBuilder,
    header::{CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue, InvalidHeaderValue, ToStrError},
};
use socks_lib::{
    io::{self, AsyncRead, AsyncWrite},
    net::TcpListener,
    v5::{
        Request, Stream,
        server::{Config, Handler, Server, auth::NoAuthentication},
    },
};
use std::{io::Cursor, net::SocketAddr, str::FromStr, string::FromUtf8Error, sync::Mutex};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, error, info, instrument, trace, warn};
use tracing_subscriber::FmtSubscriber;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[command(flatten)]
    verbosity: Verbosity<InfoLevel>,

    /// The socket address on which to listen for SOCKS5 connections.
    ///
    /// 0.0.0.0 or [::] are v4 and v6 wildcard addresses.
    /// For IPv4 localhost only, use 127.0.0.1:<port>
    #[arg(long, default_value = "[::]:32547")]
    socks5: SocketAddr,

    /// URL to the OHTTP Relay's gateway, often ending in `/gateway`
    ///
    /// Note that any relay headers supplied will be sent with each request.
    #[arg(long)]
    ohttp_relay_url: String,

    /// URL to the OHTTP Configuration, often ending in `/ohttp-configs`
    ///
    /// Note that any relay headers supplied will be sent with the request.
    #[arg(long)]
    ohttp_configuration_url: String,

    /// A custom CA certificate to use.
    #[arg(long)]
    ca_cert: Option<String>,

    /// If specified as X=Y, send that HTTP header to the relay.
    ///
    /// Example: X-Relay-Auth=authcookiegibberish
    ///
    /// May be specified multiple times, to send more than one header.
    #[arg(long)]
    relay_headers: Option<Vec<String>>,

    /// If specified, these HTTP headers will be forwarded to
    /// the relay.
    ///
    /// Example: Authentication
    ///
    /// May be specified multiple times, to send more than one header.
    #[arg(long)]
    passthrough_headers: Option<Vec<String>>,
}

/// Errors that can occur during OHTTP proxy operations.
///
/// This enum captures all possible failure modes when processing SOCKS5 requests
/// through OHTTP relays, including transport errors, encoding issues, and protocol violations.
#[derive(Error, Debug)]
pub enum OhttpProxyError {
    /// OHTTP protocol error occurred during request/response processing
    #[error("Error in OHTTP")]
    OhttpError(#[from] ohttp::Error),
    /// Binary HTTP (BHTTP) encoding/decoding error
    #[error("Error in BHTTP")]
    BhttpError(#[from] bhttp::Error),
    /// HTTP client error when communicating with relay servers
    #[error("Error in HTTP transport")]
    ReqwestError(#[from] reqwest::Error),
    /// HTTP header contains invalid value that cannot be encoded
    #[error("Invalid header value")]
    HeaderValueError(#[from] InvalidHeaderValue),
    /// HTTP header name is invalid according to HTTP specifications
    #[error("Invalid header name")]
    HeaderNameError(#[from] reqwest::header::InvalidHeaderName),
    /// String data could not be converted to proper encoding
    #[error("Invalid String Encoding")]
    StringEncodingError(#[from] ToStrError),
    /// Data is not valid UTF-8 when UTF-8 encoding was expected
    #[error("Invalid UTF-8 Encoding")]
    UTF8EncodingError(#[from] FromUtf8Error),
    /// OHTTP configuration has not been fetched or is invalid
    #[error("OHTTP is unconfigured")]
    Unconfigured,
    /// HTTP response Content-Type header does not match expected value
    #[error("Invalid Content Type: {0} != {1}")]
    ContentTypeMismatchError(String, String),
    /// HTTP data exceeds configured size limits
    #[error("Unexpectedly large HTTP data: {0}")]
    HttpTooLarge(u64),
    /// HTTP response contained no data when data was expected
    #[error("HTTP response data is empty")]
    ResponseEmpty,
    /// Input/output operation failed (file system, network, etc.)
    #[error("IO Error")]
    IOError(#[from] std::io::Error),
    /// Mutex was poisoned due to panic in another thread
    #[error("Mutex poisoned")]
    MutexPoisoned,
}

const OHTTP_REQ_TYPE: &str = "message/ohttp-req";
const OHTTP_RESP_TYPE: &str = "message/ohttp-res";
const OHTTP_CONFIG_TYPE: &str = "application/octet-stream";
const MAX_OHTTP_CONFIG_SIZE: u64 = 64 * 1024; // 64 kB
const MAX_OHTTP_RESPONSE_SIZE: u64 = 1024 * 1024; // 1MB
const SOCKS5_REQ_BUF_SIZE: usize = 64 * 1024; // 64kB

/// OHTTP SOCKS5 Proxy server implementation.
///
/// This struct manages the lifecycle of a SOCKS5 proxy server that routes traffic
/// through OHTTP relays. It handles OHTTP configuration fetching, request encryption,
/// and response decryption while maintaining SOCKS5 protocol compatibility.
pub struct OHTTPSocksProxy {
    ohttp_relay_client: Client,
    gateway_url: String,
    ohttp_config: Mutex<Option<Vec<u8>>>,
    passthrough_headers: Option<Vec<String>>,
}

impl OHTTPSocksProxy {
    fn try_new(
        gateway_url: String,
        relay_headers: Option<Vec<String>>,
        passthrough_headers: Option<Vec<String>>,
        ca_cert_path: Option<String>,
    ) -> Result<Self, OhttpProxyError> {
        let mut headers = HeaderMap::new();

        // If there are headers that should be added to the requests sent to the
        // relay, then add them in as defaults.
        if let Some(header_strings) = relay_headers {
            for header_str in header_strings {
                if let Some((name, value)) = header_str.split_once("=") {
                    let mut auth_value = HeaderValue::from_str(value)?;
                    auth_value.set_sensitive(true);
                    debug!(name, "Set relay header.");
                    headers.insert(HeaderName::from_bytes(name.as_bytes())?, auth_value);
                }
            }
        }

        let mut client_builder = ClientBuilder::new().default_headers(headers);

        if let Some(cert_path) = ca_cert_path {
            let cert_bytes = std::fs::read(&cert_path)?;
            let cert = reqwest::Certificate::from_pem(&cert_bytes)?;
            client_builder = client_builder.add_root_certificate(cert);
            info!(cert_path, "Loaded CA certificate.")
        }

        Ok(Self {
            gateway_url,
            ohttp_relay_client: client_builder.build()?,
            ohttp_config: Mutex::new(None),
            passthrough_headers,
        })
    }

    #[instrument(skip(self))]
    async fn get_configuration(&mut self, config_url: String) -> Result<(), OhttpProxyError> {
        let resp = self
            .ohttp_relay_client
            .get(&config_url)
            .send()
            .await?
            .error_for_status()?;
        if let Some(value) = resp.headers().get(CONTENT_TYPE)
            && value != OHTTP_CONFIG_TYPE
        {
            let s = value.to_str()?;
            return Err(OhttpProxyError::ContentTypeMismatchError(
                OHTTP_CONFIG_TYPE.to_string(),
                s.to_string(),
            ));
        }
        if let Some(size) = resp.content_length()
            && size > MAX_OHTTP_CONFIG_SIZE
        {
            return Err(OhttpProxyError::HttpTooLarge(size));
        }
        let ohttp_vec = resp.bytes().await?.to_vec();
        info!(config_url, ohttp_config_len=?ohttp_vec.len(), "Obtained OHTTP configuration.");

        *self
            .ohttp_config
            .lock()
            .map_err(|_| OhttpProxyError::MutexPoisoned)? = Some(ohttp_vec);
        Ok(())
    }

    fn get_ohttp_client(&self) -> Result<ClientRequest, OhttpProxyError> {
        Ok(ClientRequest::from_encoded_config(
            self.ohttp_config
                .lock()
                .map_err(|_| OhttpProxyError::MutexPoisoned)?
                .as_ref()
                .ok_or(OhttpProxyError::Unconfigured)?,
        )?)
    }

    #[instrument(skip(self, req_body))]
    async fn ohttp_tx(&self, req_body: Vec<u8>, req_headers: HeaderMap) -> Result<Vec<u8>, OhttpProxyError> {
        let resp = self
            .ohttp_relay_client
            .post(&self.gateway_url)
            .header(CONTENT_TYPE, OHTTP_REQ_TYPE)
            .headers(req_headers)
            .body(req_body)
            .send()
            .await?
            .error_for_status()?;
        if let Some(value) = resp.headers().get(CONTENT_TYPE) {
            if value != OHTTP_RESP_TYPE {
                let s = value.to_str()?;
                return Err(OhttpProxyError::ContentTypeMismatchError(
                    OHTTP_RESP_TYPE.to_string(),
                    s.to_string(),
                ));
            }
        } else {
            return Err(OhttpProxyError::ContentTypeMismatchError(
                OHTTP_RESP_TYPE.to_string(),
                "<empty>".to_string(),
            ));
        }
        if let Some(size) = resp.content_length()
            && size > MAX_OHTTP_RESPONSE_SIZE
        {
            return Err(OhttpProxyError::HttpTooLarge(size));
        }
        trace!(
            status = resp.status().as_u16(),
            content_length = resp.content_length(),
            "OHTTP Relay response."
        );
        Ok(resp.bytes().await?.to_vec())
    }

    #[instrument(skip(self, stream))]
    async fn perform_ohttp_transaction_on_stream<T>(
        &self,
        stream: &mut Stream<T>,
    ) -> Result<(), OhttpProxyError>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + Sync,
    {
        // Read the HTTP request from the SOCKS5 client
        let mut req_buf = BytesMut::with_capacity(SOCKS5_REQ_BUF_SIZE);
        stream.read_buf(&mut req_buf).await?;
        let req_msg = Message::read_http(&mut Cursor::new(req_buf))?;
        info!(
            method = req_msg
                .control()
                .method()
                .map(String::from_utf8_lossy)
                .as_deref()
                .unwrap_or("UNKNOWN"),
            path = req_msg
                .control()
                .path()
                .map(String::from_utf8_lossy)
                .as_deref()
                .unwrap_or("UNKNOWN"),
            // Authority only comes from HTTP2, and SOCKS5 doesn't support that. So
            // we're printing what we have that is reasonably anonymous.
            "HTTP request read from SOCKS5 client, forwarding using OHTTP."
        );

        let mut req_headers = HeaderMap::new();
        // Copy any passthrough headers provided
        if let Some(passthrough_headers) = &self.passthrough_headers {
            for header in passthrough_headers {
                if let Some(value) = req_msg.header().get(header.to_ascii_lowercase().as_bytes()) {
                    trace!(header, value, "Appending passthrough header");
                    req_headers.append(HeaderName::from_str(header)?, HeaderValue::from_bytes(value)?);
                }
                // TODO: Find a way to remove the header from req_msg.header()
            }
        }

        // Convert the request to Binary HTTP format
        let mut req_bhttp_vec = Vec::new();
        req_msg.write_bhttp(Mode::KnownLength, &mut req_bhttp_vec)?;

        // Encapsulate with OHTTP
        let (enc_request_vec, ohttp_tx_decoder) =
            self.get_ohttp_client()?.encapsulate(&req_bhttp_vec)?;
        trace!(
            encap_req = hex::encode(&enc_request_vec),
            "Encoded OHTTP request, encapsulated to Gateway, sending via Relay."
        );

        // Send OHTTP request, get back OHTTP response
        let ohttp_response_vec = self.ohttp_tx(enc_request_vec, req_headers).await?;
        debug!(
            encap_rsp_len = ohttp_response_vec.len(),
            "Received encapsulated OHTTP response from Gateway, via Relay."
        );

        // Decapsulate from OHTTP
        let resp_vec = ohttp_tx_decoder.decapsulate(&ohttp_response_vec)?;
        trace!(
            rsp_len = resp_vec.len(),
            "Decapsulated OHTTP response from Gateway."
        );

        // Convert the Binary HTTP format back to text
        let response = Message::read_bhttp(&mut Cursor::new(&resp_vec[..]))?;
        trace!(
            content_length = response.content().len(),
            "Decoded BHTTP response from Gateway."
        );

        // Write the HTTP request back to the SOCKS5 client
        let mut http_resp_vec = Vec::new();
        response.write_http(&mut http_resp_vec)?;
        stream.write_all(&http_resp_vec).await?;
        stream.flush().await?;
        info!(
            sent_len = http_resp_vec.len(),
            "HTTP response written to SOCKS client stream."
        );
        Ok(())
    }
}

impl Handler for OHTTPSocksProxy {
    async fn handle<T>(&self, stream: &mut Stream<T>, request: Request) -> io::Result<()>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + Sync,
    {
        trace!(?request, "Handling new SOCKS5 request.");
        match &request {
            Request::Connect(_proxy_protocol_target_addr) => {
                debug!(?request, "SOCKS5 TCP Connect requested.");
                stream.write_response_unspecified().await?;
                debug!("Unspecified response sent.");
                self.perform_ohttp_transaction_on_stream(stream)
                    .await
                    .inspect_err(|e| error!(?e, "Error in OHTTP transaction."))
                    .map_err(io::Error::other)?;
                debug!(?request, "SOCKS5 TCP transaction completed.");
            }
            Request::Associate(_) | Request::Bind(_) => {
                warn!(?request, "Unsupported SOCKS5 request.");
                stream.write_response_unsupported().await?;
            }
        }

        Ok(())
    }
}

async fn start(args: Args) -> Result<(), OhttpProxyError> {
    let mut ohttp_proxy =
        OHTTPSocksProxy::try_new(args.ohttp_relay_url, args.relay_headers, args.passthrough_headers, args.ca_cert)?;
    ohttp_proxy
        .get_configuration(args.ohttp_configuration_url)
        .await?;

    let socks5_listener = TcpListener::bind(args.socks5).await?;
    info!(
        listen_addr = ?socks5_listener.local_addr(),
        "SOCKS server listening."
    );

    let config = Config::new(NoAuthentication, ohttp_proxy);

    Server::run(socks5_listener, config.into(), async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to listen for signal.")
    })
    .await?;
    Ok(())
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let subscriber = FmtSubscriber::builder()
        .with_max_level(args.verbosity)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .expect("Setting default tracing subscriber failed.");

    match start(args).await {
        Ok(_) => info!("Exiting cleanly."),
        Err(e) => error!(?e, "Exiting with an error."),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::Server;

    /// Test successful OHTTP configuration retrieval
    #[tokio::test]
    async fn test_get_configuration_success() {
        // Create a mock server
        let mut server = Server::new_async().await;

        // Mock OHTTP configuration data (minimal valid OHTTP config)
        let mock_config = vec![0xDE, 0xAD, 0xCA, 0xFE]; // Not real

        // Set up mock endpoint
        let mock = server
            .mock("GET", "/ohttp-configs")
            .with_status(200)
            .with_header("content-type", "application/octet-stream")
            .with_header("content-length", &mock_config.len().to_string())
            .with_body(&mock_config)
            .create_async()
            .await;

        // Create proxy instance
        let mut proxy = OHTTPSocksProxy::try_new(
            server.url(),
            None, // No relay headers
            None, // No passthrough headers
            None, // No custom CA cert
        )
        .expect("Failed to create proxy");

        // Test get_configuration
        let result = proxy
            .get_configuration(format!("{}/ohttp-configs", server.url()))
            .await;

        // Verify success
        assert!(result.is_ok(), "get_configuration should succeed");

        // Verify configuration was stored
        {
            let config_guard = proxy.ohttp_config.lock().unwrap();
            assert!(config_guard.is_some(), "Configuration should be stored");
            assert_eq!(
                config_guard.as_ref().unwrap(),
                &mock_config,
                "Stored config should match mock data"
            );
        }

        // Verify mock was called
        mock.assert_async().await;
    }

    /// Test configuration retrieval with wrong content type
    #[tokio::test]
    async fn test_get_configuration_wrong_content_type() {
        let mut server = Server::new_async().await;

        let mock = server
            .mock("GET", "/ohttp-configs")
            .with_status(200)
            .with_header("content-type", "text/plain") // Wrong content type
            .with_header("content-length", "4")
            .with_body("test")
            .create_async()
            .await;

        let mut proxy =
            OHTTPSocksProxy::try_new(server.url(), None, None, None).expect("Failed to create proxy");

        let result = proxy
            .get_configuration(format!("{}/ohttp-configs", server.url()))
            .await;

        // Should fail with content type mismatch
        assert!(result.is_err(), "Should fail with wrong content type");
        match result.unwrap_err() {
            OhttpProxyError::ContentTypeMismatchError(expected, actual) => {
                assert_eq!(expected, "application/octet-stream");
                assert_eq!(actual, "text/plain");
            }
            _ => panic!("Expected ContentTypeMismatchError"),
        }

        mock.assert_async().await;
    }

    /// Test configuration retrieval with oversized response
    #[tokio::test]
    async fn test_get_configuration_too_large() {
        let mut server = Server::new_async().await;

        let large_size = MAX_OHTTP_CONFIG_SIZE + 1;
        let large_body = vec![0u8; large_size as usize]; // Body matches content-length

        let mock = server
            .mock("GET", "/ohttp-configs")
            .with_status(200)
            .with_header("content-type", "application/octet-stream")
            .with_header("content-length", &large_size.to_string())
            .with_body(&large_body)
            .create_async()
            .await;

        let mut proxy =
            OHTTPSocksProxy::try_new(server.url(), None, None, None).expect("Failed to create proxy");

        let result = proxy
            .get_configuration(format!("{}/ohttp-configs", server.url()))
            .await;

        // Should fail with HttpTooLarge error
        assert!(result.is_err(), "Should fail with oversized config");
        match result.unwrap_err() {
            OhttpProxyError::HttpTooLarge(size) => {
                assert_eq!(size, MAX_OHTTP_CONFIG_SIZE + 1);
            }
            _ => panic!("Expected HttpTooLarge error"),
        }

        mock.assert_async().await;
    }

    /// Test configuration retrieval with custom relay headers
    #[tokio::test]
    async fn test_get_configuration_with_relay_headers() {
        let mut server = Server::new_async().await;

        let mock_config = vec![0x01, 0x00, 0x20, 0x00];

        // Expect custom headers in the request
        let mock = server
            .mock("GET", "/ohttp-configs")
            .match_header("X-Auth", "secret123")
            .match_header("X-Client", "test-client")
            .with_status(200)
            .with_header("content-type", "application/octet-stream")
            .with_header("content-length", &mock_config.len().to_string())
            .with_body(&mock_config)
            .create_async()
            .await;

        // Create proxy with relay headers
        let relay_headers = vec![
            "X-Auth=secret123".to_string(),
            "X-Client=test-client".to_string(),
        ];

        let mut proxy = OHTTPSocksProxy::try_new(server.url(), Some(relay_headers), None, None)
            .expect("Failed to create proxy");

        let result = proxy
            .get_configuration(format!("{}/ohttp-configs", server.url()))
            .await;

        assert!(
            result.is_ok(),
            "get_configuration should succeed with relay headers"
        );

        // Verify configuration was stored
        {
            let config_guard = proxy.ohttp_config.lock().unwrap();
            assert!(config_guard.is_some(), "Configuration should be stored");
            assert_eq!(
                config_guard.as_ref().unwrap(),
                &mock_config,
                "Stored config should match mock data"
            );
        }

        mock.assert_async().await;
    }

    /// Test configuration retrieval with HTTP error status
    #[tokio::test]
    async fn test_get_configuration_http_error() {
        let mut server = Server::new_async().await;

        let mock = server
            .mock("GET", "/ohttp-configs")
            .with_status(418)
            .with_body("I'm a teapot")
            .create_async()
            .await;

        let mut proxy =
            OHTTPSocksProxy::try_new(server.url(), None, None, None).expect("Failed to create proxy");

        let result = proxy
            .get_configuration(format!("{}/ohttp-configs", server.url()))
            .await;

        // Should fail with HTTP error
        assert!(result.is_err(), "Should fail with 418 status");

        mock.assert_async().await;
    }
}
