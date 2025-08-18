use bhttp::{Message, Mode};
use clap::Parser;
use clap_verbosity_flag::{InfoLevel, Verbosity};
use ohttp::ClientRequest;
use reqwest::{
    Client, ClientBuilder,
    header::{CONTENT_TYPE, HeaderMap, HeaderValue, InvalidHeaderValue, ToStrError},
};
use socks_lib::{
    io::{self, AsyncRead, AsyncWrite},
    net::TcpListener,
    v5::{
        Request, Stream,
        server::{Config, Handler, Server, auth::NoAuthentication},
    },
};
use std::{io::Cursor, net::SocketAddr, string::FromUtf8Error};
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufStream};
use tracing::{debug, error, info, instrument, trace, warn};
use tracing_subscriber::FmtSubscriber;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[command(flatten)]
    verbosity: Verbosity<InfoLevel>,
    #[arg(long, default_value = "[::]:32547")]
    listen: SocketAddr,
    #[arg(long)]
    ohttp_url: String,
    #[arg(long)]
    ca_cert: String,
}

#[derive(Error, Debug)]
pub enum OhttpProxyError {
    #[error("Error in OHTTP")]
    OhttpError(#[from] ohttp::Error),
    #[error("Error in BHTTP")]
    BhttpError(#[from] bhttp::Error),
    #[error("Error in HTTP transport")]
    ReqwestError(#[from] reqwest::Error),
    #[error("Bad PAT Header")]
    HeaderError(#[from] InvalidHeaderValue),
    #[error("Invalid String Encoding")]
    StringEncodingError(#[from] ToStrError),
    #[error("Invalid UTF-8 Encoding")]
    UTF8EncodingError(#[from] FromUtf8Error),
    #[error("OHTTP is unconfigured")]
    Unconfigured,
    #[error("Invalid Content Type: {0}")]
    ContentError(String),
    #[error("IO Error")]
    IOError(#[from] std::io::Error),
}

const OHTTP_REQ_TYPE: &str = "message/ohttp-req";
const OHTTP_RESP_TYPE: &str = "message/ohttp-res";
const OHTTP_CONFIG_TYPE: &str = "application/octet-stream";

pub struct OHTTPSocksProxy {
    ohttp_relay_client: Client,
    base_url: String,
    ohttp_config: Option<Vec<u8>>,
}

impl OHTTPSocksProxy {
    fn try_new(base_url: String, pat: String) -> Result<Self, OhttpProxyError> {
        let mut headers = HeaderMap::new();
        let mut auth_value = HeaderValue::from_str(&pat)?;
        auth_value.set_sensitive(true);
        headers.insert("PAT", auth_value);

        Ok(Self {
            base_url,
            ohttp_relay_client: ClientBuilder::new().default_headers(headers).build()?,
            ohttp_config: None,
        })
    }

    #[instrument(skip(self))]
    async fn get_configuration(&mut self) -> Result<(), OhttpProxyError> {
        let url = format!("{}/ohttp-configs", self.base_url);
        let resp = self
            .ohttp_relay_client
            .get(&url)
            .send()
            .await?
            .error_for_status()?;
        if let Some(value) = resp.headers().get(CONTENT_TYPE) {
            if value != OHTTP_CONFIG_TYPE {
                let s = value.to_str()?;
                return Err(OhttpProxyError::ContentError(s.to_string()));
            }
        }
        let ohttp_vec = resp.bytes().await?.to_vec();
        info!(url, ohttp_config_len=?ohttp_vec.len(), "Obtained OHTTP configuration from relay.");
        self.ohttp_config = Some(ohttp_vec);
        Ok(())
    }

    fn get_ohttp_client(&self) -> Result<ClientRequest, OhttpProxyError> {
        Ok(ClientRequest::from_encoded_config(
            &self
                .ohttp_config
                .clone()
                .ok_or(OhttpProxyError::Unconfigured)?,
        )?)
    }

    #[instrument(skip(self, req_body))]
    async fn ohttp_tx(&self, req_body: Vec<u8>) -> Result<Vec<u8>, OhttpProxyError> {
        let resp = self
            .ohttp_relay_client
            .post(format!("{}/gateway", self.base_url))
            .header(CONTENT_TYPE, OHTTP_REQ_TYPE)
            .body(req_body)
            .send()
            .await?
            .error_for_status()?;
        if let Some(value) = resp.headers().get(CONTENT_TYPE) {
            if value != OHTTP_RESP_TYPE {
                let s = value.to_str()?;
                return Err(OhttpProxyError::ContentError(s.to_string()));
            }
        }
        trace!(?resp, "OHTTP gateway response");
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
        let mut buffered_stream = BufStream::with_capacity(8 * 1024, 8 * 1024, stream);
        let mut read_cursor = Cursor::new(buffered_stream.fill_buf().await?);
        let req_msg = Message::read_http(&mut read_cursor)?;
        trace!(?req_msg, "HTTP message read");
        let mut req_vec = Vec::new();
        req_msg
            .write_bhttp(Mode::KnownLength, &mut req_vec)
            .unwrap();
        let (enc_request_vec, ohttp_tx_decoder) = self.get_ohttp_client()?.encapsulate(&req_vec)?;

        trace!(encap_req=?enc_request_vec, "Encoded encapsulated OHTTP request");
        let ohttp_response_vec = self.ohttp_tx(enc_request_vec).await?;
        debug!(
            encap_rsp_len = ohttp_response_vec.len(),
            "Received encapsulated OHTTP response"
        );
        let resp_vec = ohttp_tx_decoder.decapsulate(&ohttp_response_vec)?;
        trace!(rsp_len = resp_vec.len(), "Decapsulated OHTTP response");
        let response = Message::read_bhttp(&mut Cursor::new(&resp_vec[..]))?;
        trace!(?response, "Decoded BHTTP response");
        let mut http_resp_vec = Vec::new();
        response.write_http(&mut http_resp_vec)?;
        buffered_stream.write_all(&http_resp_vec).await?;
        buffered_stream.flush().await?;
        debug!(
            sent_len = http_resp_vec.len(),
            "HTTP Response written to SOCKS stream"
        );
        Ok(())
    }
}

impl Handler for OHTTPSocksProxy {
    async fn handle<T>(&self, stream: &mut Stream<T>, request: Request) -> io::Result<()>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + Sync,
    {
        trace!(?request, "Handling new SOCKS5 request");
        match &request {
            Request::Connect(_proxy_protocol_target_addr) => {
                debug!(?request, "SOCKS5 TCP Connect requested");
                stream.write_response_unspecified().await?;
                debug!("Unspecified response sent");
                self.perform_ohttp_transaction_on_stream(stream)
                    .await
                    .inspect_err(|e| error!(?e, "Caught error in OHTTP transaction"))
                    .map_err(io::Error::other)?;
                debug!(?request, "TCP Connect completed")
            }
            Request::Associate(_) | Request::Bind(_) => {
                warn!(?request, "Unsupported SOCKS5 request");
                stream.write_response_unsupported().await?;
            }
        }

        Ok(())
    }
}

async fn start(args: Args) -> Result<(), OhttpProxyError> {
    let mut ohttp_proxy = OHTTPSocksProxy::try_new(args.ohttp_url, "secret".to_string())?;
    ohttp_proxy.get_configuration().await?;

    let listener = TcpListener::bind(args.listen).await.unwrap();
    info!(
        "SOCKS server listening on {}",
        listener.local_addr().unwrap()
    );

    let config = Config::new(NoAuthentication, ohttp_proxy);

    Server::run(listener, config.into(), async {
        tokio::signal::ctrl_c().await.unwrap();
    })
    .await
    .unwrap();
    Ok(())
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let subscriber = FmtSubscriber::builder()
        .with_max_level(args.verbosity)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    start(args).await.unwrap();
}
