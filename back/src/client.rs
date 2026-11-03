//! The identity and network origin of a caller, attached to every audit event.
use axum::extract::{ConnectInfo, Request};
use std::net::{IpAddr, SocketAddr};

#[derive(Clone, Debug)]
pub struct Actor {
    /// `admin:<email>` or `token:<id> (<token name>)`.
    pub subject: String,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
}

impl Actor {
    pub fn new(subject: String, request: &Request, trust_proxy: bool) -> Self {
        Self {
            subject,
            ip: client_ip(request, trust_proxy),
            user_agent: request
                .headers()
                .get("user-agent")
                .and_then(|v| v.to_str().ok())
                .map(|ua| ua.chars().take(200).collect()),
        }
    }
}

/// The socket peer, unless Keystone runs behind a reverse proxy it trusts
/// (`KEYSTONE_TRUST_PROXY=true`). Then the last `X-Forwarded-For` hop, the address that proxy saw.
/// Never trust the header without a proxy: any client could write any address into it.
pub fn client_ip(request: &Request, trust_proxy: bool) -> Option<String> {
    if trust_proxy {
        let forwarded = request
            .headers()
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.rsplit(',').next())
            .map(str::trim)
            .and_then(|ip| ip.parse::<IpAddr>().ok());
        if let Some(ip) = forwarded {
            return Some(ip.to_string());
        }
    }
    request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0.ip().to_string())
}
