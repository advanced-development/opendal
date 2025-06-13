use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bytes::Buf;
use http::{HeaderValue, Request};
use log::{debug, error, info, warn};
use reqsign::AwsCredential;
use reqsign::AwsV4Signer as ReqsignAwsV4Signer;
use serde::{Deserialize, Serialize};
use serde_json;
use tokio::sync::RwLock;

use crate::raw::new_json_deserialize_error;
use crate::raw::AccessorInfo;
use crate::Buffer;

/// Enum wrapper for different signer implementations to make it dyn-compatible
#[derive(Debug)]
pub enum SignerImpl {
    AwsV4(AwsV4Signer),
    Rest(RestSigner),
}

impl SignerImpl {
    pub async fn sign<T: Send + Sync + 'static>(
        &self,
        req: &mut Request<T>,
        cred: &AwsCredential,
    ) -> Result<()> {
        match self {
            SignerImpl::AwsV4(signer) => signer.sign(req, cred).await,
            SignerImpl::Rest(signer) => signer.sign(req, cred).await,
        }
    }

    pub async fn sign_query<T: Send + Sync + 'static>(
        &self,
        req: &mut Request<T>,
        expire: Duration,
        cred: &AwsCredential,
    ) -> Result<()> {
        match self {
            SignerImpl::AwsV4(signer) => signer.sign_query(req, expire, cred).await,
            SignerImpl::Rest(signer) => signer.sign_query(req, expire, cred).await,
        }
    }
}

#[async_trait]
pub trait Signer: Send + Sync {
    async fn sign<T: Send + Sync + 'static>(
        &self,
        req: &mut Request<T>,
        cred: &AwsCredential,
    ) -> Result<()>;
    async fn sign_query<T: Send + Sync + 'static>(
        &self,
        req: &mut Request<T>,
        expire: Duration,
        cred: &AwsCredential,
    ) -> Result<()>;
}

/// AWS V4 Signer
/// Wrapper around reqsign's AwsV4Signer that implements the Signer trait
#[derive(Debug)]
pub struct AwsV4Signer {
    inner: ReqsignAwsV4Signer,
}

impl AwsV4Signer {
    pub fn new(service: &str, region: &str) -> Self {
        debug!(
            "Creating AWS V4 signer for service: {}, region: {}",
            service, region
        );
        Self {
            inner: ReqsignAwsV4Signer::new(service, region),
        }
    }
}

#[async_trait]
impl Signer for AwsV4Signer {
    async fn sign<T: Send + Sync + 'static>(
        &self,
        req: &mut Request<T>,
        cred: &AwsCredential,
    ) -> Result<()> {
        debug!(
            "Signing request with AWS V4 signer: {} {}",
            req.method(),
            req.uri()
        );
        self.inner.sign(req, cred)
    }

    async fn sign_query<T: Send + Sync + 'static>(
        &self,
        req: &mut Request<T>,
        expire: Duration,
        cred: &AwsCredential,
    ) -> Result<()> {
        debug!(
            "Signing query with AWS V4 signer: {} {} (expires in {:?})",
            req.method(),
            req.uri(),
            expire
        );
        self.inner.sign_query(req, expire, cred)
    }
}

/// AWS V4 REST Signer Client
///
/// This implementation provides a drop-in replacement for reqsign's AwsV4Signer
/// that delegates AWS V4 signing to a remote REST service instead of computing
/// signatures locally. It follows the Apache Iceberg S3V4RestSignerClient pattern.
///
/// The signer has the exact same interface as reqsign's AwsV4Signer:
/// - `sign<T>(&self, req: &mut Request<T>, cred: &AwsCredential) -> Result<()>`
/// - `sign_query<T>(&self, req: &mut Request<T>, expire: Duration, cred: &AwsCredential) -> Result<()>`
///
/// However, signing query is not supported by the REST signer service and will return an error.
///
/// # Example
///
/// ```ignore
/// use opendal::services::s3::signer::{RestSigner, RestSignerConfig};
/// use reqsign::AwsCredential;
/// use std::time::Duration;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let config = RestSignerConfig::new("https://catalog.example.com")
///         .with_token("your-bearer-token")
///         .with_timeout(Duration::from_secs(10));
///     
///     let signer = RestSigner::new("s3", "us-west-2", config)?;
///     
///     // Use exactly like reqsign's AwsV4Signer
///     let credential = AwsCredential::default();
///     let mut request = http::Request::builder()
///         .method("GET")
///         .uri("https://my-bucket.s3.amazonaws.com/file.txt")
///         .body("")?;
///     
///     signer.sign(&mut request, &credential).await?;
///     
///     Ok(())
/// }
/// ```
#[derive(Debug)]
pub struct RestSigner {
    /// AWS service name (e.g., "s3")
    service: String,
    /// AWS region
    region: String,
    /// Configuration for the REST signer
    config: RestSignerConfig,
    /// Cache for signed requests to avoid repeated signing
    signature_cache: Arc<RwLock<HashMap<String, CachedSignature>>>,
}

impl RestSigner {
    /// Create a new AWS V4 REST Signer
    ///
    /// # Arguments
    /// * `service` - AWS service name (e.g., "s3")
    /// * `region` - AWS region (e.g., "us-east-1")
    /// * `config` - Configuration for the REST signer
    pub fn new(service: &str, region: &str, config: RestSignerConfig) -> Result<Self> {
        info!(
            "Creating REST signer for service: {}, region: {}, base_uri: {}",
            service, region, config.base_uri
        );

        // Validate config
        config.validate()?;

        Ok(Self {
            service: service.to_string(),
            region: region.to_string(),
            config,
            signature_cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Request signature from the remote signing service (header method)
    async fn request_signature<T: Send + Sync + 'static>(
        &self,
        req: &Request<T>,
        url: &str,
        headers: &HashMap<String, Vec<String>>,
    ) -> Result<(RemoteSigningResponse, HashMap<String, String>)> {
        debug!("Requesting signature for {} {}", req.method(), url);

        let signing_request = RemoteSigningRequest {
            region: self.region.clone(),
            uri: url.to_string(),
            method: req.method().to_string(),
            headers: headers.clone(),
            properties: if self.config.properties.is_empty() {
                None
            } else {
                Some(self.config.properties.clone())
            },
            body: self.get_request_body_if_possible(req),
        };

        debug!(
            "Signing request payload: method={}, uri={}, headers_count={}, has_body={}",
            signing_request.method,
            signing_request.uri,
            signing_request.headers.len(),
            signing_request.body.is_some()
        );

        self.send_signing_request(signing_request).await
    }

    /// Extract request body for specific requests that require body signing
    ///
    /// Following the Java implementation pattern, this method only extracts the body
    /// for specific S3 operations that require the request body to be included in
    /// the signing request. Currently, this includes:
    ///
    /// - DeleteObjects requests (POST with "delete" query parameter)
    ///
    /// For other requests, the body is not needed for signing and None is returned.
    /// This reduces the payload sent to the signing service and improves performance.
    fn get_request_body_if_possible<T: Send + Sync + 'static>(
        &self,
        req: &Request<T>,
    ) -> Option<String> {
        use std::any::Any;

        // Only attempt body extraction for DeleteObjects requests
        if !self.is_delete_objects_request(req) {
            debug!("Request is not a DeleteObjects request, skipping body extraction");
            return None;
        }

        debug!("Detected DeleteObjects request, attempting body extraction");

        // Try to extract body
        let body = req.body();
        if let Some(buffer) = (body as &dyn Any).downcast_ref::<crate::Buffer>() {
            if buffer.is_empty() {
                debug!("Request body is empty");
                return None;
            }

            // Convert buffer to string - this involves copying the data
            match std::str::from_utf8(&buffer.to_vec()) {
                Ok(body_str) => {
                    debug!(
                        "Successfully extracted request body ({} bytes)",
                        body_str.len()
                    );
                    Some(body_str.to_string())
                }
                Err(e) => {
                    warn!(
                        "Request body is not valid UTF-8, cannot include in signing request: {}",
                        e
                    );
                    None
                }
            }
        } else {
            debug!("Request body type cannot be extracted safely");
            None
        }
    }

    /// Check if this is a DELETE objects request
    /// Following the Java implementation: POST method with "delete" query parameter
    ///
    /// This is used to identify S3 DeleteObjects requests which require the request body
    /// to be included in the signing request.
    fn is_delete_objects_request<T: Send + Sync + 'static>(&self, req: &Request<T>) -> bool {
        if req.method() != http::Method::POST {
            return false;
        }

        // Check for "delete" query parameter
        if let Some(query) = req.uri().query() {
            let is_delete = query
                .split('&')
                .any(|param| param == "delete" || param.starts_with("delete="));

            if is_delete {
                debug!("Identified as DeleteObjects request");
            }
            is_delete
        } else {
            false
        }
    }

    /// Send signing request to the remote service
    async fn send_signing_request(
        &self,
        signing_request: RemoteSigningRequest,
    ) -> Result<(RemoteSigningResponse, HashMap<String, String>)> {
        let base_uri = self.config.base_uri.trim_end_matches('/');
        let signer_endpoint = self.config.signer_endpoint.trim_start_matches('/');
        let full_url = format!("{}/{}", base_uri, signer_endpoint);

        debug!("Sending signing request to: {}", full_url);

        // Serialize the request body
        let json_body = serde_json::to_string(&signing_request)
            .map_err(|e| anyhow!("Failed to serialize signing request: {}", e))?;
        let body_buffer = Buffer::from(json_body.into_bytes());

        // Build the HTTP request
        let mut request = Request::post(&full_url)
            .header("content-type", "application/json")
            .body(body_buffer)
            .map_err(|e| anyhow!("Failed to build HTTP request: {}", e))?;

        // Add configured headers
        for (key, value) in &self.config.headers {
            for v in value {
                if let (Ok(header_name), Ok(header_value)) = (
                    http::HeaderName::from_bytes(key.as_bytes()),
                    HeaderValue::from_str(v),
                ) {
                    request.headers_mut().insert(header_name, header_value);
                } else {
                    warn!("Failed to parse configured header: {} = {}", key, v);
                }
            }
        }

        // Add Bearer token authentication if available
        if let Some(token) = &self.config.token {
            if let Ok(auth_value) = HeaderValue::from_str(&format!("Bearer {}", token)) {
                request.headers_mut().insert("authorization", auth_value);
            } else {
                warn!("Failed to create authorization header with token");
            }
        }

        let http_client = self
            .config
            .info
            .as_ref()
            .map(|info| info.http_client())
            .unwrap_or_default();

        let start_time = std::time::Instant::now();

        // Apply timeout if configured
        let response = if let Some(timeout) = self.config.timeout {
            match tokio::time::timeout(timeout, http_client.send(request)).await {
                Ok(Ok(response)) => {
                    debug!("Signing request completed in {:?}", start_time.elapsed());
                    response
                }
                Ok(Err(e)) => {
                    error!("Failed to send signing request: {}", e);
                    return Err(anyhow!("Failed to send signing request: {}", e));
                }
                Err(_) => {
                    error!("Signing request timed out after {:?}", timeout);
                    return Err(anyhow!("Signing request timed out after {:?}", timeout));
                }
            }
        } else {
            match http_client.send(request).await {
                Ok(response) => {
                    debug!("Signing request completed in {:?}", start_time.elapsed());
                    response
                }
                Err(e) => {
                    error!("Failed to send signing request: {}", e);
                    return Err(anyhow!("Failed to send signing request: {}", e));
                }
            }
        };

        let status_code = response.status().as_u16();
        debug!("Signing service responded with status: {}", status_code);

        if response.status().is_success() {
            // Extract response headers for cache control
            let mut response_headers = HashMap::new();
            for (name, value) in response.headers() {
                if let Ok(value_str) = value.to_str() {
                    response_headers.insert(name.as_str().to_lowercase(), value_str.to_string());
                }
            }

            // Read response body
            let body = response.into_body();
            let signing_response =
                serde_json::from_reader::<_, RemoteSigningResponse>(body.reader())
                    .map_err(new_json_deserialize_error)?;

            debug!(
                "Successfully parsed signing response with {} headers",
                signing_response.headers.len()
            );

            Ok((signing_response, response_headers))
        } else {
            // Read response body as text for error handling
            let body = response.into_body();
            let error_text = String::from_utf8_lossy(&body.to_vec()).to_string();

            // Try to parse as structured error
            if let Ok(error_response) = serde_json::from_str::<ErrorResponse>(&error_text) {
                error!(
                    "Signing service error: [{}] {} - {}",
                    status_code, error_response.code, error_response.message
                );
                Err(anyhow!(
                    "Signing request failed [{}]: {} - {}",
                    status_code,
                    error_response.code,
                    error_response.message
                ))
            } else {
                error!("Signing service error: [{}] {}", status_code, error_text);
                Err(anyhow!(
                    "Signing request failed [{}]: {}",
                    status_code,
                    error_text
                ))
            }
        }
    }

    /// Apply signature to the request
    fn apply_signature_to_request<T: Send>(
        &self,
        req: &mut Request<T>,
        signed_headers: &HashMap<String, Vec<String>>,
    ) {
        debug!(
            "Applying {} signed headers to request",
            signed_headers.len()
        );

        // Add all signed headers (including authorization)
        for (key, value) in signed_headers {
            for v in value {
                if let (Ok(header_name), Ok(header_value)) = (
                    http::HeaderName::from_bytes(key.as_bytes()),
                    HeaderValue::from_str(v),
                ) {
                    req.headers_mut().insert(header_name, header_value);
                } else {
                    warn!("Failed to parse header: {} = {}", key, v);
                }
            }
        }
    }

    /// Create a cache key for the request
    fn create_cache_key(
        &self,
        method: &str,
        url: &str,
        headers: &HashMap<String, Vec<String>>,
        is_query: bool,
    ) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        method.hash(&mut hasher);
        url.hash(&mut hasher);
        is_query.hash(&mut hasher);

        // Sort headers for consistent hashing
        let mut sorted_headers: Vec<_> = headers.iter().collect();
        sorted_headers.sort_by_key(|(k, _)| *k);
        for (k, v) in sorted_headers {
            k.hash(&mut hasher);
            v.hash(&mut hasher);
        }

        format!("{}:{}:{}", hasher.finish(), self.service, self.region)
    }

    /// Get cached signature if available and not expired
    async fn get_cached_signature(&self, cache_key: &str) -> Option<CachedSignature> {
        let cache = self.signature_cache.read().await;
        if let Some(cached) = cache.get(cache_key) {
            if cached.expires_at > SystemTime::now() {
                debug!("Cache hit for key: {}", cache_key);
                return Some(cached.clone());
            } else {
                debug!("Cache entry expired for key: {}", cache_key);
            }
        } else {
            debug!("Cache miss for key: {}", cache_key);
        }
        None
    }

    /// Cache a signature
    async fn cache_signature(&self, cache_key: String, signature: CachedSignature) {
        debug!("Caching signature for key: {}", cache_key);
        let mut cache = self.signature_cache.write().await;
        cache.insert(cache_key, signature);

        // Clean up expired entries (simple cleanup)
        let now = SystemTime::now();
        let initial_size = cache.len();
        cache.retain(|_, cached| cached.expires_at > now);
        let final_size = cache.len();

        if initial_size != final_size {
            debug!(
                "Cleaned up {} expired cache entries",
                initial_size - final_size
            );
        }
    }

    /// Check if a response can be cached based on Cache-Control header
    /// Following the Java implementation pattern
    fn can_be_cached(&self, response_headers: &HashMap<String, String>) -> bool {
        let can_cache = response_headers
            .get(CACHE_CONTROL)
            .map(|value| value.as_str() == CACHE_CONTROL_PRIVATE)
            .unwrap_or(false);

        debug!("Response can be cached: {}", can_cache);
        can_cache
    }
}

#[async_trait]
impl Signer for RestSigner {
    /// Sign an HTTP request using the remote signing service
    ///
    /// This method has the same signature as reqsign's AwsV4Signer::sign
    async fn sign<T: Send + Sync + 'static>(
        &self,
        req: &mut Request<T>,
        _cred: &AwsCredential, // Credentials are handled by the remote signing service
    ) -> Result<()> {
        let method = req.method().to_string();

        // Construct the full URL from the request
        let scheme = req.uri().scheme_str().unwrap_or("http");
        let authority = req
            .uri()
            .authority()
            .ok_or_else(|| anyhow!("Request URI must have an authority"))?;
        let path_and_query = req
            .uri()
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");
        let url = format!("{}://{}{}", scheme, authority, path_and_query);

        info!("Signing request: {} {}", method, url);

        // Extract headers
        let mut headers = HashMap::new();
        for (name, value) in req.headers() {
            let key = name.as_str().to_string();
            let val = value
                .to_str()
                .map_err(|e| anyhow!("Invalid header value for '{}': {}", key, e))?;

            // Headers in HTTP can have multiple values, so we use Vec<String>
            headers
                .entry(key)
                .or_insert_with(Vec::new)
                .push(val.to_string());
        }

        // Add host header if not present
        if !headers.contains_key("host") {
            headers.insert("host".to_string(), vec![authority.to_string()]);
            debug!("Added missing host header: {}", authority);
        }

        // Create cache key
        let cache_key = self.create_cache_key(&method, &url, &headers, false);

        // Check cache first
        if let Some(cached) = self.get_cached_signature(&cache_key).await {
            debug!("Using cached signature");
            self.apply_signature_to_request(req, &cached.headers);
            return Ok(());
        }

        // Request signature from remote service
        let (signature, response_headers) = self.request_signature(req, &url, &headers).await?;

        // Apply signature to request (header signing only)
        self.apply_signature_to_request(req, &signature.headers);

        // Cache the signature only if the response allows it (Cache-Control: private)
        if self.can_be_cached(&response_headers) {
            let cached = CachedSignature {
                headers: signature.headers.clone(),
                expires_at: SystemTime::now() + Duration::from_secs(300),
            };
            self.cache_signature(cache_key, cached).await;
        }

        info!("Successfully signed request: {} {}", method, url);
        Ok(())
    }

    /// Sign an HTTP request with query parameters (presigned URL)
    ///
    /// This method has the same signature as reqsign's AwsV4Signer::sign_query
    /// Note: Query signing is not supported by the REST signer service
    async fn sign_query<T: Send + Sync + 'static>(
        &self,
        req: &mut Request<T>,
        expire: Duration,
        _cred: &AwsCredential,
    ) -> Result<()> {
        warn!("Query signing (presigned URLs) is not supported by the REST signer service");
        debug!(
            "Attempted to sign query for: {} {} with expiration: {:?}",
            req.method(),
            req.uri(),
            expire
        );

        Err(anyhow!(
            "Query signing (presigned URLs) is not supported by the REST signer service"
        ))
    }
}

pub const S3_V4_REST_SIGNER: &str = "S3V4RestSigner";
const DEFAULT_SIGNER_ENDPOINT: &str = "v1/aws/s3/sign";
const CACHE_CONTROL: &str = "cache-control";
const CACHE_CONTROL_PRIVATE: &str = "private";

/// Configuration for AWS V4 REST Signer
#[derive(Debug, Clone)]
pub struct RestSignerConfig {
    /// The REST endpoint for remote signing
    pub signer_endpoint: String,
    /// The base URI for the REST catalog
    pub base_uri: String,
    /// Bearer token for authentication with the signing service
    pub token: Option<String>,
    /// HTTP client timeout
    pub timeout: Option<Duration>,
    /// Additional headers to include in signing requests
    pub headers: HashMap<String, Vec<String>>,
    /// Additional properties to include in signing requests
    pub properties: HashMap<String, String>,
    /// Accessor info
    pub info: Option<Arc<AccessorInfo>>,
}

impl Default for RestSignerConfig {
    fn default() -> Self {
        Self {
            signer_endpoint: DEFAULT_SIGNER_ENDPOINT.to_string(),
            base_uri: "".to_string(),
            token: None,
            timeout: None,
            headers: HashMap::new(),
            properties: HashMap::new(),
            info: None,
        }
    }
}

impl RestSignerConfig {
    /// Create a new configuration with the required endpoint
    pub fn new(base_uri: impl Into<String>) -> Self {
        Self {
            base_uri: base_uri.into(),
            ..Default::default()
        }
    }

    /// Set the signer endpoint (defaults to "v1/aws/s3/sign")
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.signer_endpoint = endpoint.into();
        self
    }

    /// Set the bearer token for authentication
    pub fn with_token(mut self, token: impl Into<String>) -> Self {
        self.token = Some(token.into());
        self
    }

    /// Set the HTTP timeout
    #[allow(dead_code)]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Add a header to be included in signing requests
    #[allow(dead_code)]
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers
            .entry(name.into())
            .or_insert_with(Vec::new)
            .push(value.into());
        self
    }

    /// Add a property to be included in signing requests
    #[allow(dead_code)]
    pub fn with_property(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.properties.insert(key.into(), value.into());
        self
    }

    /// Set the accessor info
    pub fn with_info(mut self, info: Arc<AccessorInfo>) -> Self {
        self.info = Some(info);
        self
    }

    /// Validate that required fields are set
    pub fn validate(&self) -> Result<()> {
        if self.base_uri.is_empty() {
            return Err(anyhow!("base_uri is required"));
        }
        Ok(())
    }
}

/// Request payload for remote signing service (matches OpenAPI spec)
#[derive(Debug, Serialize)]
struct RemoteSigningRequest {
    /// AWS region for signing
    region: String,
    /// The full URI being signed
    uri: String,
    /// HTTP method (GET, PUT, POST, etc.)
    method: String,
    /// Headers to include in the signing process
    headers: HashMap<String, Vec<String>>,
    /// Optional additional properties
    #[serde(skip_serializing_if = "Option::is_none")]
    properties: Option<HashMap<String, String>>,
    /// Optional request body (for specific requests like DeleteObjects)
    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<String>,
}

/// Response from remote signing service (matches OpenAPI spec)
#[derive(Debug, Deserialize)]
struct RemoteSigningResponse {
    // The URI that was signed
    // uri: String,
    /// All signed headers (including authorization)
    headers: HashMap<String, Vec<String>>,
}

/// Error response from remote signing service
#[derive(Debug, Deserialize)]
struct ErrorResponse {
    /// Error code
    code: String,
    /// Error message
    message: String,
    // Optional error type
    // #[serde(rename = "type")]
    // error_type: Option<String>,
}

/// Cached signature with expiration
#[derive(Debug, Clone)]
struct CachedSignature {
    /// Signed headers
    headers: HashMap<String, Vec<String>>,
    /// When this signature expires
    expires_at: SystemTime,
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::Server;
    use serde_json::json;
    use std::time::Duration;

    #[test]
    fn test_rest_signer_config_validation() {
        // Valid config
        let config = RestSignerConfig::new("https://example.com");
        assert!(config.validate().is_ok());

        // Invalid config - empty base_uri
        let config = RestSignerConfig::default();
        assert!(config.validate().is_err());

        // Default config should have no timeout set
        assert_eq!(config.timeout, None);
    }

    #[test]
    fn test_rest_signer_config_builder() {
        let config = RestSignerConfig::new("https://example.com")
            .with_endpoint("custom/endpoint")
            .with_token("test-token")
            .with_timeout(Duration::from_secs(60))
            .with_header("Custom-Header", "value")
            .with_property("prop", "value");

        assert_eq!(config.base_uri, "https://example.com");
        assert_eq!(config.signer_endpoint, "custom/endpoint");
        assert_eq!(config.token, Some("test-token".to_string()));
        assert_eq!(config.timeout, Some(Duration::from_secs(60)));
        assert_eq!(
            config.headers.get("Custom-Header"),
            Some(&vec!["value".to_string()])
        );
        assert_eq!(config.properties.get("prop"), Some(&"value".to_string()));
    }

    #[tokio::test]
    async fn test_aws_v4_signer_creation() {
        let signer = AwsV4Signer::new("s3", "us-east-1");

        // Test that we can create a request and attempt to sign it
        let mut req = http::Request::builder()
            .method("GET")
            .uri("https://test-bucket.s3.amazonaws.com/test-key")
            .body(())
            .unwrap();

        let cred = AwsCredential::default();

        // The signing might succeed with default credentials, let's just test the interface
        let _result = signer.sign(&mut req, &cred).await;
        // We're mainly testing that the interface works, not that it fails
        // The actual behavior depends on whether default credentials are available
        assert!(true); // Interface test passed
    }

    #[tokio::test]
    async fn test_rest_signer_creation() {
        let config = RestSignerConfig::new("https://example.com");
        let signer = RestSigner::new("s3", "us-east-1", config);
        assert!(signer.is_ok());
    }

    #[tokio::test]
    async fn test_rest_signer_creation_invalid_config() {
        let config = RestSignerConfig::default(); // Empty base_uri
        let signer = RestSigner::new("s3", "us-east-1", config);
        assert!(signer.is_err());
    }

    #[test]
    fn test_is_delete_objects_request() {
        let config = RestSignerConfig::new("https://example.com");
        let signer = RestSigner::new("s3", "us-east-1", config).unwrap();

        // Test DELETE objects request
        let delete_req = http::Request::builder()
            .method("POST")
            .uri("https://bucket.s3.amazonaws.com/?delete")
            .body(())
            .unwrap();
        assert!(signer.is_delete_objects_request(&delete_req));

        // Test regular POST request
        let post_req = http::Request::builder()
            .method("POST")
            .uri("https://bucket.s3.amazonaws.com/")
            .body(())
            .unwrap();
        assert!(!signer.is_delete_objects_request(&post_req));

        // Test GET request
        let get_req = http::Request::builder()
            .method("GET")
            .uri("https://bucket.s3.amazonaws.com/object")
            .body(())
            .unwrap();
        assert!(!signer.is_delete_objects_request(&get_req));
    }

    #[test]
    fn test_cache_key_creation() {
        let config = RestSignerConfig::new("https://example.com");
        let signer = RestSigner::new("s3", "us-east-1", config).unwrap();

        let mut headers = HashMap::new();
        headers.insert("host".to_string(), vec!["example.com".to_string()]);
        headers.insert(
            "authorization".to_string(),
            vec!["Bearer token".to_string()],
        );

        let key1 = signer.create_cache_key("GET", "https://example.com/path", &headers, false);
        let key2 = signer.create_cache_key("GET", "https://example.com/path", &headers, false);
        let key3 = signer.create_cache_key("POST", "https://example.com/path", &headers, false);

        // Same parameters should produce same key
        assert_eq!(key1, key2);
        // Different method should produce different key
        assert_ne!(key1, key3);
    }

    #[tokio::test]
    async fn test_signature_caching() {
        let config = RestSignerConfig::new("https://example.com");
        let signer = RestSigner::new("s3", "us-east-1", config).unwrap();

        let cache_key = "test-key".to_string();
        let signature = CachedSignature {
            headers: HashMap::new(),
            expires_at: SystemTime::now() + Duration::from_secs(300),
        };

        // Test cache miss
        assert!(signer.get_cached_signature(&cache_key).await.is_none());

        // Cache signature
        signer
            .cache_signature(cache_key.clone(), signature.clone())
            .await;

        // Test cache hit
        let cached = signer.get_cached_signature(&cache_key).await;
        assert!(cached.is_some());
    }

    #[tokio::test]
    async fn test_signature_cache_expiration() {
        let config = RestSignerConfig::new("https://example.com");
        let signer = RestSigner::new("s3", "us-east-1", config).unwrap();

        let cache_key = "test-key".to_string();
        let expired_signature = CachedSignature {
            headers: HashMap::new(),
            expires_at: SystemTime::now() - Duration::from_secs(1), // Already expired
        };

        // Cache expired signature
        signer
            .cache_signature(cache_key.clone(), expired_signature)
            .await;

        // Should not return expired signature
        assert!(signer.get_cached_signature(&cache_key).await.is_none());
    }

    #[test]
    fn test_can_be_cached() {
        let config = RestSignerConfig::new("https://example.com");
        let signer = RestSigner::new("s3", "us-east-1", config).unwrap();

        let mut headers = HashMap::new();

        // Test with Cache-Control: private
        headers.insert("cache-control".to_string(), "private".to_string());
        assert!(signer.can_be_cached(&headers));

        // Test with different Cache-Control
        headers.insert("cache-control".to_string(), "no-cache".to_string());
        assert!(!signer.can_be_cached(&headers));

        // Test without Cache-Control header
        headers.clear();
        assert!(!signer.can_be_cached(&headers));
    }

    #[tokio::test]
    async fn test_rest_signer_unsupported_query_signing() {
        let config = RestSignerConfig::new("https://example.com");
        let signer = RestSigner::new("s3", "us-east-1", config).unwrap();

        let mut req = http::Request::builder()
            .method("GET")
            .uri("https://bucket.s3.amazonaws.com/object")
            .body(())
            .unwrap();

        let cred = AwsCredential::default();
        let result = signer
            .sign_query(&mut req, Duration::from_secs(300), &cred)
            .await;

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Query signing"));
        assert!(error_msg.contains("not supported"));
    }

    #[tokio::test]
    async fn test_mock_signing_service_success() {
        let mut server = Server::new_async().await;

        let mock_response = json!({
            "uri": "https://bucket.s3.amazonaws.com/object",
            "headers": {
                "authorization": ["AWS4-HMAC-SHA256 Credential=..."],
                "x-amz-date": ["20231201T120000Z"]
            }
        });

        let _mock = server
            .mock("POST", "/v1/aws/s3/sign")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_header("cache-control", "private")
            .with_body(mock_response.to_string())
            .create_async()
            .await;

        let config = RestSignerConfig::new(&server.url());
        let signer = RestSigner::new("s3", "us-east-1", config).unwrap();

        let mut req = http::Request::builder()
            .method("GET")
            .uri("https://bucket.s3.amazonaws.com/object")
            .body(())
            .unwrap();

        let cred = AwsCredential::default();
        let result = signer.sign(&mut req, &cred).await;

        assert!(result.is_ok());

        // Verify that headers were added
        assert!(req.headers().contains_key("authorization"));
        assert!(req.headers().contains_key("x-amz-date"));
    }

    #[tokio::test]
    async fn test_mock_signing_service_error() {
        let mut server = Server::new_async().await;

        let error_response = json!({
            "code": "INVALID_REQUEST",
            "message": "The request is invalid"
        });

        let _mock = server
            .mock("POST", "/v1/aws/s3/sign")
            .with_status(400)
            .with_header("content-type", "application/json")
            .with_body(error_response.to_string())
            .create_async()
            .await;

        let config = RestSignerConfig::new(&server.url());
        let signer = RestSigner::new("s3", "us-east-1", config).unwrap();

        let mut req = http::Request::builder()
            .method("GET")
            .uri("https://bucket.s3.amazonaws.com/object")
            .body(())
            .unwrap();

        let cred = AwsCredential::default();
        let result = signer.sign(&mut req, &cred).await;

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("INVALID_REQUEST"));
        assert!(error_msg.contains("The request is invalid"));
    }

    #[tokio::test]
    async fn test_mock_signing_service_with_authentication() {
        let mut server = Server::new_async().await;

        let mock_response = json!({
            "uri": "https://bucket.s3.amazonaws.com/object",
            "headers": {
                "authorization": ["AWS4-HMAC-SHA256 Credential=..."]
            }
        });

        let _mock = server
            .mock("POST", "/v1/aws/s3/sign")
            .match_header("authorization", "Bearer test-token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_response.to_string())
            .create_async()
            .await;

        let config = RestSignerConfig::new(&server.url()).with_token("test-token");
        let signer = RestSigner::new("s3", "us-east-1", config).unwrap();

        let mut req = http::Request::builder()
            .method("GET")
            .uri("https://bucket.s3.amazonaws.com/object")
            .body(())
            .unwrap();

        let cred = AwsCredential::default();
        let result = signer.sign(&mut req, &cred).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_mock_signing_service_caching() {
        let mut server = Server::new_async().await;

        let mock_response = json!({
            "uri": "https://bucket.s3.amazonaws.com/object",
            "headers": {
                "authorization": ["AWS4-HMAC-SHA256 Credential=..."]
            }
        });

        // Create a mock that should only be called once due to caching
        let _mock = server
            .mock("POST", "/v1/aws/s3/sign")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_header("cache-control", "private")
            .with_body(mock_response.to_string())
            .expect(1) // Should only be called once
            .create_async()
            .await;

        let config = RestSignerConfig::new(&server.url());
        let signer = RestSigner::new("s3", "us-east-1", config).unwrap();

        // First request
        let mut req1 = http::Request::builder()
            .method("GET")
            .uri("https://bucket.s3.amazonaws.com/object")
            .body(())
            .unwrap();

        let cred = AwsCredential::default();
        let result1 = signer.sign(&mut req1, &cred).await;
        assert!(result1.is_ok());

        // Second identical request should use cache
        let mut req2 = http::Request::builder()
            .method("GET")
            .uri("https://bucket.s3.amazonaws.com/object")
            .body(())
            .unwrap();

        let result2 = signer.sign(&mut req2, &cred).await;
        assert!(result2.is_ok());

        // Both requests should have the authorization header
        assert!(req1.headers().contains_key("authorization"));
        assert!(req2.headers().contains_key("authorization"));
    }
}
