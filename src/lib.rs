use hmac::{Hmac, Mac};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};
use pyo3::Bound;
use rand::Rng;
use serde_json::Value;
use sha2::Sha256;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

/// Bomiot payment client.
/// Holds community_key and sponsor_key, both read from auth_key.py.
/// create_payment sends both keys directly to the server.
/// query_order and verify_callback still use sponsor_key as HMAC key.
const BASE_URL: &str = "https://www.bomiot.com";

#[pyclass]
struct Client {
    community_key: String,
    sponsor_key: String,
}

/// Payment result returned by create_payment.
#[pyclass]
#[derive(Clone)]
struct PaymentResult {
    order_id: String,
    pay_url: String,
}

/// Order status returned by query_order.
#[pyclass]
#[derive(Clone)]
struct OrderStatus {
    order_id: String,
    pay_status: i32,
    pay_status_text: String,
    settle_status: i32,
    settle_status_text: String,
    refund_status: i32,
    refund_status_text: String,
    amount: String,
    settle_amount: String,
    expired: String,
    fail_reason: String,
}

/// HTTP request via Python urllib (avoids native TLS deps like ring/openssl).
fn http_request(
    py: Python,
    url: &str,
    method: &str,
    body: Option<&str>,
) -> PyResult<(u16, String)> {
    let urllib = py.import_bound("urllib.request")?;

    let request = match body {
        Some(data) => {
            let req = urllib.getattr("Request")?;
            let bytes = PyBytes::new_bound(py, data.as_bytes());
            req.call1((url, bytes))?
        }
        None => {
            let req = urllib.getattr("Request")?;
            req.call1((url,))?
        }
    };
    request.setattr("method", method)?;

    // urlopen raises HTTPError for non-200
    match urllib.getattr("urlopen")?.call1((request,)) {
        Ok(resp) => {
            let status_code = resp.getattr("getcode")?.call0()?.extract::<i32>()? as u16;
            let body = resp.call_method0("read")?.extract::<Vec<u8>>()?;
            let body_str = String::from_utf8_lossy(&body).to_string();
            Ok((status_code, body_str))
        }
        Err(err) => {
            let urllib_err = py.import_bound("urllib.error")?;
            let http_err_type = urllib_err.getattr("HTTPError")?;
            if err.matches(py, &http_err_type) {
                let value = err.into_value(py);
                let vb = value.bind(py);
                let code = vb.getattr("code")?.extract::<i32>()? as u16;
                let body = vb.call_method0("read")?.extract::<Vec<u8>>()?;
                let body_str = String::from_utf8_lossy(&body).to_string();
                Ok((code, body_str))
            } else {
                Err(err)
            }
        }
    }
}

/// Read COMMUNITY_KEY and SPONSOR_KEY from auth_key.py in WORKING_SPACE.
fn load_keys_from_auth_file(py: Python) -> PyResult<(String, String)> {
    let working_space = py
        .import_bound("django.conf")?
        .getattr("settings")?
        .getattr("WORKING_SPACE")
        .and_then(|v| v.extract::<String>())
        .or_else(|_| {
            let is_lan = py
                .import_bound("os")?
                .getattr("environ")
                .and_then(|env| env.get_item("IS_LAN"))
                .and_then(|v| v.extract::<String>())
                .unwrap_or_else(|_| "false".to_string());
            if is_lan == "true" {
                let exe = py.import_bound("sys")?.getattr("executable")?;
                let exe_str = exe.extract::<String>()?;
                py.import_bound("os")?
                    .getattr("path")?
                    .getattr("dirname")?
                    .call1((exe_str,))?
                    .extract::<String>()
            } else {
                let os_mod = py.import_bound("os")?;
                let cwd = os_mod.getattr("getcwd")?.call0()?;
                cwd.extract::<String>()
            }
        })?;

    let auth_key_path = format!("{}/auth_key.py", working_space);
    let content = fs::read_to_string(&auth_key_path).map_err(|e| {
        pyo3::exceptions::PyRuntimeError::new_err(format!(
            "Cannot read auth_key.py at {}: {}. Please pass community_key and sponsor_key manually.",
            auth_key_path, e
        ))
    })?;

    let community_key = extract_assignment(&content, "COMMUNITY_KEY").ok_or_else(|| {
        pyo3::exceptions::PyRuntimeError::new_err("COMMUNITY_KEY not found in auth_key.py")
    })?;
    let sponsor_key = extract_assignment(&content, "SPONSOR_KEY").ok_or_else(|| {
        pyo3::exceptions::PyRuntimeError::new_err("SPONSOR_KEY not found in auth_key.py")
    })?;

    Ok((community_key, sponsor_key))
}

/// Extract a string value from a Python assignment like: NAME = "value"
fn extract_assignment(content: &str, name: &str) -> Option<String> {
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with(name) {
            if let Some(eq_pos) = trimmed.find('=') {
                let val_part = trimmed[eq_pos + 1..].trim();
                let unquoted = val_part
                    .strip_prefix('"')
                    .and_then(|s| s.strip_suffix('"'))
                    .or_else(|| val_part.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')))
                    .unwrap_or(val_part);
                return Some(unquoted.to_string());
            }
        }
    }
    None
}

#[pymethods]
impl Client {
    #[new]
    #[pyo3(signature = (community_key=None, sponsor_key=None))]
    fn new(community_key: Option<String>, sponsor_key: Option<String>, py: Python) -> PyResult<Self> {
        let (ck, sk) = match (community_key, sponsor_key) {
            (Some(c), Some(s)) => (c, s),
            _ => load_keys_from_auth_file(py)?,
        };
        Ok(Client {
            community_key: ck,
            sponsor_key: sk,
        })
    }

    /// Create a payment order with royalty split.
    #[pyo3(signature = (amount, currency, recipient_account, notify_url, return_url=None))]
    fn create_payment(
        &self,
        py: Python,
        amount: f64,
        currency: &str,
        recipient_account: &str,
        notify_url: &str,
        return_url: Option<&str>,
    ) -> PyResult<Py<PyAny>> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let nonce = generate_nonce();

        let amount_str = format!("{}", amount);
        let return_url_val = return_url.unwrap_or("");

        let mut form = format!(
            "community_key={}&sponsor_key={}&timestamp={}&nonce={}&amount={}&currency={}&recipient_account={}&user_notify_url={}",
            url_encode(&self.community_key),
            url_encode(&self.sponsor_key),
            timestamp,
            nonce,
            url_encode(&amount_str),
            url_encode(currency),
            url_encode(recipient_account),
            url_encode(notify_url)
        );
        if !return_url_val.is_empty() {
            form.push_str(&format!("&return_url={}", url_encode(return_url_val)));
        }

        let url = format!("{}/alipayment/sponsor/pay/", BASE_URL);

        let (status_code, body) = http_request(py, &url, "POST", Some(&form))?;

        if status_code != 200 {
            return Err(pyo3::exceptions::PyRuntimeError::new_err(format!(
                "HTTP {}: {}",
                status_code, body
            )));
        }

        let json: Value = serde_json::from_str(&body).map_err(|e| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("Invalid JSON: {} | body: {}", e, body))
        })?;

        if let Some(detail) = json.get("detail").and_then(|d| d.as_str()) {
            return Err(pyo3::exceptions::PyRuntimeError::new_err(detail.to_string()));
        }

        let data = json.get("data").ok_or_else(|| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("Missing 'data' in response: {}", body))
        })?;

        let order_id = data.get("order_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let pay_url = data.get("pay_url").and_then(|v| v.as_str()).unwrap_or("").to_string();

        let result = PaymentResult { order_id, pay_url };
        Ok(result.into_py(py))
    }

    /// Query order status.
    fn query_order(&self, py: Python, order_id: &str) -> PyResult<Py<PyAny>> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let nonce = generate_nonce();

        let sign_str = format!("{}{}{}{}", self.community_key, timestamp, nonce, order_id);
        let signature = hmac_sign(&self.sponsor_key, &sign_str);

        let url = format!(
            "{}/alipayment/sponsor/order-status/?community_key={}&timestamp={}&nonce={}&signature={}&order_id={}",
            BASE_URL,
            url_encode(&self.community_key),
            timestamp,
            nonce,
            signature,
            url_encode(order_id)
        );

        let (status_code, body) = http_request(py, &url, "GET", None)?;

        if status_code != 200 {
            return Err(pyo3::exceptions::PyRuntimeError::new_err(format!(
                "HTTP {}: {}",
                status_code, body
            )));
        }

        let json: Value = serde_json::from_str(&body).map_err(|e| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("Invalid JSON: {} | body: {}", e, body))
        })?;

        if let Some(detail) = json.get("detail").and_then(|d| d.as_str()) {
            return Err(pyo3::exceptions::PyRuntimeError::new_err(detail.to_string()));
        }

        let data = json.get("data").ok_or_else(|| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("Missing 'data' in response: {}", body))
        })?;

        let status = OrderStatus {
            order_id: data.get("order_id").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            pay_status: data.get("pay_status").and_then(|v| v.as_i64()).unwrap_or(0) as i32,
            pay_status_text: data.get("pay_status_text").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            settle_status: data.get("settle_status").and_then(|v| v.as_i64()).unwrap_or(0) as i32,
            settle_status_text: data.get("settle_status_text").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            refund_status: data.get("refund_status").and_then(|v| v.as_i64()).unwrap_or(0) as i32,
            refund_status_text: data.get("refund_status_text").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            amount: data.get("amount").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            settle_amount: data.get("settle_amount").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            expired: data.get("expired").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            fail_reason: data.get("fail_reason").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        };

        Ok(status.into_py(py))
    }

    /// Verify a callback from Bomiot.
    fn verify_callback(&self, py: Python, body: &str, signature: &str) -> PyResult<Py<PyAny>> {
        let expected = hmac_sign(&self.sponsor_key, body);

        if expected != signature {
            return Err(pyo3::exceptions::PyRuntimeError::new_err(
                "Invalid callback signature",
            ));
        }

        let json: Value = serde_json::from_str(body).map_err(|e| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("Invalid JSON body: {}", e))
        })?;

        let dict = PyDict::new_bound(py);
        if let Some(obj) = json.get("status") {
            dict.set_item("status", obj.as_str().unwrap_or(""))?;
        }
        if let Some(obj) = json.get("order_id") {
            dict.set_item("order_id", obj.as_str().unwrap_or(""))?;
        }
        if let Some(obj) = json.get("amount") {
            dict.set_item("amount", obj.as_str().unwrap_or(""))?;
        }
        if let Some(obj) = json.get("settle_amount") {
            dict.set_item("settle_amount", obj.as_str().unwrap_or(""))?;
        }
        if let Some(obj) = json.get("reason") {
            dict.set_item("reason", obj.as_str().unwrap_or(""))?;
        }
        if let Some(obj) = json.get("expired") {
            dict.set_item("expired", obj.as_str().unwrap_or(""))?;
        }

        Ok(dict.into_any().unbind())
    }
}

#[pymethods]
impl PaymentResult {
    #[getter]
    fn order_id(&self) -> &str {
        &self.order_id
    }

    #[getter]
    fn pay_url(&self) -> &str {
        &self.pay_url
    }

    fn __repr__(&self) -> String {
        format!("PaymentResult(order_id='{}', pay_url='{}')", self.order_id, self.pay_url)
    }
}

#[pymethods]
impl OrderStatus {
    #[getter]
    fn order_id(&self) -> &str {
        &self.order_id
    }
    #[getter]
    fn pay_status(&self) -> i32 {
        self.pay_status
    }
    #[getter]
    fn pay_status_text(&self) -> &str {
        &self.pay_status_text
    }
    #[getter]
    fn settle_status(&self) -> i32 {
        self.settle_status
    }
    #[getter]
    fn settle_status_text(&self) -> &str {
        &self.settle_status_text
    }
    #[getter]
    fn refund_status(&self) -> i32 {
        self.refund_status
    }
    #[getter]
    fn refund_status_text(&self) -> &str {
        &self.refund_status_text
    }
    #[getter]
    fn amount(&self) -> &str {
        &self.amount
    }
    #[getter]
    fn settle_amount(&self) -> &str {
        &self.settle_amount
    }
    #[getter]
    fn expired(&self) -> &str {
        &self.expired
    }
    #[getter]
    fn fail_reason(&self) -> &str {
        &self.fail_reason
    }

    fn __repr__(&self) -> String {
        format!(
            "OrderStatus(order_id='{}', pay_status={}, settle_status={}, refund_status={})",
            self.order_id, self.pay_status, self.settle_status, self.refund_status
        )
    }
}

fn generate_nonce() -> String {
    let bytes: [u8; 16] = rand::thread_rng().gen();
    hex_encode(&bytes)
}

fn hmac_sign(key: &str, message: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).unwrap();
    mac.update(message.as_bytes());
    let result = mac.finalize();
    hex_encode(result.into_bytes().as_slice())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn url_encode(s: &str) -> String {
    let mut result = String::new();
    for c in s.chars() {
        match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => result.push(c),
            _ => {
                let bytes = c.to_string().into_bytes();
                for b in bytes {
                    result.push_str(&format!("%{:02X}", b));
                }
            }
        }
    }
    result
}

#[pymodule]
fn bomiot_pay(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Client>()?;
    m.add_class::<PaymentResult>()?;
    m.add_class::<OrderStatus>()?;
    m.add("__version__", "0.1.0")?;
    Ok(())
}
