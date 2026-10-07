use std::sync::{Mutex, OnceLock, mpsc};
use std::time::SystemTime;

use plume_core::CertificateReset;
use plume_core::developer::qh::certs::Cert;

pub(crate) const WARNING: &str = "Impactor needs to reset your certificate. This breaks existing SideStore and AltStore installs.";

#[derive(Debug, Clone)]
pub struct ConfirmationRequest {
    pub message: String,
    responder: mpsc::Sender<bool>,
}

impl ConfirmationRequest {
    pub fn respond(&self, accepted: bool) {
        let _ = self.responder.send(accepted);
    }
}

static REQUEST_TX: OnceLock<mpsc::Sender<ConfirmationRequest>> = OnceLock::new();
static REQUEST_RX: OnceLock<Mutex<mpsc::Receiver<ConfirmationRequest>>> = OnceLock::new();

fn request_channel() -> (
    &'static mpsc::Sender<ConfirmationRequest>,
    &'static Mutex<mpsc::Receiver<ConfirmationRequest>>,
) {
    REQUEST_TX.get_or_init(|| {
        let (tx, rx) = mpsc::channel();
        let _ = REQUEST_RX.set(Mutex::new(rx));
        tx
    });

    (
        REQUEST_TX
            .get()
            .expect("request sender should be initialized"),
        REQUEST_RX
            .get()
            .expect("request receiver should be initialized"),
    )
}

pub fn request_confirmation(message: &str) -> bool {
    let (response_tx, response_rx) = mpsc::channel();
    let request = ConfirmationRequest {
        message: message.to_string(),
        responder: response_tx,
    };

    let (request_tx, _) = request_channel();
    if request_tx.send(request).is_err() {
        return false;
    }

    response_rx.recv().unwrap_or(false)
}

pub fn confirm(certs: &[Cert]) -> CertificateReset {
    // The user confirms with a single yes/no, so exactly one named
    // certificate is offered: the one expiring first, which is the least
    // disruptive to keep. Revoking anything else would be a decision the
    // user never saw.
    let Some(chosen) = certs
        .iter()
        .min_by_key(|c| SystemTime::from(c.expiration_date))
    else {
        log::error!("Certificate reset requested but no certificate is on the account");
        return CertificateReset::NoAuthorization;
    };

    let message = format!(
        "{WARNING}\n\nRevoking: `{}` (serial `{}`, expires {:?}).",
        chosen.name, chosen.serial_number, chosen.expiration_date
    );

    log::warn!("{message}");
    if request_confirmation(&message) {
        CertificateReset::Revoke(chosen.serial_number.clone())
    } else {
        CertificateReset::Cancelled
    }
}

pub fn wait_for_request() -> Option<ConfirmationRequest> {
    let (_, request_rx) = request_channel();
    request_rx.lock().ok()?.recv().ok()
}
