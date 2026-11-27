//! HALFKEY ZEC privacy module (Rust -> WASM for the browser, also loaded by Node for the
//! watchtower, the maker and the regtest runner). Every export takes and returns JSON strings.
pub mod adaptor;
pub mod shielded;

use wasm_bindgen::prelude::*;

fn js<T: serde::Serialize>(r: Result<T, String>) -> Result<String, JsError> {
    match r {
        Ok(v) => serde_json::to_string(&v).map_err(|e| JsError::new(&e.to_string())),
        Err(e) => Err(JsError::new(&e)),
    }
}
fn parse<T: serde::de::DeserializeOwned>(s: &str) -> Result<T, String> {
    serde_json::from_str(s).map_err(|e| format!("bad request: {e}"))
}

/// Build the Halo2 proving key now (the slow first step), returns milliseconds taken.
#[wasm_bindgen(js_name = prepareProver)]
pub fn prepare_prover() -> f64 {
    let t = shielded::now_ms();
    shielded::proving_key();
    shielded::now_ms() - t
}

/// Build + prove + shielded-sign a v6 spend of one P2SH output into one Ironwood note.
#[wasm_bindgen(js_name = buildShieldedSpend)]
pub fn build_shielded_spend(req: &str) -> Result<String, JsError> {
    js(parse(req).and_then(|r| shielded::build_spend(&r)))
}

/// Parse a finished (or template) spend: txid, inputs, Ironwood summary, input-0 sighash, proof check.
#[wasm_bindgen(js_name = inspectSpend)]
pub fn inspect_spend(req: &str) -> Result<String, JsError> {
    js(parse(req).and_then(|r| shielded::inspect(&r)))
}

/// The Orchard-family (Ironwood) receiver of a unified address, hex.
#[wasm_bindgen(js_name = uaReceiver)]
pub fn ua_receiver(ua: &str, net: &str) -> Result<String, JsError> {
    shielded::ua_receiver(ua, net).map_err(|e| JsError::new(&e))
}

#[cfg(feature = "testkit")]
#[wasm_bindgen(js_name = testWallet)]
pub fn test_wallet(seed_hex: &str, net: &str) -> Result<String, JsError> {
    js(shielded::testkit::wallet(seed_hex, net).map(|(ua, recv)| serde_json::json!({ "ua": ua, "receiver": recv })))
}
#[cfg(feature = "testkit")]
#[wasm_bindgen(js_name = testDecrypt)]
pub fn test_decrypt(raw_hex: &str, branch: u32, seed_hex: &str) -> Result<String, JsError> {
    js(shielded::testkit::decrypt(raw_hex, branch, seed_hex)
        .map(|v| v.into_iter().map(|(value, memo)| serde_json::json!({ "value": value, "memoLead": memo })).collect::<Vec<_>>()))
}

// ------------------------------------------------------------------ ZEC v2: adaptor signatures + DLEQ
/// {tSecp, tEd} for a secret t (32 bytes little-endian hex, t < 2^252).
#[wasm_bindgen(js_name = adaptorPoints)]
pub fn adaptor_points(t: &str) -> Result<String, JsError> {
    js(adaptor::points(t))
}
/// {tSecp, tEd, proof}: the cross-curve DLEQ that both points share t (~1-3 s).
#[wasm_bindgen(js_name = dleqProve)]
pub fn dleq_prove(t: &str) -> Result<String, JsError> {
    js(adaptor::dleq_prove(t))
}
#[wasm_bindgen(js_name = dleqVerify)]
pub fn dleq_verify(t_secp: &str, t_ed: &str, proof: &str) -> Result<bool, JsError> {
    adaptor::dleq_verify(t_secp, t_ed, proof).map_err(|e| JsError::new(&e))
}
/// Adaptor signature (162 bytes hex) by `sk` (32-byte big-endian hex) on `msg` (32 bytes), encrypted to T_secp.
#[wasm_bindgen(js_name = adaptorSign)]
pub fn adaptor_sign(sk: &str, t_secp: &str, msg: &str) -> Result<String, JsError> {
    adaptor::enc_sign(sk, t_secp, msg).map_err(|e| JsError::new(&e))
}
#[wasm_bindgen(js_name = adaptorVerify)]
pub fn adaptor_verify(pk: &str, t_secp: &str, msg: &str, enc: &str) -> Result<bool, JsError> {
    adaptor::enc_verify(pk, t_secp, msg, enc).map_err(|e| JsError::new(&e))
}
/// Decrypt with t: the 64-byte r||s ECDSA signature (low-S), hex.
#[wasm_bindgen(js_name = adaptorDecrypt)]
pub fn adaptor_decrypt(t: &str, enc: &str) -> Result<String, JsError> {
    adaptor::decrypt(t, enc).map_err(|e| JsError::new(&e))
}
#[wasm_bindgen(js_name = adaptorRecover)]
pub fn adaptor_recover(t_secp: &str, sig64: &str, enc: &str) -> Result<String, JsError> {
    adaptor::recover(t_secp, sig64, enc).map_err(|e| JsError::new(&e))
}
