//! Shielded spends of a HALFKEY Zcash P2SH output (HTLC or 2-of-2): one transparent input, one
//! Ironwood output, v6 transaction (NU6.3+/NU7), built and Halo2-proven by the party that receives
//! the note (the user's browser). Nobody else ever sees the note's recipient, value or memo.
//!
//! Why this is safe to pre-sign and hand to a watchtower:
//!  * ZIP 244 (v5/v6) signature digests do not commit to any scriptSig, so the transparent
//!    signature is made before the HTLC preimage (or the counterparty's decrypted adaptor
//!    signature) exists; the watchtower only fills the scriptSig.
//!  * The transparent signature commits to the whole Ironwood bundle digest (actions, value
//!    balance, flags), and the binding signature commits to the shielded sighash, so nothing about
//!    the output can be changed without invalidating both.
//!  * v6 digests exclude the Orchard-family anchor; the proof commits to it. We take the anchor
//!    from the node at build time; Zcash accepts any earlier final Ironwood root, so the proof stays
//!    valid however late the spend is broadcast (until the next branch-ID change).
//!
//! The scriptSig is left EMPTY in the serialized template. The caller (JS) signs the transparent
//! sighash with its own secp256k1 key and writes the final scriptSig.
use orchard::{
    builder::{BundleType, InProgress, Unauthorized as OUnauthorized, Unproven},
    bundle::{Authorized as OAuthorized, BundleVersion},
    circuit::{ProvingKey, VerifyingKey},
    keys::OutgoingViewingKey,
    value::NoteValue,
    Address, Anchor,
};
/// System randomness (crypto.getRandomValues in the browser).
#[allow(non_upper_case_globals)]
const OsRng: rand_core::UnwrapErr<getrandom::SysRng> = rand_core::UnwrapErr(getrandom::SysRng);
use std::sync::OnceLock;
use transparent::{
    address::Script,
    bundle::{Authorization as TAuthorization, Authorized as TAuthorized, Bundle as TBundle, OutPoint, TxIn, TxOut},
    sighash::{SighashType, SignableInput as TSignableInput, TransparentAuthorizingContext},
};
use zcash_primitives::transaction::{
    sighash::{PrecomputedSighashData, SignableInput},
    Authorization, Transaction, TransactionData, TxVersion,
};
use zcash_protocol::{
    consensus::{BlockHeight, BranchId},
    value::Zatoshis,
};
use zcash_transparent as transparent;

/// Errors are plain strings: they cross into JS unchanged.
pub type Res<T> = Result<T, String>;
fn e<T: std::fmt::Debug>(what: &'static str) -> impl FnOnce(T) -> String {
    move |x| format!("{what}: {x:?}")
}

// ------------------------------------------------------------------ authorization markers
/// Transparent inputs as the signer sees them: amounts and spent scriptPubKeys, no scriptSig yet.
#[derive(Debug, Clone)]
pub struct Unsigned {
    inputs: Vec<TxOut>,
}
impl TAuthorization for Unsigned {
    type ScriptSig = ();
}
impl TransparentAuthorizingContext for Unsigned {
    fn input_amounts(&self) -> Vec<Zatoshis> {
        self.inputs.iter().map(|o| o.value()).collect()
    }
    fn input_scriptpubkeys(&self) -> Vec<Script> {
        self.inputs.iter().map(|o| o.script_pubkey().clone()).collect()
    }
}
/// A transaction whose transparent part is unsigned and whose Ironwood bundle is unproven.
#[derive(Debug)]
struct Building;
impl Authorization for Building {
    type TransparentAuth = Unsigned;
    type SaplingAuth = sapling::bundle::Authorized;
    type OrchardAuth = InProgress<Unproven, OUnauthorized>;
}
/// A complete transaction re-read from bytes, with the prevout data the sighash needs.
#[derive(Debug)]
struct Checking;
impl Authorization for Checking {
    type TransparentAuth = Unsigned;
    type SaplingAuth = sapling::bundle::Authorized;
    type OrchardAuth = OAuthorized;
}
use sapling_crypto as sapling;

// ------------------------------------------------------------------ keys (cached per process)
static PK: OnceLock<ProvingKey> = OnceLock::new();
static VK: OnceLock<VerifyingKey> = OnceLock::new();
fn circuit() -> orchard::circuit::OrchardCircuitVersion {
    BundleVersion::ironwood_v3().circuit_version()
}
/// Builds (once) the Halo2 proving key for the post-NU6.3 action circuit. The slow first step.
pub fn proving_key() -> &'static ProvingKey {
    PK.get_or_init(|| ProvingKey::build(circuit()))
}
pub fn verifying_key() -> &'static VerifyingKey {
    VK.get_or_init(|| VerifyingKey::build(circuit()))
}

// ------------------------------------------------------------------ requests
#[derive(serde::Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SpendRequest {
    /// Consensus branch ID the spend commits to (NU7 = 0x77190ad9).
    pub branch: u32,
    /// 0 for a claim; the refund height for a refund.
    pub lock_time: u32,
    /// 0xffffffff for a claim, 0xfffffffe for a refund (enables nLockTime / CLTV).
    pub sequence: u32,
    /// Funding outpoint, txid in RPC display order.
    pub prev_txid: String,
    pub vout: u32,
    /// Funding value in zatoshis.
    pub value: u64,
    /// The spent scriptPubKey (P2SH), hex.
    #[serde(rename = "scriptPubKey")]
    pub script_pubkey: String,
    /// The redeem script (ZIP 244 does not commit to it, but zcash_primitives asks for it), hex.
    pub script_code: String,
    /// The recipient's Orchard-family receiver (43 bytes, hex): Ironwood shares the UA's Orchard receiver.
    pub recipient: String,
    /// Fee in zatoshis (ZIP 317, computed by the caller for the final scriptSig size).
    pub fee: u64,
    /// Ironwood anchor (32 bytes, hex, internal byte order: zebrad's z_gettreestate prints
    /// Orchard-family roots in this order already, no reversal).
    pub anchor: String,
    /// Optional 512-byte memo, hex; default "no memo" (0xF6).
    #[serde(default)]
    pub memo: Option<String>,
}

#[derive(serde::Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SpendTemplate {
    /// The full v6 transaction with an EMPTY scriptSig on input 0, hex.
    pub raw: String,
    /// ZIP 244 txid (display order). Final: the scriptSig is not hashed.
    pub txid: String,
    /// Transparent sighash (SIGHASH_ALL) for input 0, hex: sign this with the P2SH key.
    pub sighash: String,
    pub actions: usize,
    pub proof_bytes: usize,
    pub out_value: u64,
    pub prove_ms: f64,
}

fn unhex<const N: usize>(h: &str, what: &'static str) -> Res<[u8; N]> {
    let v = hex::decode(h).map_err(e(what))?;
    v.try_into().map_err(|_| format!("{what}: expected {N} bytes"))
}
fn txid_internal(display: &str) -> Res<[u8; 32]> {
    let mut b: [u8; 32] = unhex(display, "prev txid")?;
    b.reverse();
    Ok(b)
}
fn script(h: &str, what: &'static str) -> Res<Script> {
    Ok(Script(zcash_script::script::Code(hex::decode(h).map_err(e(what))?)))
}

fn transparent_part(r: &SpendRequest) -> Res<(TBundle<Unsigned>, Script, Script)> {
    let spk = script(&r.script_pubkey, "scriptPubKey")?;
    let code = script(&r.script_code, "redeem script")?;
    let value = Zatoshis::from_u64(r.value).map_err(e("value"))?;
    let b = TBundle {
        vin: vec![TxIn::from_parts(OutPoint::new(txid_internal(&r.prev_txid)?, r.vout), (), r.sequence)],
        vout: vec![],
        authorization: Unsigned { inputs: vec![TxOut::new(value, spk.clone())] },
    };
    Ok((b, spk, code))
}

pub fn now_ms() -> f64 {
    #[cfg(target_arch = "wasm32")]
    {
        js_sys::Date::now()
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs_f64() * 1000.0
    }
}

/// Build, prove and shielded-sign the spend. Returns the template and the transparent sighash.
pub fn build_spend(r: &SpendRequest) -> Res<SpendTemplate> {
    let branch = BranchId::try_from(r.branch).map_err(e("branch"))?;
    if !TxVersion::suggested_for_branch(branch).has_ironwood() {
        return Err("this branch has no Ironwood pool (needs NU6.3 or later)".into());
    }
    if r.sequence != 0xffff_ffff && r.sequence != 0xffff_fffe {
        return Err("sequence must be final or 0xfffffffe".into());
    }
    let out_value = r.value.checked_sub(r.fee).ok_or("fee above the HTLC value")?;
    if out_value == 0 {
        return Err("nothing left after the fee".into());
    }
    let recipient = Address::from_raw_address_bytes(&unhex::<43>(&r.recipient, "recipient")?)
        .into_option()
        .ok_or("recipient is not a valid Orchard/Ironwood receiver")?;
    let anchor = Anchor::from_bytes(unhex::<32>(&r.anchor, "anchor")?)
        .into_option()
        .ok_or("anchor is not a Pallas field element")?;
    let mut memo = [0u8; 512];
    memo[0] = 0xF6;
    if let Some(m) = &r.memo {
        memo = unhex::<512>(m, "memo")?;
    }

    // Ironwood bundle: one real output, padded to the default two actions (both look alike).
    let version = BundleVersion::ironwood_v3();
    let mut ob = orchard::builder::Builder::new(BundleType::DEFAULT, version, version.default_flags(), anchor)
        .map_err(e("ironwood builder"))?;
    // No outgoing viewing key: the recipient is the only one who can ever read this note.
    ob.add_output(None::<OutgoingViewingKey>, recipient, NoteValue::from_raw(out_value), memo)
        .map_err(e("ironwood output"))?;
    let (bundle, _meta) = ob
        .build::<zcash_protocol::value::ZatBalance>(OsRng)
        .map_err(e("ironwood build"))?
        .ok_or("empty ironwood bundle")?;
    let actions = bundle.actions().len();

    let (tb, spk, code) = transparent_part(r)?;
    let value = Zatoshis::from_u64(r.value).map_err(e("value"))?;
    let tx: TransactionData<Building> = TransactionData::from_parts_v6(
        branch,
        r.lock_time,
        BlockHeight::from_u32(0), // never expires: it may be broadcast hours later by a watchtower
        Some(tb),
        None,
        None,
        Some(bundle),
    );
    let sd = PrecomputedSighashData::new(tx);
    let tsig = {
        let tb = sd.tx().transparent_bundle().expect("set above");
        let si = TSignableInput::from_parts(tb, SighashType::ALL, 0, &code, &spk, value).map_err(e("input"))?;
        *sd.signature_hash(&SignableInput::Transparent(si)).as_ref()
    };
    let shielded = *sd.signature_hash(&SignableInput::Shielded).as_ref();
    let tx = sd.into_tx();

    let t0 = now_ms();
    let pk = proving_key();
    let ib = tx.ironwood_bundle().cloned().expect("set above");
    let proven = ib.create_proof(pk, OsRng).map_err(e("prove"))?;
    let prove_ms = now_ms() - t0;
    let signed = proven
        .apply_signatures(OsRng, shielded, &[])
        .map_err(e("ironwood signatures"))?;
    let proof_bytes = signed.authorization().proof().as_ref().len();

    // Re-assemble with an empty scriptSig placeholder.
    let tb = tx.transparent_bundle().expect("set above");
    let vin = tb
        .vin
        .iter()
        .map(|i| TxIn::<TAuthorized>::from_parts(i.prevout().clone(), Script(zcash_script::script::Code(vec![])), i.sequence()))
        .collect();
    let final_tx: TransactionData<zcash_primitives::transaction::Authorized> = TransactionData::from_parts_v6(
        branch,
        r.lock_time,
        BlockHeight::from_u32(0),
        Some(TBundle { vin, vout: vec![], authorization: TAuthorized }),
        None,
        None,
        Some(signed),
    );
    let frozen = final_tx.freeze().map_err(e("freeze"))?;
    let mut raw = vec![];
    frozen.write(&mut raw).map_err(e("serialize"))?;
    Ok(SpendTemplate {
        raw: hex::encode(raw),
        txid: frozen.txid().to_string(),
        sighash: hex::encode(tsig),
        actions,
        proof_bytes,
        out_value,
        prove_ms,
    })
}

// ------------------------------------------------------------------ checking a finished spend
#[derive(serde::Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct InspectRequest {
    pub raw: String,
    pub branch: u32,
    pub value: u64,
    #[serde(rename = "scriptPubKey")]
    pub script_pubkey: String,
    pub script_code: String,
    /// Verify the Halo2 proof and the bundle signatures (slow the first time: builds the VK).
    #[serde(default)]
    pub verify_proof: bool,
}
#[derive(serde::Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Inspection {
    pub txid: String,
    pub version: u32,
    pub lock_time: u32,
    pub expiry_height: u32,
    pub inputs: Vec<InputInfo>,
    pub transparent_outputs: usize,
    pub has_sapling: bool,
    pub has_orchard: bool,
    pub ironwood_actions: usize,
    /// Net value entering the Ironwood pool (positive = into the pool), zatoshis.
    pub ironwood_value_in: i64,
    pub sighash: String,
    /// The Ironwood anchor the proof commits to (hex, z_gettreestate order). Outside the sighash
    /// and the txid: a holder must check it is a real final root, or the spend is dead on arrival.
    pub anchor: Option<String>,
    /// null unless verify_proof was asked.
    pub proof_ok: Option<bool>,
}
#[derive(serde::Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct InputInfo {
    pub prev_txid: String,
    pub vout: u32,
    pub sequence: u32,
    pub script_sig: String,
}

pub fn inspect(r: &InspectRequest) -> Res<Inspection> {
    let branch = BranchId::try_from(r.branch).map_err(e("branch"))?;
    let raw = hex::decode(&r.raw).map_err(e("raw"))?;
    let tx = Transaction::read(&raw[..], branch).map_err(e("parse"))?;
    let mut back = vec![];
    tx.write(&mut back).map_err(e("reserialize"))?;
    if back != raw {
        return Err("non-canonical transaction encoding".into());
    }
    let txid = tx.txid().to_string();
    let version = tx.version().header() & 0x7fff_ffff;
    let data = tx.into_data();
    let lock_time = data.lock_time();
    let expiry_height = u32::from(data.expiry_height());
    let tb = data.transparent_bundle().ok_or("no transparent input")?;
    let inputs = tb
        .vin
        .iter()
        .map(|i| {
            let mut t = *i.prevout().hash();
            t.reverse();
            InputInfo { prev_txid: hex::encode(t), vout: i.prevout().n(), sequence: i.sequence(), script_sig: hex::encode(&i.script_sig().0 .0) }
        })
        .collect::<Vec<_>>();
    let transparent_outputs = tb.vout.len();
    let has_sapling = data.sapling_bundle().is_some();
    let has_orchard = data.orchard_bundle().is_some();
    let (ironwood_actions, ironwood_value_in) = data
        .ironwood_bundle()
        .map(|b| (b.actions().len(), -i64::from(*b.value_balance())))
        .unwrap_or((0, 0));
    let spk = script(&r.script_pubkey, "scriptPubKey")?;
    let code = script(&r.script_code, "redeem script")?;
    let value = Zatoshis::from_u64(r.value).map_err(e("value"))?;
    let n_in = tb.vin.len();
    let ib = data.ironwood_bundle().cloned();
    // Map to the checking authorization (same effects, the prevout context the sighash needs).
    let chk: TransactionData<Checking> = TransactionData::from_parts_v6(
        data.consensus_branch_id(),
        lock_time,
        data.expiry_height(),
        Some(TBundle {
            vin: tb.vin.iter().map(|i| TxIn::from_parts(i.prevout().clone(), (), i.sequence())).collect(),
            vout: tb.vout.clone(),
            authorization: Unsigned { inputs: vec![TxOut::new(value, spk.clone()); n_in] },
        }),
        None,
        None,
        ib.clone(),
    );
    if n_in != 1 {
        return Err("expected exactly one transparent input".into());
    }
    let sd = PrecomputedSighashData::new_zip244(chk).map_err(|_| "not a ZIP 244 transaction".to_string())?;
    let tb2 = sd.tx().transparent_bundle().expect("set");
    let si = TSignableInput::from_parts(tb2, SighashType::ALL, 0, &code, &spk, value).map_err(e("input"))?;
    let sighash = hex::encode(sd.signature_hash(&SignableInput::Transparent(si)).as_ref());
    let proof_ok = if r.verify_proof {
        let shielded = *sd.signature_hash(&SignableInput::Shielded).as_ref();
        Some(match &ib {
            None => false,
            Some(b) => {
                // add_bundle refuses a bundle whose flags do not fit the verifying key; an empty
                // batch would then "validate", so a refused bundle is a failed check.
                let mut v = orchard::bundle::BatchValidator::new(verifying_key());
                v.add_bundle(b, shielded).is_ok() && v.validate(OsRng)
            }
        })
    } else {
        None
    };
    Ok(Inspection {
        txid,
        version,
        lock_time,
        expiry_height,
        inputs,
        transparent_outputs,
        has_sapling,
        has_orchard,
        ironwood_actions,
        ironwood_value_in,
        sighash,
        anchor: ib.as_ref().map(|b| hex::encode(b.anchor().to_bytes())),
        proof_ok,
    })
}

// ------------------------------------------------------------------ unified addresses
/// The Orchard-family receiver of a unified address (ZIP 316), hex. Ironwood shares it.
pub fn ua_receiver(ua: &str, net: &str) -> Res<String> {
    use zcash_address::unified::{self, Container, Encoding};
    let (nt, _rev, addr) = unified::Address::decode(ua.trim()).map_err(|x| format!("not a unified address: {x}"))?;
    let want = net_type(net)?;
    if nt != want {
        return Err(format!("address is for {nt:?}, not {want:?}"));
    }
    for item in addr.items() {
        if let unified::Receiver::Orchard(b) = item {
            Address::from_raw_address_bytes(&b).into_option().ok_or("invalid Orchard receiver")?;
            return Ok(hex::encode(b));
        }
    }
    Err("this unified address has no shielded Orchard/Ironwood receiver".into())
}
pub fn net_type(net: &str) -> Res<zcash_protocol::consensus::NetworkType> {
    use zcash_protocol::consensus::NetworkType::*;
    Ok(match net {
        "mainnet" => Main,
        "testnet" => Test,
        "regtest" => Regtest,
        _ => return Err("unknown network".into()),
    })
}

// ------------------------------------------------------------------ test kit (regtest runner only)
#[cfg(feature = "testkit")]
pub mod testkit {
    use super::*;
    use orchard::keys::{FullViewingKey, PreparedIncomingViewingKey, Scope, SpendingKey};
    use orchard::note_encryption::IronwoodDomain;
    use zcash_note_encryption::try_note_decryption;

    fn keys(seed: &[u8]) -> Res<FullViewingKey> {
        let sk = SpendingKey::from_zip32_seed(seed, 1, zip32::AccountId::ZERO).map_err(e("zip32"))?;
        Ok(FullViewingKey::from(&sk))
    }
    /// A unified address with only an Orchard-family receiver, from a test seed.
    pub fn wallet(seed_hex: &str, net: &str) -> Res<(String, String)> {
        use zcash_address::unified::{self, Encoding};
        let fvk = keys(&hex::decode(seed_hex).map_err(e("seed"))?)?;
        let a = fvk.address_at(0u32, Scope::External).to_raw_address_bytes();
        let ua = unified::Address::try_from_items(unified::Revision::R0, vec![unified::Uitem::Data(unified::Receiver::Orchard(a))])
            .map_err(e("ua"))?;
        Ok((ua.encode(&net_type(net)?), hex::encode(a)))
    }
    /// Trial-decrypt every Ironwood output of `raw` with the test wallet: (value, memo lead byte).
    pub fn decrypt(raw_hex: &str, branch: u32, seed_hex: &str) -> Res<Vec<(u64, u8)>> {
        let fvk = keys(&hex::decode(seed_hex).map_err(e("seed"))?)?;
        let ivk = PreparedIncomingViewingKey::new(&fvk.to_ivk(Scope::External));
        let tx = Transaction::read(&hex::decode(raw_hex).map_err(e("raw"))?[..], BranchId::try_from(branch).map_err(e("branch"))?)
            .map_err(e("parse"))?;
        let mut out = vec![];
        if let Some(b) = tx.ironwood_bundle() {
            for a in b.actions() {
                let d = IronwoodDomain::for_action(a);
                if let Some((note, _addr, memo)) = try_note_decryption(&d, &ivk, a) {
                    out.push((note.value().inner(), memo[0]));
                }
            }
        }
        Ok(out)
    }
}
