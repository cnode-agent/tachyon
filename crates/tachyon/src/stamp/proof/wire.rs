//! Wire decoding for the header data the wallet persists.
//!
//! Ragu's mock wire format stores a PCD as its proof plus the flattened
//! elements emitted by [`Header::encode`]. These implementations reconstruct
//! the cached header data from those elements; the wallet uses the resulting
//! `Pcd::to_bytes`/`from_bytes` path for its proof cache.

use ragu::WireHeader;
use ragu_core::pasta::Fp;
use udon::{curve::Affine as _, field::Field as _};

use crate::{
    note,
    pasta::EpAffine,
    primitives::{Anchor, EpochIndex, QrDiscriminant, QrProfile, TachygramSetBridge},
};

use super::{
    qr::{QrBucket, QrIntake},
    spendable::NoteSpendable,
};

fn u32_from_fp(value: Fp) -> Option<u32> {
    let bytes = value.to_bytes();
    let bytes = bytes.as_ref();
    let (head, rest) = bytes.split_at(4);
    if rest.iter().any(|byte| *byte != 0) {
        return None;
    }
    Some(u32::from_le_bytes(head.try_into().ok()?))
}

fn profile(depth: Fp, bits: Fp) -> Option<QrProfile> {
    let depth = u32_from_fp(depth)?;
    let bits = u32_from_fp(bits)?;
    if depth > u32::BITS || (depth < u32::BITS && bits >> depth != 0) {
        return None;
    }
    Some(QrProfile { depth, bits })
}

impl WireHeader<Fp> for QrIntake {
    fn decode(elements: &[Fp]) -> Option<Self::Data> {
        let [epoch, before, after, discriminant, depth, bits] =
            <[Fp; 6]>::try_from(elements).ok()?;
        Some((
            EpochIndex::try_from(epoch).ok()?,
            Anchor(before),
            Anchor(after),
            QrDiscriminant(discriminant),
            profile(depth, bits)?,
        ))
    }
}

impl WireHeader<Fp> for QrBucket {
    fn decode(elements: &[Fp]) -> Option<Self::Data> {
        let [epoch, before, after, discriminant, depth, bits, hash_x, hash_y] =
            <[Fp; 8]>::try_from(elements).ok()?;
        let contents = TachygramSetBridge::from(EpAffine::from_xy(hash_x, hash_y)?);
        Some((
            EpochIndex::try_from(epoch).ok()?,
            Anchor(before),
            Anchor(after),
            QrDiscriminant(discriminant),
            profile(depth, bits)?,
            contents,
        ))
    }
}

impl WireHeader<Fp> for NoteSpendable {
    fn decode(elements: &[Fp]) -> Option<Self::Data> {
        let [cm, epoch, anchor] = <[Fp; 3]>::try_from(elements).ok()?;
        Some((
            note::Commitment::from(cm),
            EpochIndex::try_from(epoch).ok()?,
            Anchor(anchor),
        ))
    }
}
