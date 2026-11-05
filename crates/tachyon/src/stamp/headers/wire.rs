//! Wire codecs for the header data the wallet persists.
//!
//! Implements ragu's mock `WireHeader` for the headers whose PCDs a consumer
//! caches across epochs (epoch buckets and spendability lineages), so those
//! proofs can be stored and lifted incrementally instead of rebuilt from raw
//! chain data.

use alloc::vec::Vec;
use core::convert::Infallible;

use ragu::WireHeader;
use ragu_core::pasta::Fp;
use udon::field::Field;

use crate::{
    EpochIndex, Anchor, QrDiscriminant, QrProfile, TachygramSetCommit, note::Commitment,
};

use super::{qr::QrBucket, spendable::NoteSpendable};

fn write_fp(bytes: &mut Vec<u8>, element: &Fp) {
    bytes.extend_from_slice(element.to_bytes().as_ref());
}

fn read_fp(bytes: &[u8]) -> Option<(Fp, &[u8])> {
    let mut repr = Fp::ZERO.to_bytes();
    let (head, rest) = bytes.split_at_checked(repr.as_ref().len())?;
    repr.as_mut().copy_from_slice(head);
    Fp::from_bytes(repr).map(|element| (element, rest))
}

fn read_u32(bytes: &[u8]) -> Option<(u32, &[u8])> {
    let (head, rest) = bytes.split_at_checked(4)?;
    Some((u32::from_le_bytes(head.try_into().ok()?), rest))
}

fn write_commit(bytes: &mut Vec<u8>, commit: &TachygramSetCommit) {
    commit
        .write(&mut *bytes)
        .expect("Vec write is infallible")
}

fn read_commit(bytes: &[u8]) -> Option<(TachygramSetCommit, &[u8])> {
    let (head, rest) = bytes.split_at_checked(32)?;
    TachygramSetCommit::read(head).ok().map(|commit| (commit, rest))
}

fn write_epoch(bytes: &mut Vec<u8>, epoch: EpochIndex) {
    bytes.extend_from_slice(&u32::from(epoch).to_le_bytes());
}

fn write_bucket_data(
    data: &(
        EpochIndex,
        Anchor,
        Anchor,
        QrDiscriminant,
        QrProfile,
        TachygramSetCommit,
    ),
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(4 + 32 * 3 + 8 + 32);
    write_epoch(&mut bytes, data.0);
    write_fp(&mut bytes, &data.1.0);
    write_fp(&mut bytes, &data.2.0);
    write_fp(&mut bytes, &data.3.0);
    bytes.extend_from_slice(&data.4.depth.to_le_bytes());
    bytes.extend_from_slice(&data.4.bits.to_le_bytes());
    write_commit(&mut bytes, &data.5);
    bytes
}

fn read_bucket_data(
    bytes: &[u8],
) -> Option<(
    EpochIndex,
    Anchor,
    Anchor,
    QrDiscriminant,
    QrProfile,
    TachygramSetCommit,
)> {
    let (epoch, rest) = read_u32(bytes)?;
    let (before, rest) = read_fp(rest)?;
    let (after, rest) = read_fp(rest)?;
    let (discriminant, rest) = read_fp(rest)?;
    let (depth, rest) = read_u32(rest)?;
    let (bits, rest) = read_u32(rest)?;
    if depth > u32::BITS || bits >> depth != 0 {
        return None;
    }
    let (contents, rest) = read_commit(rest)?;
    if !rest.is_empty() {
        return None;
    }
    Some((
        EpochIndex::new(epoch),
        Anchor(before),
        Anchor(after),
        QrDiscriminant(discriminant),
        QrProfile { depth, bits },
        contents,
    ))
}

impl WireHeader for QrBucket {
    fn data_to_bytes(data: &Self::Data) -> Vec<u8> {
        write_bucket_data(data)
    }

    fn data_from_bytes(bytes: &[u8]) -> Option<Self::Data> {
        read_bucket_data(bytes)
    }
}

impl WireHeader for NoteSpendable {
    fn data_to_bytes(data: &Self::Data) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(32 + 4 + 32);
        write_fp(&mut bytes, &Fp::from(data.0));
        write_epoch(&mut bytes, data.1);
        write_fp(&mut bytes, &data.2.0);
        bytes
    }

    fn data_from_bytes(bytes: &[u8]) -> Option<Self::Data> {
        let (cm, rest) = read_fp(bytes)?;
        let (epoch, rest) = read_u32(rest)?;
        let (anchor, rest) = read_fp(rest)?;
        if !rest.is_empty() {
            return None;
        }
        Some((Commitment::from(cm), EpochIndex::new(epoch), Anchor(anchor)))
    }
}

// The unit header's codec is total; keep the type referenced so the module
// documents that unit data never reaches the wire.
#[allow(dead_code)]
fn unit_is_total(_: Infallible) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Anchor, EpochIndex};

    #[test]
    fn bucket_data_round_trip() {
        let data = (
            EpochIndex::new(7),
            Anchor(Fp::from(3)),
            Anchor(Fp::from(9)),
            QrDiscriminant(Fp::from(11)),
            QrProfile {
                depth: 3,
                bits: 0b101,
            },
            TachygramSetCommit::default(),
        );
        let bytes = <QrBucket as WireHeader>::data_to_bytes(&data);
        assert_eq!(bytes.len(), 4 + 32 * 3 + 8 + 32);
        assert_eq!(
            <QrBucket as WireHeader>::data_from_bytes(&bytes),
            Some(data)
        );
        for truncation in [0, 4, 36, 68, 100, 108, bytes.len() - 1] {
            assert_eq!(<QrBucket as WireHeader>::data_from_bytes(&bytes[..truncation]), None);
        }
        let mut longer = bytes.clone();
        longer.push(0);
        assert_eq!(<QrBucket as WireHeader>::data_from_bytes(&longer), None);
    }

    #[test]
    fn spendable_data_round_trip() {
        let data = (
            Commitment::from(Fp::from(5)),
            EpochIndex::new(2),
            Anchor(Fp::from(17)),
        );
        let bytes = <NoteSpendable as WireHeader>::data_to_bytes(&data);
        assert_eq!(bytes.len(), 32 + 4 + 32);
        assert_eq!(
            <NoteSpendable as WireHeader>::data_from_bytes(&bytes),
            Some(data)
        );
    }
}
