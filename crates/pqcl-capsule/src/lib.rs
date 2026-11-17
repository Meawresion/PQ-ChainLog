//! Evidence Capsule, Custody Record, and the court-disclosure bundle.
//!
//! | Module | What |
//! |---|---|
//! | [`codec`] | canonical deterministic serialization |
//! | [`record`] | the two-plane data model: capsule and custody record |
//! | [`disclosure`] | the bundle a lab hands a court for one capsule |
//! | [`redaction`] | the court's redaction order and its `0x05` leaf |
//!
//! # The distinction the whole design turns on
//!
//! **The artefact** and **the record of who did what to it** are different
//! objects. `PQ-ChainLog-DESIGN.md` §1 keys and indexes them separately, and
//! both are confidential and both are searchable. The project rules is careful
//! about the novelty here: B-CoC already split an Evidence DB from an Evidence
//! Log, and Turner's Digital Evidence Bags described an evidence container in
//! 2005. What is ours is that **both planes are encrypted and both are
//! searchable**, and that per-capsule selective disclosure falls out of the
//! three-tier structure rather than being bolted on.

pub mod codec;
pub mod disclosure;
pub mod record;
pub mod redaction;

pub use codec::{CodecError, Reader, Writer};
pub use disclosure::{
    Bundle, DisclosureError, DisclosureKeys, SealError, SealedDisclosure, Segment,
};
pub use record::{
    Act, ActorOpening, ActorRef, Capsule, CustodyRecord, Event, OpenedRecord, Params,
    ParamsOpening, Provenance, RecordBody, RecordSignatures, Role,
};
pub use redaction::{Mode, Order, OrderError, Scope, Target};
