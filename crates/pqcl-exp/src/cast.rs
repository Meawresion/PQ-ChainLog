//! One agent per custody role, shared by every harness (M13 A2).
//!
//! ⭐ **Why a harness needs a cast at all.** draft8 gives every event exactly
//! one accountable signer role — the DEFR collects, the DES analyses, the
//! investigator or DES reads, the custodian exports, seals, transfers and
//! disposes — and [`pqcl_pipeline::Agent`] now refuses an event its role may
//! not sign. A harness that signed everything with one key was producing
//! records the library will no longer build, and the paper's own reason is the
//! point: *"a chain in which any credentialed actor may sign any event
//! establishes presence, not responsibility."*
//!
//! One place rather than five: `custody.rs`, `tamper.rs`, `exp6chain.rs` and
//! the two audit profiles all need the same mapping, and a mapping copied five
//! times is a mapping that will disagree with itself.

use pqcl_capsule::{ActorRef, Event, Role};
use pqcl_pipeline::Agent;
use pqcl_primitives::SoftwareMlDsa;

/// The actors a custody stream needs, enrolled by `(role, id)` from
/// [`pqcl_sm::CAST`], each with its own signing key: one per role, plus a
/// second custodian so a bilateral transfer is between two parties.
#[derive(Debug)]
pub struct Cast {
    /// Collects.
    pub defr: Agent,
    /// Analyses.
    pub des: Agent,
    /// Reads.
    pub inv: Agent,
    /// Holds, exports, seals, disposes, and releases in a transfer.
    pub cust: Agent,
    /// The second custodian: witnesses a release and signs its receipt.
    pub lab: Agent,
}

impl Cast {
    /// Fresh keys for every member of [`pqcl_sm::CAST`].
    ///
    /// # Errors
    ///
    /// A key-generation failure.
    pub fn generate() -> Result<Self, Box<dyn core::error::Error>> {
        let enrol = |who: ActorRef| -> Result<Agent, Box<dyn core::error::Error>> {
            Ok(Agent::new(SoftwareMlDsa::generate()?, &who.id, who.role))
        };
        Ok(Self {
            defr: enrol(pqcl_sm::cast_member(Role::Defr))?,
            des: enrol(pqcl_sm::cast_member(Role::Des))?,
            inv: enrol(pqcl_sm::cast_member(Role::Investigator))?,
            cust: enrol(pqcl_sm::evidence_store())?,
            lab: enrol(pqcl_sm::lab_custodian())?,
        })
    }

    fn all(&self) -> [&Agent; 5] {
        [&self.defr, &self.cust, &self.lab, &self.des, &self.inv]
    }

    /// The actor enrolled as `who`.
    #[must_use]
    pub fn member(&self, who: &ActorRef) -> Option<&Agent> {
        self.all().into_iter().find(|a| a.actor_ref() == *who)
    }

    /// The agent accountable for `event`, per draft8's table.
    #[must_use]
    pub const fn signer(&self, event: Event) -> &Agent {
        self.agent(role_for(event))
    }

    /// The agent a harness signs `role` as outside a transfer's receiving
    /// half, which is [`pqcl_sm::cast_member`] (`cast_matches_the_table`).
    #[must_use]
    pub const fn agent(&self, role: Role) -> &Agent {
        match role {
            Role::Defr => &self.defr,
            Role::Des => &self.des,
            Role::Investigator => &self.inv,
            Role::Custodian => &self.cust,
        }
    }

    /// `ρ`, the roster `reg` commits to (§1br F3): every member's `(role,
    /// id)` and verification key.
    #[must_use]
    pub fn roster(&self) -> pqcl_pipeline::accept::Roster {
        pqcl_pipeline::accept::Roster {
            entries: self
                .all()
                .into_iter()
                .map(|a| pqcl_pipeline::accept::RosterEntry {
                    actor: a.actor_ref(),
                    pk: a.public_key().to_vec(),
                })
                .collect(),
        }
    }

    /// Every public key, in [`pqcl_sm::CAST`]'s order.
    #[must_use]
    pub fn public_keys(&self) -> Vec<&[u8]> {
        self.all().into_iter().map(Agent::public_key).collect()
    }

    /// The key that signed a record of `event`.
    #[must_use]
    pub fn public_key_for(&self, event: Event) -> &[u8] {
        self.signer(event).public_key()
    }
}

/// The role a harness signs `event` in, per draft8's table.
///
/// ⭐ **One function, used both ways** (M13 A18): [`Cast::signer`] reads it to
/// pick an agent, and `CaseBuilder` reads it to name the role in an
/// `AppendRequest`. Two `match`es would be two copies of the table, and the
/// harness would then ask the enclave to sign in a role it does not itself use.
///
/// Exhaustive on purpose: a new event type must be assigned a role here, or it
/// will not compile — which is cheaper than discovering at run time that the
/// harness cannot sign it. Where the table admits two roles (`ACCESS`:
/// investigator or DES; `TRANSFER`: custodian or DEFR) the harness picks one,
/// and `every_event_is_signed_by_a_role_that_may_sign_it` checks the pick
/// against the library.
#[must_use]
pub const fn role_for(event: Event) -> Role {
    match event {
        Event::Collect => Role::Defr,
        Event::Analyze => Role::Des,
        Event::Access => Role::Investigator,
        Event::Transfer | Event::Export | Event::Seal | Event::Dispose => Role::Custodian,
    }
}

/// The harness's cast as the actors an appender signs with — the same
/// interface the Secure Module's own cast presents, so `sign_step` builds a
/// harness record and an enclave record by one code path.
impl pqcl_sm::Actors for Cast {
    fn actor(&self, who: &ActorRef) -> Result<&Agent, pqcl_sm::SmError> {
        self.member(who)
            .ok_or_else(|| pqcl_sm::SmError::NoSuchActor {
                role: who.role.byte(),
                id: who.id.clone(),
            })
    }

    fn first_responder(&self) -> Result<&Agent, pqcl_sm::SmError> {
        Ok(self.agent(Role::Defr))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    /// The cast's mapping and the library's table are the same table, or the
    /// harness would build records the library refuses.
    #[test]
    fn every_event_is_signed_by_a_role_that_may_sign_it() {
        let cast = Cast::generate().unwrap();
        for event in [
            Event::Collect,
            Event::Transfer,
            Event::Access,
            Event::Analyze,
            Event::Export,
            Event::Seal,
            Event::Dispose,
        ] {
            let signer = cast.signer(event);
            assert!(
                signer.role().may(event),
                "the cast signs {event:?} with a {:?}, which draft8's table forbids",
                signer.role()
            );
        }
    }

    /// The harness cast is exactly `CAST`, in order, and [`Cast::agent`] picks
    /// the member `cast_member` names — so a harness appending through the
    /// enclave names actors the enclave enrolled.
    #[test]
    fn cast_matches_the_table() {
        let cast = Cast::generate().unwrap();
        let enrolled: Vec<ActorRef> = cast.all().iter().map(|a| a.actor_ref()).collect();
        let table: Vec<ActorRef> = pqcl_sm::CAST
            .iter()
            .map(|(r, id)| ActorRef::new(*r, id))
            .collect();
        assert_eq!(enrolled, table);
        for role in [Role::Defr, Role::Custodian, Role::Des, Role::Investigator] {
            assert_eq!(cast.agent(role).actor_ref(), pqcl_sm::cast_member(role));
        }
        assert_ne!(pqcl_sm::evidence_store(), pqcl_sm::lab_custodian());
    }

    /// Distinct keys for every actor, so a signature actually attributes an
    /// act. One key shared between roles would make the role table
    /// decoration, and one shared between the two custodians would make a
    /// bilateral transfer one party's.
    #[test]
    fn every_actor_has_its_own_key() {
        let cast = Cast::generate().unwrap();
        let keys = cast.public_keys();
        for (i, a) in keys.iter().enumerate() {
            for b in keys.iter().skip(i + 1) {
                assert_ne!(a, b);
            }
        }
    }
}
