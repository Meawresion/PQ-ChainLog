//! Compiles the SP1 guest to RISC-V so the ELF can be embedded.
//!
//! Building the guest from the host's build script is what keeps the two in
//! step: there is no path where the host embeds a stale ELF compiled from an
//! older `relation::check`. Given that draft6 requires the rule to hold
//! identically in circuit and verifier, a stale ELF is precisely the silent
//! divergence to design out rather than remember.

fn main() {
    sp1_build::build_program("../warrant-guest");
}
