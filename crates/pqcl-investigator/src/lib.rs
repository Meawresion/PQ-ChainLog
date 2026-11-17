//! M8b — the investigator's custody dashboard, and the midterm demo built on
//! it (plan M8b, extended 2026-10-01).
//!
//! A local client that walks draft7's Phases 1–11 against a live chain and
//! shows, at every step, what the investigator's client knows beside what the
//! Aggregation & Index Server actually holds. The dashboard is a rendering
//! surface bound to loopback ([`web`]); the case keys, the custody graph
//! ([`graph`]) and every verification live in this process ([`demo`]).
//!
//! ⛔ **No number from the demo reaches any document.** It runs locally, on one
//! validator, with the host-software Secure Module, and is timed by eye.

pub mod chain;
pub mod demo;
pub mod docs;
pub mod explorer;
pub mod graph;
pub mod perf;
pub mod web;
