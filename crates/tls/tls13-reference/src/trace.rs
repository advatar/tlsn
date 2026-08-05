//! An ordered log of every key-schedule operation.
//!
//! The trace is the reason this crate is useful for debugging the MPC
//! implementation: when MPC and oracle disagree on a final traffic key, the
//! trace says *which derivation* diverged, and [`Trace::render`] prints it in
//! the same layout RFC 8448 uses so the two can be read side by side.

/// One recorded key-schedule operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// An `HKDF-Extract` step.
    Extract {
        /// Which secret this produces, e.g. `"handshake"`.
        secret: &'static str,
        /// The salt (the previous stage's `derived` secret, or zeros).
        salt: Vec<u8>,
        /// The input keying material (PSK or ECDHE shared secret).
        ikm: Vec<u8>,
        /// The extracted secret.
        out: Vec<u8>,
    },
    /// An `HKDF-Expand-Label` / `Derive-Secret` step.
    Expand {
        /// The full RFC-style label, e.g. `"tls13 c hs traffic"`.
        label: String,
        /// The pseudorandom key the expansion runs on.
        prk: Vec<u8>,
        /// The context, a transcript hash for `Derive-Secret` or empty.
        context: Vec<u8>,
        /// The serialized `HkdfLabel`.
        info: Vec<u8>,
        /// The expanded output.
        out: Vec<u8>,
    },
}

impl Step {
    /// The label or secret name identifying this step.
    pub fn label(&self) -> &str {
        match self {
            Step::Extract { secret, .. } => secret,
            Step::Expand { label, .. } => label,
        }
    }

    /// The output of this step.
    pub fn out(&self) -> &[u8] {
        match self {
            Step::Extract { out, .. } | Step::Expand { out, .. } => out,
        }
    }
}

/// An ordered log of key-schedule steps.
#[derive(Debug, Clone, Default)]
pub struct Trace {
    steps: Vec<Step>,
}

impl Trace {
    /// Creates an empty trace.
    pub fn new() -> Self {
        Self::default()
    }

    /// Every step, in the order it was performed.
    pub fn steps(&self) -> &[Step] {
        &self.steps
    }

    /// Records a step.
    pub fn record(&mut self, step: Step) {
        self.steps.push(step);
    }

    /// The first step whose label matches exactly.
    ///
    /// Labels repeat in a full handshake — `"tls13 derived"` occurs twice — so
    /// prefer [`Trace::steps`] with an index when the position matters.
    pub fn find(&self, label: &str) -> Option<&Step> {
        self.steps.iter().find(|s| s.label() == label)
    }

    /// All steps whose label matches exactly, in order.
    pub fn find_all(&self, label: &str) -> Vec<&Step> {
        self.steps.iter().filter(|s| s.label() == label).collect()
    }

    /// Renders the trace in RFC 8448's layout for side-by-side comparison.
    pub fn render(&self) -> String {
        let mut out = String::new();
        for step in &self.steps {
            match step {
                Step::Extract {
                    secret,
                    salt,
                    ikm,
                    out: secret_out,
                } => {
                    out.push_str(&format!("extract secret {secret:?}:\n"));
                    push_field(&mut out, "salt", salt);
                    push_field(&mut out, "IKM", ikm);
                    push_field(&mut out, "secret", secret_out);
                }
                Step::Expand {
                    label,
                    prk,
                    context,
                    info,
                    out: expanded,
                } => {
                    out.push_str(&format!("derive secret {label:?}:\n"));
                    push_field(&mut out, "PRK", prk);
                    push_field(&mut out, "hash", context);
                    push_field(&mut out, "info", info);
                    push_field(&mut out, "expanded", expanded);
                }
            }
            out.push('\n');
        }
        out
    }
}

/// Formats one field the way RFC 8448 does: a name, an octet count, then hex
/// in space-separated pairs wrapped to twelve octets per line.
fn push_field(out: &mut String, name: &str, bytes: &[u8]) {
    if bytes.is_empty() {
        out.push_str(&format!("  {name} (0 octets):  (empty)\n"));
        return;
    }
    out.push_str(&format!("  {name} ({} octets):", bytes.len()));
    for (i, b) in bytes.iter().enumerate() {
        if i % 12 == 0 {
            out.push_str("\n    ");
        }
        out.push_str(&format!("{b:02x} "));
    }
    out.push('\n');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_all_distinguishes_repeated_labels() {
        let mut trace = Trace::new();
        for out in [vec![1u8], vec![2u8]] {
            trace.record(Step::Expand {
                label: "tls13 derived".into(),
                prk: vec![],
                context: vec![],
                info: vec![],
                out,
            });
        }
        assert_eq!(trace.find_all("tls13 derived").len(), 2);
        assert_eq!(trace.find("tls13 derived").unwrap().out(), &[1u8]);
    }

    #[test]
    fn render_marks_empty_context() {
        let mut trace = Trace::new();
        trace.record(Step::Expand {
            label: "tls13 finished".into(),
            prk: vec![0xaa],
            context: vec![],
            info: vec![0xbb],
            out: vec![0xcc],
        });
        let rendered = trace.render();
        assert!(rendered.contains("hash (0 octets):  (empty)"), "{rendered}");
        assert!(rendered.contains("aa"), "{rendered}");
    }
}
