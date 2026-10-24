//! Intent question library and the reviewer's recorded answers.
//!
//! The library ships inside the binary. Answers live on the reviewer's machine
//! (never in the reviewed repository, which is attacker-controlled for a
//! third-party target) and are copied into each new run directory.

use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::OnceLock;

#[derive(Debug, Clone, Deserialize)]
pub struct Library {
    pub questions: Vec<Question>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Question {
    pub id: String,
    #[serde(default)]
    pub stacks: Vec<String>,
    #[serde(default)]
    pub attack_classes: Vec<String>,
    pub question: String,
    #[serde(default)]
    pub why: String,
    #[serde(default)]
    pub answers: Vec<String>,
}

const LIBRARY_JSON: &str = include_str!("../skill/intent/library.json");

/// The shipped library. It is checked by tests, so a parse failure here is a
/// build defect, not a runtime condition.
pub fn library() -> &'static Library {
    static LIB: OnceLock<Library> = OnceLock::new();
    LIB.get_or_init(|| serde_json::from_str(LIBRARY_JSON).expect("skill/intent/library.json"))
}

pub fn find(id: &str) -> Option<&'static Question> {
    library().questions.iter().find(|q| q.id == id)
}

/// Questions matching an optional stack and attack class, in library order.
pub fn list(stack: Option<&str>, attack_class: Option<&str>) -> Vec<&'static Question> {
    library()
        .questions
        .iter()
        .filter(|q| stack.is_none_or(|s| q.stacks.iter().any(|x| x == s)))
        .filter(|q| attack_class.is_none_or(|c| q.attack_classes.iter().any(|x| x == c)))
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Answer {
    pub id: String,
    pub answer: String,
    /// `repo` for the whole repository, or a repository-relative path prefix.
    pub scope: String,
    /// Who gave the answer, for example the repository owner's handle.
    pub source: String,
    pub recorded_unix: u64,
}

/// Both fields are required in a file that exists; only an absent file
/// means "no answers yet".
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Answers {
    /// Canonical path of the target these answers belong to. Checked before
    /// answers are copied into a run or rendered, so two repositories never
    /// share answers.
    pub target: String,
    pub answers: Vec<Answer>,
}

/// Where the answers for a canonical target path are stored: one file per
/// target, named by a stable hash of the full path.
pub fn answers_file(omgs_home: &Path, canonical_target: &Path) -> std::path::PathBuf {
    let key = crate::fingerprint(
        "intent-answers",
        &canonical_target.to_string_lossy(),
        "",
        "",
    );
    omgs_home.join("intent").join(format!("{key}.json"))
}

pub fn load_answers(path: &Path) -> Result<Answers, String> {
    match std::fs::read_to_string(path) {
        Ok(text) => parse_answers(&text).map_err(|e| format!("parse {}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Answers::default()),
        Err(e) => Err(format!("read {}: {e}", path.display())),
    }
}

/// Strictly parse an answers file: an object with a string `target` and an
/// `answers` array of objects, no duplicate keys, no positional arrays.
pub fn parse_answers(text: &str) -> Result<Answers, String> {
    let v = crate::shape::strict_json(text)?;
    let top = v.as_object().ok_or("answers file must be a JSON object")?;
    if !top.get("target").is_some_and(|t| t.is_string()) {
        return Err("answers file needs a string target".into());
    }
    let list = top
        .get("answers")
        .and_then(|a| a.as_array())
        .ok_or("answers file needs an answers array")?;
    if list.iter().any(|a| !a.is_object()) {
        return Err("every answer must be a JSON object".into());
    }
    serde_json::from_value(v).map_err(|e| e.to_string())
}

/// Record an answer, replacing any earlier answer for the same id and scope.
pub fn record(answers: &mut Answers, answer: Answer) -> Result<(), String> {
    if find(&answer.id).is_none() {
        return Err(format!("unknown intent id: {}", answer.id));
    }
    for (name, value) in [
        ("answer", &answer.answer),
        ("scope", &answer.scope),
        ("source", &answer.source),
    ] {
        if value.trim().is_empty() {
            return Err(format!("intent answer requires a non-empty {name}"));
        }
    }
    answers
        .answers
        .retain(|a| !(a.id == answer.id && a.scope == answer.scope));
    answers.answers.push(answer);
    answers
        .answers
        .sort_by(|a, b| (&a.id, &a.scope).cmp(&(&b.id, &b.scope)));
    Ok(())
}

/// Answers that apply to a record of `id` at `path`: whole-repository answers
/// plus any whose path prefix contains the location.
pub fn applicable<'a>(answers: &'a Answers, id: &str, path: &str) -> Vec<&'a Answer> {
    answers
        .answers
        .iter()
        .filter(|a| a.id == id)
        .filter(|a| {
            let prefix = a.scope.trim_end_matches('/');
            a.scope == "repo" || path == prefix || path.starts_with(&format!("{prefix}/"))
        })
        .collect()
}
