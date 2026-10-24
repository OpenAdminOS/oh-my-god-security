use crate::critic::CriticReport;
use crate::html_escape;
use crate::model::{Finding, FindingsFile, Location, Verdict};

#[derive(Default)]
pub struct ReportMeta {
    pub repo: String,
    pub source_ref: String,
    pub mode: String,
    pub sandbox: String,
    /// Human readable coverage lines, for example "covered: client:import".
    pub coverage: Vec<String>,
    /// One line sensor summary, for example "gitleaks: 0 hits (2 vendored)".
    pub sensors: Option<String>,
    /// Isolated hunters dispatched this run, when recorded.
    pub hunters: Option<u32>,
    /// Independent verifier identity, when recorded.
    pub verifier: Option<String>,
    /// Total agent/model calls across hunt, challenge and verify, when recorded.
    pub agent_calls: Option<u32>,
    /// Coverage critic result, when the run files were available to check.
    pub critic: Option<CriticReport>,
    /// Model per role, for example "hunter: model-a", from run metadata.
    pub models: Vec<String>,
    /// Recorded reroutes after a refusal, one line each.
    pub reroutes: Vec<String>,
    /// The reviewer's recorded intent answers for this run.
    pub intent_answers: crate::intent::Answers,
}

/// The intent question a record asks: its own text, else the library text
/// for its `intent_id`.
fn question_of(f: &Finding) -> Option<String> {
    nonblank(&f.intent_question).map(String::from).or_else(|| {
        f.intent_id
            .as_deref()
            .and_then(crate::intent::find)
            .map(|q| q.question.clone())
    })
}

/// Recorded answers that apply to a record, as display lines.
fn answers_for(meta: &ReportMeta, f: &Finding) -> Vec<String> {
    let Some(id) = f.intent_id.as_deref() else {
        return Vec::new();
    };
    let mut lines: Vec<String> = Vec::new();
    for loc in std::iter::once(&f.location).chain(&f.locations) {
        for a in crate::intent::applicable(&meta.intent_answers, id, &loc.path) {
            let line = format!("{} (scope {}, from {})", a.answer, a.scope, a.source);
            if !lines.contains(&line) {
                lines.push(line);
            }
        }
    }
    lines
}

/// A record's intent question and any recorded answers, for every verdict,
/// matching what the HTML card shows.
fn push_intent(out: &mut String, meta: &ReportMeta, f: &Finding) {
    if let Some(q) = question_of(f) {
        out.push_str(&format!("Intent question: {q}\n\n"));
    }
    for a in answers_for(meta, f) {
        out.push_str(&format!("Recorded answer: {a}\n\n"));
    }
}

fn models_text(meta: &ReportMeta) -> Option<String> {
    let mut parts = Vec::new();
    if !meta.models.is_empty() {
        parts.push(meta.models.join(", "));
    }
    if !meta.reroutes.is_empty() {
        parts.push(format!("reroutes: {}", meta.reroutes.join("; ")));
    }
    (!parts.is_empty()).then(|| parts.join(". "))
}

fn critic_text(meta: &ReportMeta) -> String {
    meta.critic
        .as_ref()
        .map(|c| c.summary())
        .unwrap_or_else(|| "not run".into())
}

/// One line describing who ran the review and at what cost. Each unrecorded
/// value reads "not recorded" so a report never implies metadata it lacks.
fn run_meta_text(meta: &ReportMeta) -> String {
    let hunters = meta
        .hunters
        .map(|n| n.to_string())
        .unwrap_or_else(|| "not recorded".into());
    let verifier = meta
        .verifier
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or("not recorded");
    let agent_calls = meta
        .agent_calls
        .map(|n| n.to_string())
        .unwrap_or_else(|| "not recorded".into());
    format!("hunters {hunters}, verifier {verifier}, agent calls {agent_calls}")
}

fn confirmed(file: &FindingsFile) -> Vec<&crate::model::Finding> {
    file.findings
        .iter()
        .filter(|f| f.verdict == Verdict::Confirmed)
        .collect()
}

pub fn render_markdown(file: &FindingsFile, meta: &ReportMeta) -> String {
    let conf = confirmed(file);
    let mut out = String::new();
    out.push_str(&format!(
        "# OMGS Security Review\n\nRepository: {} at {}\nMode: {}\nSandbox: {}\n\n",
        meta.repo, meta.source_ref, meta.mode, meta.sandbox
    ));
    let pending = file
        .findings
        .iter()
        .filter(|f| f.verdict == Verdict::NeedsValidation)
        .count();
    let rejected: Vec<_> = file
        .findings
        .iter()
        .filter(|f| f.verdict == Verdict::Rejected)
        .collect();
    let mut families = std::collections::BTreeSet::new();
    for f in &file.findings {
        families.insert(f.family.clone().unwrap_or_else(|| f.attack_class.clone()));
    }
    out.push_str(&format!(
        "Confirmed findings: {}\nNeeds validation: {}\nRejected after verification: {}\nFinding families: {}\n\n",
        conf.len(),
        pending,
        rejected.len(),
        families.len()
    ));
    if let Some(sensors) = &meta.sensors {
        out.push_str(&format!("Sensors: {sensors}\n\n"));
    }
    out.push_str(&format!("Run: {}\n\n", run_meta_text(meta)));
    out.push_str(&format!("Coverage critic: {}\n\n", critic_text(meta)));
    if let Some(models) = models_text(meta) {
        out.push_str(&format!("Models: {models}\n\n"));
    }
    for f in &conf {
        out.push_str(&format!(
            "## {} ({}, {})\n\n{}\n\n{}\n\n",
            f.title,
            f.severity.map(|s| s.label()).unwrap_or("none"),
            f.proof_tier.label(),
            location_line(f),
            f.evidence
        ));
        if let Some(brief) = &f.fix_brief {
            out.push_str(&format!("Fix brief: {brief}\n\n"));
        }
        push_intent(&mut out, meta, f);
    }
    let intent: Vec<_> = file
        .findings
        .iter()
        .filter(|f| f.verdict == Verdict::NeedsValidation)
        .collect();
    if !intent.is_empty() {
        out.push_str("## Needs validation\n\n");
        for f in intent {
            out.push_str(&format!(
                "### {}\n\n{}\n\n{}\n\n",
                f.title,
                location_line(f),
                f.evidence
            ));
            if let Some(p) = &f.prerequisites {
                out.push_str(&format!("Prerequisites: {p}\n\n"));
            }
            push_intent(&mut out, meta, f);
        }
    }
    if !rejected.is_empty() {
        out.push_str("## Rejected after verification\n\n");
        for f in rejected {
            out.push_str(&format!(
                "### {}\n\n{}\n\n{}\n\n",
                f.title,
                location_line(f),
                f.evidence
            ));
            push_intent(&mut out, meta, f);
        }
    }
    if !meta.coverage.is_empty() {
        out.push_str("## Coverage\n\n");
        for line in &meta.coverage {
            out.push_str(&format!("- {line}\n"));
        }
        out.push('\n');
    }
    if let Some(critic) = meta.critic.as_ref().filter(|c| !c.passed()) {
        out.push_str("## Coverage critic gaps\n\n");
        for gap in &critic.gaps {
            out.push_str(&format!("- {gap}\n"));
        }
        out.push('\n');
    }
    out.push_str("Full evidence lives in findings.json. Anything not listed as examined in coverage was not examined.\n");
    out
}

/// One labelled block of evidence prose, for example "Trace" or "Missing fact".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidencePart {
    /// Lead-in exactly as written before its colon, `None` for opening prose.
    pub label: Option<String>,
    pub body: String,
}

/// Lead-ins that open a new evidence block when they start a sentence.
const EVIDENCE_MARKERS: &[&str] = &[
    "Trace",
    "Sandbox evidence",
    "Runner disclosure",
    "Missing fact",
    "Safe manual validation plan",
    "Manual validation plan",
    "Manual plan",
    "Validation plan",
    "Proposed fix",
    "Evaluator adjudication",
    "Evaluator overturn",
    "Evaluator narrowing",
    "Evaluation note",
    "Scope note",
    "Tier note",
    "Partial counterevidence",
    "Counterevidence",
];

/// Lead-ins that open a new paragraph inside one evidence block.
const PARAGRAPH_MARKERS: &[&str] = &[
    "Invariant",
    "Narrowest change",
    "Acceptance check",
    "Observed output",
];

/// Longest lead-in promoted to a label, so ordinary prose is never split.
const MAX_LEAD_IN: usize = 140;

/// Paragraph length after which a sentence boundary starts a new paragraph.
const PARAGRAPH_TARGET: usize = 320;

/// Split evidence prose on its known lead-ins. Text without any lead-in comes
/// back as one unlabelled part, and no text is dropped or reordered.
pub fn split_evidence(text: &str) -> Vec<EvidencePart> {
    split_labeled(text, EVIDENCE_MARKERS)
}

fn split_labeled(text: &str, markers: &[&str]) -> Vec<EvidencePart> {
    // Each cut is (label start, colon index).
    let mut cuts: Vec<(usize, usize)> = Vec::new();
    for (p, ch) in text.char_indices() {
        if !ch.is_ascii_uppercase() || !is_sentence_start(text, p) {
            continue;
        }
        if cuts.last().is_some_and(|&(_, colon)| p <= colon) {
            continue;
        }
        if let Some(colon) = lead_in_end(text, p, markers) {
            cuts.push((p, colon));
        }
    }
    let mut parts = Vec::new();
    let head = text[..cuts.first().map_or(text.len(), |c| c.0)].trim();
    if !head.is_empty() {
        parts.push(EvidencePart {
            label: None,
            body: head.to_string(),
        });
    }
    for (i, &(start, colon)) in cuts.iter().enumerate() {
        let end = cuts.get(i + 1).map_or(text.len(), |c| c.0);
        parts.push(EvidencePart {
            label: Some(text[start..colon].trim().to_string()),
            body: text[colon + 1..end].trim().to_string(),
        });
    }
    parts
}

/// True at the start of the text or after sentence punctuation and whitespace,
/// allowing closing brackets or quotes after the punctuation.
fn is_sentence_start(text: &str, p: usize) -> bool {
    let before = &text[..p];
    let prior = before.trim_end();
    prior.is_empty()
        || (before.ends_with(char::is_whitespace)
            && prior
                .trim_end_matches([')', ']', '"', '\'', '`'])
                .ends_with(['.', '?', '!']))
}

/// Index of the colon closing a lead-in that starts at `start`, if any.
fn lead_in_end(text: &str, start: usize, markers: &[&str]) -> Option<usize> {
    let rest = &text[start..];
    let opens = markers.iter().any(|m| {
        rest.strip_prefix(m)
            .is_some_and(|after| after.starts_with([':', ' ', '(']))
    });
    if !opens {
        return None;
    }
    let mut depth = 0usize;
    for (i, ch) in rest.char_indices() {
        if i > MAX_LEAD_IN {
            return None;
        }
        let ends_word = rest[i + ch.len_utf8()..]
            .chars()
            .next()
            .is_none_or(char::is_whitespace);
        match ch {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            '.' if ends_word => return None,
            ':' if depth == 0 && ends_word => return Some(start + i),
            _ => {}
        }
    }
    None
}

/// Break long prose into paragraphs at sentence boundaries.
fn sentence_chunks(text: &str) -> Vec<&str> {
    let mut chunks = Vec::new();
    let mut start = 0;
    for (i, _) in text.match_indices(". ") {
        let next_upper = text[i + 2..]
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_uppercase());
        if next_upper && i + 1 - start >= PARAGRAPH_TARGET {
            chunks.push(text[start..=i].trim());
            start = i + 2;
        }
    }
    let tail = text[start..].trim();
    if !tail.is_empty() {
        chunks.push(tail);
    }
    chunks
}

/// Escaped paragraphs for one block of prose, with inline lead-ins in bold.
fn render_prose(text: &str) -> String {
    let mut out = String::new();
    for part in split_labeled(text, PARAGRAPH_MARKERS) {
        let lead = part
            .label
            .as_deref()
            .map(|l| format!("<strong>{}:</strong> ", html_escape(l)))
            .unwrap_or_default();
        let chunks = sentence_chunks(&part.body);
        if chunks.is_empty() && !lead.is_empty() {
            out.push_str(&format!("<p>{}</p>", lead.trim_end()));
        }
        for (i, chunk) in chunks.into_iter().enumerate() {
            let lead = if i == 0 { lead.as_str() } else { "" };
            out.push_str(&format!("<p>{lead}{}</p>", html_escape(chunk)));
        }
    }
    out
}

fn evidence_kind(label: &str) -> &'static str {
    let l = label.to_lowercase();
    if l.starts_with("trace") {
        "trace"
    } else if l.starts_with("missing fact") {
        "missing"
    } else if l.starts_with("proposed fix") {
        "fix"
    } else if l.starts_with("evaluator") || l.starts_with("evaluation") {
        "review"
    } else if l.ends_with("plan") {
        "plan"
    } else if l.starts_with("sandbox evidence")
        || l.starts_with("runner disclosure")
        || l.contains("counterevidence")
    {
        "proof"
    } else {
        "note"
    }
}

fn render_evidence_parts(parts: &[&EvidencePart]) -> String {
    let mut out = String::new();
    for part in parts {
        match &part.label {
            None => out.push_str(&format!(
                "<div class=\"ev ev-plain\">{}</div>",
                render_prose(&part.body)
            )),
            Some(label) => out.push_str(&format!(
                "<div class=\"ev ev-{}\"><h5>{}</h5>{}</div>",
                evidence_kind(label),
                html_escape(label),
                render_prose(&part.body)
            )),
        }
    }
    out
}

/// A finding with its stable anchor and its short reference such as "V3".
struct Record<'a> {
    f: &'a Finding,
    anchor: String,
    reference: String,
}

/// Anchors derived from fingerprints, so links survive reruns unchanged.
fn anchors(file: &FindingsFile) -> Vec<String> {
    let mut seen = std::collections::BTreeSet::new();
    file.findings
        .iter()
        .enumerate()
        .map(|(i, f)| {
            let clean: String = f
                .fingerprint
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
                .collect::<String>()
                .to_ascii_lowercase();
            let base = if clean.is_empty() {
                format!("f-record-{}", i + 1)
            } else {
                format!("f-{clean}")
            };
            let mut id = base.clone();
            let mut n = i + 1;
            // Each record also owns "{id}-t" for its heading, so reserve both.
            while seen.contains(&id) || seen.contains(&format!("{id}-t")) {
                id = format!("{base}-{n}");
                n += 1;
            }
            seen.insert(format!("{id}-t"));
            seen.insert(id.clone());
            id
        })
        .collect()
}

fn records<'a>(
    file: &'a FindingsFile,
    ids: &[String],
    verdict: Verdict,
    prefix: char,
) -> Vec<Record<'a>> {
    file.findings
        .iter()
        .zip(ids)
        .filter(|(f, _)| f.verdict == verdict)
        .enumerate()
        .map(|(n, (f, id))| Record {
            f,
            anchor: id.clone(),
            reference: format!("{prefix}{}", n + 1),
        })
        .collect()
}

fn nonblank(value: &Option<String>) -> Option<&str> {
    value.as_deref().map(str::trim).filter(|v| !v.is_empty())
}

fn place(l: &Location) -> String {
    format!(
        "{}{}",
        l.path,
        l.line.map(|n| format!(":{n}")).unwrap_or_default()
    )
}

fn location(f: &Finding) -> String {
    place(&f.location)
}

/// Markdown location line: the primary location, then any further copies.
fn location_line(f: &Finding) -> String {
    if f.locations.is_empty() {
        format!("Location: {}", location(f))
    } else {
        let all: Vec<String> = std::iter::once(&f.location)
            .chain(&f.locations)
            .map(place)
            .collect();
        format!("Locations: {}", all.join(", "))
    }
}

fn verdict_label(verdict: Verdict) -> (&'static str, &'static str) {
    match verdict {
        Verdict::Confirmed => ("confirmed", "Confirmed"),
        Verdict::NeedsValidation => ("pending", "Needs validation"),
        Verdict::Rejected => ("rejected", "Rejected after verification"),
    }
}

/// Summary tile; an empty bucket drops its accent so zero never reads as an alarm.
fn count_tile(kind: &str, n: usize, label: &str, detail: &str) -> String {
    let zero = if n == 0 { " zero" } else { "" };
    format!("<li class=\"count k-{kind}{zero}\"><span class=\"n\">{n}</span><span class=\"l\">{label}</span><span class=\"d\">{detail}</span></li>")
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

fn render_tags(f: &Finding) -> String {
    let (class, text) = verdict_label(f.verdict);
    let mut out = format!(
        "<ul class=\"tags\" aria-label=\"Classification\"><li class=\"tag tag-{class}\">{text}</li><li class=\"tag\">Proof: {}</li>",
        html_escape(f.proof_tier.label())
    );
    if let Some(sev) = f.severity {
        out.push_str(&format!(
            "<li class=\"tag tag-sev\">Severity: {}</li>",
            html_escape(sev.label())
        ));
    }
    out.push_str("</ul>");
    out
}

fn render_facts(f: &Finding) -> String {
    let mut rows: Vec<(&str, String)> = Vec::new();
    for (name, value) in [
        ("Entry point", &f.entry_point),
        ("Sink", &f.sink),
        ("Boundary", &f.boundary),
    ] {
        if !value.trim().is_empty() {
            rows.push((name, html_escape(value)));
        }
    }
    if !f.attack_class.trim().is_empty() {
        rows.push((
            "Class",
            format!("<code>{}</code>", html_escape(&f.attack_class)),
        ));
    }
    if !f.locations.is_empty() {
        let also: Vec<String> = f
            .locations
            .iter()
            .map(|l| format!("<code>{}</code>", html_escape(&place(l))))
            .collect();
        rows.push(("Also at", also.join(" ")));
    }
    for (name, value) in [
        ("Family", &f.family),
        ("Prerequisites", &f.prerequisites),
        ("Hunted by", &f.hunted_by),
        ("Verified by", &f.verified_by),
    ] {
        if let Some(v) = nonblank(value) {
            rows.push((name, html_escape(v)));
        }
    }
    if rows.is_empty() {
        return String::new();
    }
    let mut out = String::from("<dl class=\"facts\">");
    for (name, value) in rows {
        out.push_str(&format!("<div><dt>{name}</dt><dd>{value}</dd></div>"));
    }
    out.push_str("</dl>");
    out
}

fn render_finding(r: &Record, meta: &ReportMeta) -> String {
    let f = r.f;
    let parts = split_evidence(&f.evidence);
    // An open record leads with what is missing, ahead of the supporting trace.
    let (missing, rest): (Vec<&EvidencePart>, Vec<&EvidencePart>) = parts.iter().partition(|p| {
        f.verdict == Verdict::NeedsValidation
            && p.label
                .as_deref()
                .is_some_and(|l| l.starts_with("Missing fact"))
    });
    let mut callouts = String::new();
    if let Some(q) = question_of(f) {
        let answers: String = answers_for(meta, f)
            .iter()
            .map(|a| {
                format!(
                    "<p class=\"answer\">Recorded answer: {}</p>",
                    html_escape(a)
                )
            })
            .collect();
        callouts.push_str(&format!(
            "<div class=\"callout c-intent\"><h4>Question for you</h4><p>{}</p>{answers}</div>",
            html_escape(&q)
        ));
    }
    for part in &missing {
        callouts.push_str(&format!(
            "<div class=\"callout c-missing\"><h4>{}</h4>{}</div>",
            html_escape(part.label.as_deref().unwrap_or("Missing fact")),
            render_prose(&part.body)
        ));
    }
    if let Some(brief) = nonblank(&f.fix_brief) {
        callouts.push_str(&format!(
            "<div class=\"callout c-fix\"><h4>Fix brief</h4>{}</div>",
            render_prose(brief)
        ));
    }
    let caption = if f.verdict == Verdict::Rejected {
        "Why it was ruled out"
    } else {
        "Evidence"
    };
    let evidence = if !rest.is_empty() {
        format!(
            "<div class=\"evidence\"><h4>{caption}</h4>{}</div>",
            render_evidence_parts(&rest)
        )
    } else if missing.is_empty() {
        format!("<div class=\"evidence\"><h4>{caption}</h4><p class=\"note\">No evidence text was recorded for this record.</p></div>")
    } else {
        String::new()
    };
    let fingerprint = if f.fingerprint.trim().is_empty() {
        "not recorded".to_string()
    } else {
        format!("<code>{}</code>", html_escape(&f.fingerprint))
    };
    let (class, _) = verdict_label(f.verdict);
    format!(
        "<article class=\"finding v-{class}\" id=\"{id}\" aria-labelledby=\"{id}-t\"><header class=\"fhead\"><p class=\"ref\">{reference}</p><h3 id=\"{id}-t\">{title}</h3><p class=\"floc\"><code>{loc}</code></p>{tags}</header>{callouts}{facts}{evidence}<p class=\"fp\">Fingerprint {fingerprint}</p></article>",
        id = html_escape(&r.anchor),
        reference = html_escape(&r.reference),
        title = html_escape(&f.title),
        loc = html_escape(&location(f)),
        tags = render_tags(f),
        facts = render_facts(f),
    )
}

fn render_section(id: &str, title: &str, intro: &str, body: &str) -> String {
    let intro = if intro.is_empty() {
        String::new()
    } else {
        format!("<p class=\"intro\">{intro}</p>")
    };
    format!("<section class=\"sec sec-{id}\" id=\"{id}\" aria-labelledby=\"{id}-h\"><h2 id=\"{id}-h\">{title}</h2>{intro}{body}</section>")
}

fn render_cards(list: &[Record], empty: &str, meta: &ReportMeta) -> String {
    if list.is_empty() {
        return format!("<p class=\"empty\">{empty}</p>");
    }
    list.iter().map(|r| render_finding(r, meta)).collect()
}

/// Records that ask the same library question form one group, so one answer
/// resolves them together; a free-text question is its own group.
fn intent_groups<'a>(records: &[&'a Record<'a>]) -> Vec<Vec<&'a Record<'a>>> {
    let mut groups: Vec<Vec<&Record>> = Vec::new();
    for r in records {
        let shared = r.f.intent_id.as_deref().and_then(|id| {
            groups
                .iter()
                .position(|g| g[0].f.intent_id.as_deref() == Some(id))
        });
        match shared {
            Some(i) => groups[i].push(r),
            None => groups.push(vec![r]),
        }
    }
    groups
}

pub fn render_html(file: &FindingsFile, meta: &ReportMeta) -> String {
    let ids = anchors(file);
    let conf = records(file, &ids, Verdict::Confirmed, 'C');
    let pending = records(file, &ids, Verdict::NeedsValidation, 'V');
    let rejected = records(file, &ids, Verdict::Rejected, 'R');
    let intent: Vec<&Record> = conf
        .iter()
        .chain(&pending)
        .chain(&rejected)
        .filter(|r| question_of(r.f).is_some())
        .collect();
    let groups = intent_groups(&intent);
    let pending_open = pending
        .iter()
        .filter(|r| question_of(r.f).is_none())
        .count();
    let mut families = std::collections::BTreeSet::new();
    for f in &file.findings {
        families.insert(f.family.clone().unwrap_or_else(|| f.attack_class.clone()));
    }
    let sensors_text = meta.sensors.as_deref().unwrap_or("not recorded");

    let masthead = format!(
        "<header class=\"masthead\"><div class=\"wrap\"><p class=\"eyebrow\">OMGS security review</p><h1>Security review of {repo}</h1><dl class=\"meta\"><div><dt>Commit</dt><dd><code>{source_ref}</code></dd></div><div><dt>Mode</dt><dd>{mode}</dd></div><div><dt>Sandbox</dt><dd>{sandbox}</dd></div><div><dt>Sensors</dt><dd>{sensors}</dd></div><div><dt>Run</dt><dd>{run}</dd></div>{models}</dl></div></header>",
        repo = html_escape(&meta.repo),
        source_ref = html_escape(&meta.source_ref),
        mode = html_escape(&meta.mode),
        sandbox = html_escape(&meta.sandbox),
        sensors = html_escape(sensors_text),
        run = html_escape(&run_meta_text(meta)),
        models = models_text(meta)
            .map(|m| format!("<div><dt>Models</dt><dd>{}</dd></div>", html_escape(&m)))
            .unwrap_or_default(),
    );

    let nav = format!(
        "<nav class=\"toc\" aria-label=\"Report sections\"><ol><li><a href=\"#summary\">Summary</a></li><li><a href=\"#index\">Index</a></li><li><a href=\"#confirmed\">Confirmed <span class=\"c\">{}</span></a></li><li><a href=\"#intent\">Needs your intent <span class=\"c\">{}</span></a></li><li><a href=\"#pending\">Needs validation <span class=\"c\">{}</span></a></li><li><a href=\"#rejected\">Rejected <span class=\"c\">{}</span></a></li><li><a href=\"#coverage\">Coverage</a></li><li><a href=\"#reading\">Reading this report</a></li></ol></nav>",
        conf.len(),
        groups.len(),
        pending.len(),
        rejected.len(),
    );

    let fix_line = if conf.is_empty() {
        "Nothing to fix from this run. No record reached confirmed.".to_string()
    } else {
        format!(
            "{}, each with the evidence that decided it.",
            plural(conf.len(), "confirmed finding", "confirmed findings")
        )
    };
    let decide_line = if groups.is_empty() {
        "No open questions about intended behavior.".to_string()
    } else {
        format!(
            "{} about intended behavior, listed under Needs your intent.",
            plural(groups.len(), "question", "questions")
        )
    };
    let validate_line = if pending_open == 0 {
        "No other open records.".to_string()
    } else {
        format!(
            "{} a validation step before {} can be confirmed or ruled out.",
            plural(pending_open, "record needs", "records need"),
            if pending_open == 1 { "it" } else { "they" }
        )
    };
    let cleared_line = if rejected.is_empty() {
        "No leads were ruled out in this run.".to_string()
    } else {
        format!(
            "{} ruled out after verification, with the counterevidence recorded.",
            plural(rejected.len(), "lead was", "leads were")
        )
    };
    let summary = render_section(
        "summary",
        "Summary",
        "",
        &format!(
            "<p class=\"lede\">Outcome of {}: {} confirmed, {} needs validation, {} rejected after verification.</p><ul class=\"counts\">{}{}{}</ul><div class=\"asks\"><h3>What this asks of you</h3><ul><li><strong>Fix</strong> {fix_line}</li><li><strong>Decide</strong> {decide_line}</li><li><strong>Validate</strong> {validate_line}</li><li><strong>No action</strong> {cleared_line}</li></ul></div><p class=\"note\">{} across {}. Severity appears only on confirmed findings.</p>",
            plural(file.findings.len(), "record", "records"),
            conf.len(),
            pending.len(),
            rejected.len(),
            count_tile("confirmed", conf.len(), "Confirmed", "Decided by executed proof"),
            count_tile("pending", pending.len(), "Needs validation", "Open, a fact is still missing"),
            count_tile("rejected", rejected.len(), "Rejected after verification", "Ruled out with counterevidence"),
            plural(file.findings.len(), "record", "records"),
            plural(families.len(), "finding family", "finding families"),
        ),
    );

    let mut rows = String::new();
    for r in conf.iter().chain(&pending).chain(&rejected) {
        let (class, text) = verdict_label(r.f.verdict);
        let outcome = match r.f.severity {
            Some(sev) => format!("{text}, {}", html_escape(sev.label())),
            None => text.to_string(),
        };
        let more = if r.f.locations.is_empty() {
            String::new()
        } else {
            format!(
                "<span class=\"more\">and {}</span>",
                plural(r.f.locations.len(), "more location", "more locations")
            )
        };
        let question = if question_of(r.f).is_some() {
            "<span class=\"q\">Has a question</span>"
        } else {
            ""
        };
        rows.push_str(&format!(
            "<tr class=\"v-{class}\"><td>{reference}</td><td><a href=\"#{id}\">{title}</a><code class=\"loc\">{loc}</code>{more}</td><td class=\"out\">{outcome}{question}</td><td class=\"out\">{tier}</td></tr>",
            reference = html_escape(&r.reference),
            id = html_escape(&r.anchor),
            title = html_escape(&r.f.title),
            loc = html_escape(&location(r.f)),
            tier = html_escape(r.f.proof_tier.label()),
        ));
    }
    let index_body = if rows.is_empty() {
        "<p class=\"empty\">findings.json holds no records.</p>".to_string()
    } else {
        format!("<table class=\"index\"><thead><tr><th scope=\"col\">Ref</th><th scope=\"col\">Record</th><th scope=\"col\">Outcome</th><th scope=\"col\">Proof</th></tr></thead><tbody>{rows}</tbody></table>")
    };
    let index = render_section("index", "Index of records", "", &index_body);

    let confirmed_html = render_section(
        "confirmed",
        "Confirmed findings",
        if conf.is_empty() {
            ""
        } else {
            "Each finding here was decided by executed proof and needs a fix."
        },
        &render_cards(
            &conf,
            "No finding was confirmed in this run. Confirmation requires executed proof, so open records stay under Needs validation until their missing fact is established.",
            meta,
        ),
    );

    let intent_body = if groups.is_empty() {
        "<p class=\"empty\">No open questions about intended behavior.</p>".to_string()
    } else {
        let mut items = String::from("<ol class=\"intents\">");
        for (n, group) in groups.iter().enumerate() {
            let first = group[0];
            let refs: Vec<String> = group
                .iter()
                .map(|r| {
                    format!(
                        "<a href=\"#{}\">{}</a>",
                        html_escape(&r.anchor),
                        html_escape(&r.reference)
                    )
                })
                .collect();
            let abouts: String = group
                .iter()
                .map(|r| {
                    format!(
                        "<p class=\"about\"><a href=\"#{id}\">{title}</a> <code>{loc}</code></p>",
                        id = html_escape(&r.anchor),
                        title = html_escape(&r.f.title),
                        loc = html_escape(&location(r.f)),
                    )
                })
                .collect();
            let mut answers: Vec<String> = Vec::new();
            for r in group {
                for a in answers_for(meta, r.f) {
                    if !answers.contains(&a) {
                        answers.push(a);
                    }
                }
            }
            let answers: String = answers
                .iter()
                .map(|a| {
                    format!(
                        "<p class=\"answer\">Recorded answer: {}</p>",
                        html_escape(a)
                    )
                })
                .collect();
            items.push_str(&format!(
                "<li class=\"intent-item\" id=\"q-{id}\"><p class=\"ref\">Q{n}, about {refs}</p><p class=\"question\">{question}</p>{answers}{abouts}</li>",
                n = n + 1,
                id = html_escape(&first.anchor),
                refs = refs.join(", "),
                question = html_escape(&question_of(first.f).unwrap_or_default()),
            ));
        }
        items.push_str("</ol>");
        items
    };
    let intent_html = render_section(
        "intent",
        "Needs your intent",
        if groups.is_empty() {
            ""
        } else {
            "These records turn on how the project is meant to behave. Each question links to its records; one answer resolves every record that asks it."
        },
        &intent_body,
    );

    let pending_html = render_section(
        "pending",
        "Needs validation",
        if pending.is_empty() {
            ""
        } else {
            "These records are plausible from the source but not decided. Each one states what is still missing. None of them is a confirmed vulnerability."
        },
        &render_cards(&pending, "No records need validation.", meta),
    );

    let rejected_html = render_section(
        "rejected",
        "Rejected after verification",
        if rejected.is_empty() {
            ""
        } else {
            "These leads were investigated and ruled out. The counterevidence is kept here so the same question does not need to be reopened."
        },
        &render_cards(&rejected, "No candidates were rejected in this run.", meta),
    );

    let coverage_body = if meta.coverage.is_empty() {
        "<p class=\"empty\">No coverage ledger was supplied for this report.</p>".to_string()
    } else {
        let mut items = String::from("<ul class=\"coverage\">");
        for line in &meta.coverage {
            items.push_str(&format!("<li>{}</li>", html_escape(line)));
        }
        items.push_str("</ul>");
        items
    };
    let critic_body = match &meta.critic {
        None => "<p class=\"note\">Coverage critic: not run for this report.</p>".to_string(),
        Some(c) if c.passed() => format!(
            "<p class=\"note\">Coverage critic: {}. Every candidate was verified by someone other than its hunter, and every unit was examined or closed with a reason.</p>",
            html_escape(&c.summary())
        ),
        Some(c) => {
            let mut items = format!(
                "<div class=\"callout c-missing\"><h4>Coverage critic: {}</h4><ul class=\"gaps\">",
                html_escape(&c.summary())
            );
            for gap in &c.gaps {
                items.push_str(&format!("<li>{}</li>", html_escape(gap)));
            }
            items.push_str("</ul></div>");
            items
        }
    };
    let coverage_html = render_section(
        "coverage",
        "Coverage",
        "Anything not listed here was not examined.",
        &format!("{coverage_body}{critic_body}"),
    );

    let reading_html = render_section(
        "reading",
        "Reading this report",
        "",
        "<dl class=\"reading\"><div><dt>Confirmed</dt><dd>Decided by executed proof at the test proven or sandbox exploited tier. Traced evidence alone is never confirmed.</dd></div><div><dt>Needs validation</dt><dd>A complete trace exists, but a named fact or a question about intent is still open. Not a confirmed vulnerability.</dd></div><div><dt>Rejected after verification</dt><dd>An independent check found concrete counterevidence that defeats the claimed result.</dd></div><div><dt>Proof: traced</dt><dd>Input to sink trace read from source, not executed.</dd></div><div><dt>Proof: test proven</dt><dd>A security invariant test failed on the real code path inside the sandbox, under the project's test runner or an equivalent harness exercising the unmodified target code.</dd></div><div><dt>Proof: sandbox exploited</dt><dd>Shown against a locally built copy of the app on synthetic data, inside the sandbox.</dd></div><div><dt>Fingerprint</dt><dd>Stable identity from attack class, entry point, sink, and boundary, so a record keeps its anchor across runs.</dd></div></dl>",
    );

    let footer = format!(
        "<footer class=\"colophon\"><div class=\"wrap\"><p>Generated by omgs {version} from findings.json. The same input renders the same report. Full evidence lives in findings.json and REPORT.md.</p><p>Mode: {mode}. Sandbox: {sandbox}. Sensors: {sensors}. Run: {run}.</p><p>No OMGS cloud. No telemetry. This page loads no external resources and runs no scripts.</p></div></footer>",
        version = html_escape(env!("CARGO_PKG_VERSION")),
        mode = html_escape(&meta.mode),
        sandbox = html_escape(&meta.sandbox),
        sensors = html_escape(sensors_text),
        run = html_escape(&run_meta_text(meta)),
    );

    format!(
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><meta name=\"color-scheme\" content=\"light dark\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\"><title>OMGS security review: {repo}</title><style>{CSS}</style></head><body><a class=\"skip\" href=\"#main\">Skip to report</a>{masthead}{nav}<main id=\"main\"><div class=\"wrap\">{summary}{index}{confirmed_html}{intent_html}{pending_html}{rejected_html}{coverage_html}{reading_html}</div></main>{footer}</body></html>\n",
        repo = html_escape(&meta.repo),
    )
}

const CSS: &str = r#"
:root{color-scheme:light dark;--bg:#f6f6f4;--surface:#fff;--sunk:#efefec;--text:#18181b;--muted:#4f4f57;--faint:#66666e;--line:#deded9;--link:#1d4ed8;--red:#b42318;--red-bg:#fdf0ee;--amber:#8a5300;--amber-bg:#fcf4e4;--blue:#1d4ed8;--green:#166534;--green-bg:#ebf6ee;--violet:#5b3cc4;--violet-bg:#f2effc;--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
@media (prefers-color-scheme:dark){:root{--bg:#111113;--surface:#18181b;--sunk:#222226;--text:#ececef;--muted:#b4b4bc;--faint:#9a9aa3;--line:#2e2e34;--link:#9ab8ff;--red:#ff9b93;--red-bg:#2b1715;--amber:#f0c36a;--amber-bg:#2a2112;--blue:#9ab8ff;--green:#86d9a0;--green-bg:#12281b;--violet:#c0b0ff;--violet-bg:#211a3d}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.6 system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;-webkit-text-size-adjust:100%}
.wrap{max-width:900px;margin:0 auto;padding:0 24px}
a{color:var(--link)}
code{font-family:var(--mono);font-size:.88em;overflow-wrap:anywhere}
.skip{position:absolute;left:-9999px}
.skip:focus{left:16px;top:12px;z-index:10;background:var(--surface);color:var(--text);padding:6px 10px;border:1px solid var(--line)}
.masthead{background:var(--surface);border-bottom:1px solid var(--line);padding:32px 0 24px}
.eyebrow{margin:0 0 6px;font-size:12px;font-weight:600;letter-spacing:.08em;text-transform:uppercase;color:var(--faint)}
h1{margin:0 0 18px;font-size:26px;line-height:1.25;font-weight:650;overflow-wrap:anywhere}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px 28px;margin:0}
.meta div{min-width:0}
.meta dt,.facts dt,.index th{font-size:11.5px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;color:var(--faint)}
.meta dd{margin:2px 0 0;overflow-wrap:anywhere}
.toc{position:sticky;top:0;z-index:5;background:var(--bg);border-bottom:1px solid var(--line)}
.toc ol{list-style:none;display:flex;flex-wrap:wrap;gap:4px 18px;max-width:900px;margin:0 auto;padding:10px 24px;font-size:13.5px}
.toc a{color:var(--muted);text-decoration:none}
.toc a:hover,.toc a:focus{color:var(--text);text-decoration:underline}
.toc .c{display:inline-block;min-width:1.7em;margin-left:3px;padding:0 6px;border-radius:9px;background:var(--sunk);color:var(--text);font-size:12px;text-align:center;font-variant-numeric:tabular-nums}
main{padding:4px 0 40px}
.sec{margin-top:40px;scroll-margin-top:56px}
h2{margin:0 0 6px;font-size:19px;font-weight:650}
.intro{margin:0 0 16px;max-width:70ch;color:var(--muted)}
.lede{margin:0 0 16px;font-size:16px}
.note{margin:12px 0 0;font-size:13.5px;color:var(--muted)}
.counts{list-style:none;display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin:0 0 16px;padding:0}
.count{background:var(--surface);border:1px solid var(--line);border-top:4px solid var(--line);border-radius:8px;padding:14px 16px}
.count .n{display:block;font-size:30px;font-weight:650;line-height:1.1;font-variant-numeric:tabular-nums}
.count .l{display:block;margin-top:4px;font-weight:600}
.count .d{display:block;margin-top:2px;font-size:13px;color:var(--muted)}
.k-confirmed{border-top-color:var(--red)}
.k-pending{border-top-color:var(--amber)}
.k-rejected{border-top-color:var(--green)}
.count.zero{border-top-color:var(--line)}
.asks{background:var(--surface);border:1px solid var(--line);border-radius:8px;padding:14px 18px}
.asks h3{margin:0 0 6px;font-size:15px}
.asks ul{list-style:none;margin:0;padding:0}
.asks li{display:flex;gap:12px;padding:6px 0;border-top:1px solid var(--line)}
.asks li:first-child{border-top:0}
.asks strong{flex:0 0 6em}
table.index{width:100%;border-collapse:collapse;background:var(--surface);border:1px solid var(--line);font-size:14px}
.index th{text-align:left;padding:9px 12px;border-bottom:1px solid var(--line)}
.index td{padding:9px 12px;border-top:1px solid var(--line);vertical-align:top}
.index td:first-child{font-weight:600;white-space:nowrap;font-variant-numeric:tabular-nums;border-left:4px solid var(--line)}
.index tr.v-confirmed td:first-child{border-left-color:var(--red)}
.index tr.v-pending td:first-child{border-left-color:var(--amber)}
.index tr.v-rejected td:first-child{border-left-color:var(--green)}
.index .loc{display:block;margin-top:2px;font-size:12px;color:var(--faint)}
.index .out{white-space:nowrap;color:var(--muted)}
.index .more{display:block;font-size:12px;color:var(--faint)}
.index .q{display:block;font-size:12.5px;color:var(--violet)}
.finding{background:var(--surface);border:1px solid var(--line);border-left:4px solid var(--line);border-radius:8px;padding:18px 20px;margin:0 0 16px;scroll-margin-top:56px}
.finding.v-confirmed{border-left-color:var(--red)}
.finding.v-pending{border-left-color:var(--amber)}
.finding.v-rejected{border-left-color:var(--green)}
.ref{margin:0;font-size:12px;font-weight:600;letter-spacing:.06em;color:var(--faint);font-variant-numeric:tabular-nums}
.fhead h3{margin:2px 0 4px;font-size:17px;line-height:1.35;font-weight:650}
.floc{margin:0 0 10px;font-size:13px;color:var(--muted)}
.tags{list-style:none;display:flex;flex-wrap:wrap;gap:6px;margin:0;padding:0}
.tag{padding:2px 9px;border:1px solid var(--line);border-radius:999px;background:var(--sunk);color:var(--muted);font-size:12px;font-weight:600}
.tag-confirmed,.tag-sev{border-color:currentColor;background:var(--red-bg);color:var(--red)}
.tag-pending{border-color:currentColor;background:var(--amber-bg);color:var(--amber)}
.tag-rejected{border-color:currentColor;background:var(--green-bg);color:var(--green)}
.callout{margin:14px 0 0;padding:10px 14px;border-left:3px solid;border-radius:6px}
.callout h4{margin:0 0 4px;font-size:12px;letter-spacing:.06em;text-transform:uppercase}
.callout p{margin:0 0 6px;max-width:76ch}
.callout p:last-child{margin-bottom:0}
.c-missing{border-color:var(--amber);background:var(--amber-bg)}
.c-missing h4{color:var(--amber)}
.c-intent{border-color:var(--violet);background:var(--violet-bg)}
.c-intent h4{color:var(--violet)}
.c-fix{border-color:var(--green);background:var(--green-bg)}
.c-fix h4{color:var(--green)}
.facts{display:grid;grid-template-columns:max-content 1fr;gap:6px 18px;margin:16px 0 0;font-size:14px}
.facts div{display:contents}
.facts dt{padding-top:2px}
.facts dd{margin:0;min-width:0;overflow-wrap:anywhere}
.evidence{margin-top:16px;padding-top:12px;border-top:1px solid var(--line)}
.evidence>h4{margin:0 0 10px;font-size:12px;letter-spacing:.06em;text-transform:uppercase;color:var(--faint)}
.ev{margin:0 0 14px;padding-left:12px;border-left:2px solid var(--line)}
.ev:last-child{margin-bottom:0}
.ev h5{margin:0 0 2px;font-size:13px;font-weight:650}
.ev p{margin:0 0 8px;max-width:76ch;overflow-wrap:anywhere}
.ev p:last-child{margin-bottom:0}
.ev-proof{border-left-color:var(--blue)}
.ev-proof h5{color:var(--blue)}
.ev-missing{border-left-color:var(--amber)}
.ev-missing h5{color:var(--amber)}
.ev-plan{border-left:2px dashed var(--amber)}
.ev-fix{border-left-color:var(--green)}
.ev-fix h5{color:var(--green)}
.ev-review{border-left-color:var(--violet)}
.ev-review h5{color:var(--violet)}
.ev-note{color:var(--muted)}
.fp{margin:14px 0 0;font-size:12px;color:var(--faint)}
.empty{margin:0;padding:14px 16px;border:1px dashed var(--line);border-radius:8px;background:var(--surface);color:var(--muted)}
.intents{list-style:none;margin:0;padding:0}
.intent-item{margin:0 0 12px;padding:14px 18px;background:var(--surface);border:1px solid var(--line);border-left:4px solid var(--violet);border-radius:8px;scroll-margin-top:56px}
.question{margin:4px 0 8px;max-width:70ch;font-size:16.5px;line-height:1.5;font-weight:500}
.about{margin:0;font-size:13.5px;color:var(--muted)}
.answer{margin:4px 0 8px;font-size:14px;font-weight:600;color:var(--violet)}
.sec-rejected>.intro{padding:10px 14px;border-left:3px solid var(--green);border-radius:6px;background:var(--green-bg);color:var(--text)}
.gaps{margin:4px 0 0;padding-left:20px;font-size:13.5px}
.coverage{margin:0;padding:12px 18px 12px 36px;background:var(--surface);border:1px solid var(--line);border-radius:8px;font-family:var(--mono);font-size:13px}
.reading{display:grid;grid-template-columns:max-content 1fr;gap:8px 18px;margin:0;font-size:14px}
.reading div{display:contents}
.reading dt{font-weight:600}
.reading dd{margin:0;color:var(--muted)}
.colophon{padding:18px 0 28px;border-top:1px solid var(--line);font-size:12.5px;color:var(--faint)}
.colophon p{margin:0 0 4px}
@media (max-width:640px){.wrap,.toc ol{padding:0 16px}.toc ol{padding-top:8px;padding-bottom:8px}.counts,.facts,.reading{grid-template-columns:1fr}.facts dt,.reading dt{padding-top:6px}.index .out{white-space:normal}}
@media print{
:root{--bg:#fff;--surface:#fff;--sunk:#fff;--text:#000;--muted:#2b2b2b;--faint:#4a4a4a;--line:#c4c4c4;--link:#000;--red:#9b1c13;--red-bg:#fff;--amber:#6b4100;--amber-bg:#fff;--blue:#1e3a8a;--green:#14532d;--green-bg:#fff;--violet:#4c2fa8;--violet-bg:#fff}
@page{margin:15mm 14mm}
body{font-size:10pt;line-height:1.45}
.toc,.skip{display:none}
.wrap{max-width:none;padding:0}
.masthead{padding:0 0 10pt;border-bottom:2px solid #000}
main{padding:0}
.sec{margin-top:18pt}
h2{font-size:13pt;break-after:avoid}
a{color:inherit;text-decoration:none}
.count,.asks,.finding,.intent-item,.empty,.coverage,.callout{border-radius:0}
.count .n{font-size:20pt}
.finding{padding:10pt 12pt;margin-bottom:10pt}
.fhead,.callout,.count,.asks,.intent-item,tr,.facts{break-inside:avoid}
.evidence>h4,.ev h5,.callout h4{break-after:avoid}
}
"#;

pub fn render_sarif(file: &FindingsFile, meta: &ReportMeta) -> String {
    let results: Vec<serde_json::Value> = confirmed(file)
        .iter()
        .map(|f| {
            serde_json::json!({
                "ruleId": f.attack_class,
                "level": "error",
                "message": { "text": format!("{}: {}", f.title, f.evidence) },
                "fingerprints": { "omgs/v1": f.fingerprint },
                "locations": std::iter::once(&f.location)
                    .chain(&f.locations)
                    .map(|l| serde_json::json!({ "physicalLocation": {
                        "artifactLocation": { "uri": l.path },
                        "region": { "startLine": l.line.unwrap_or(1) }
                    }}))
                    .collect::<Vec<_>>()
            })
        })
        .collect();
    serde_json::to_string_pretty(&serde_json::json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": { "name": "omgs", "informationUri": "https://github.com/", "version": env!("CARGO_PKG_VERSION") } },
            "originalUriBaseIds": { "PROJECTROOT": { "uri": meta.repo } },
            "results": results
        }]
    }))
    .unwrap_or_default()
}
