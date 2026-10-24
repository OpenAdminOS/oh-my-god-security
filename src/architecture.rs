//! Architecture map of a reviewed target application.
//!
//! The Map phase of an OMGS review writes `architecture.json` (see
//! `schemas/architecture.schema.json`); this module renders it deterministically
//! to Markdown and a self-contained, offline HTML page with an auto-laid-out
//! flow graph. It is descriptive only and never changes a verdict. Every
//! free-text field is target-derived and is escaped before rendering.
//!
//! Determinism: the layout uses integer arithmetic only, orders nodes with a
//! fixed-iteration barycenter heuristic broken by input order then id, and never
//! embeds a timestamp. The same input renders byte-identical output.

use crate::html_escape;
use serde::Deserialize;

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ArchitectureFile {
    #[serde(default)]
    pub target: String,
    #[serde(default)]
    pub source_ref: String,
    #[serde(default)]
    pub generated: Generated,
    #[serde(default)]
    pub stack: Stack,
    #[serde(default)]
    pub zones: Vec<Zone>,
    #[serde(default)]
    pub principals: Vec<Principal>,
    #[serde(default)]
    pub components: Vec<Component>,
    #[serde(default)]
    pub boundaries: Vec<Boundary>,
    #[serde(default)]
    pub flows: Vec<Flow>,
    #[serde(default)]
    pub input_surfaces: Vec<InputSurface>,
    #[serde(default)]
    pub unexamined: Vec<String>,
    #[serde(default)]
    pub notes: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Generated {
    #[serde(default)]
    pub run: String,
    #[serde(default)]
    pub by: String,
    #[serde(default)]
    pub updated_ms: Option<i64>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Stack {
    #[serde(default)]
    pub languages: Vec<String>,
    #[serde(default)]
    pub frameworks: Vec<String>,
    #[serde(default)]
    pub package_managers: Vec<String>,
    #[serde(default)]
    pub runtimes: Vec<String>,
    #[serde(default)]
    pub datastores: Vec<String>,
    #[serde(default)]
    pub notes: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Zone {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub trust: Option<String>,
    #[serde(default)]
    pub notes: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Principal {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub notes: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Component {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub zone: String,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub tech: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub entry_point: bool,
    #[serde(default)]
    pub notes: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Boundary {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub between: Vec<String>,
    #[serde(default)]
    pub enforcement: Vec<String>,
    #[serde(default)]
    pub notes: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Flow {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub from: String,
    #[serde(default)]
    pub to: String,
    #[serde(default)]
    pub data: String,
    #[serde(default)]
    pub protocol: String,
    #[serde(default)]
    pub authn: String,
    #[serde(default)]
    pub authz: String,
    #[serde(default)]
    pub crosses: String,
    #[serde(default)]
    pub notes: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct InputSurface {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub component: String,
    #[serde(default)]
    pub attacker: String,
    #[serde(default)]
    pub notes: String,
}

/// Parse an architecture map from JSON text. Lenient: unknown fields are
/// ignored and unrecognised enum-like values are kept as plain strings.
pub fn from_json(text: &str) -> Result<ArchitectureFile, String> {
    serde_json::from_str(text).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Structural checks on an architecture map. Returns every violation as a
/// human-readable string; an empty vec means the map is coherent enough to
/// render.
pub fn validate_architecture(a: &ArchitectureFile) -> Vec<String> {
    let mut errs = Vec::new();
    if a.target.trim().is_empty() {
        errs.push("target is empty".to_string());
    }
    if a.zones.is_empty() {
        errs.push("zones is empty; map at least one trust zone".to_string());
    }
    if a.components.is_empty() {
        errs.push("components is empty; map at least one component".to_string());
    }

    dup_check(&mut errs, "zone", a.zones.iter().map(|z| z.id.as_str()));
    dup_check(
        &mut errs,
        "principal",
        a.principals.iter().map(|p| p.id.as_str()),
    );
    dup_check(
        &mut errs,
        "component",
        a.components.iter().map(|c| c.id.as_str()),
    );
    dup_check(
        &mut errs,
        "boundary",
        a.boundaries.iter().map(|b| b.id.as_str()),
    );
    dup_check(
        &mut errs,
        "input_surface",
        a.input_surfaces.iter().map(|s| s.id.as_str()),
    );

    let zone_ids: std::collections::HashSet<&str> = a.zones.iter().map(|z| z.id.as_str()).collect();
    let comp_ids: std::collections::HashSet<&str> =
        a.components.iter().map(|c| c.id.as_str()).collect();
    let boundary_ids: std::collections::HashSet<&str> =
        a.boundaries.iter().map(|b| b.id.as_str()).collect();

    for c in &a.components {
        if c.id.trim().is_empty() {
            errs.push("a component has an empty id".to_string());
        }
        if !c.zone.is_empty() && !zone_ids.contains(c.zone.as_str()) {
            errs.push(format!(
                "component '{}': zone '{}' is not defined",
                c.id, c.zone
            ));
        }
    }
    for (i, f) in a.flows.iter().enumerate() {
        let label = if f.id.is_empty() {
            format!("flows[{i}]")
        } else {
            format!("flow '{}'", f.id)
        };
        if !comp_ids.contains(f.from.as_str()) {
            errs.push(format!("{label}: from '{}' is not a component", f.from));
        }
        if !comp_ids.contains(f.to.as_str()) {
            errs.push(format!("{label}: to '{}' is not a component", f.to));
        }
        if !f.crosses.is_empty() && !boundary_ids.contains(f.crosses.as_str()) {
            errs.push(format!(
                "{label}: crosses '{}' is not a boundary",
                f.crosses
            ));
        }
    }
    for b in &a.boundaries {
        if !b.between.is_empty() {
            if b.between.len() != 2 {
                errs.push(format!(
                    "boundary '{}': between must name exactly two zones",
                    b.id
                ));
            }
            for z in &b.between {
                if !zone_ids.contains(z.as_str()) {
                    errs.push(format!("boundary '{}': zone '{}' is not defined", b.id, z));
                }
            }
        }
    }
    for s in &a.input_surfaces {
        if !comp_ids.contains(s.component.as_str()) {
            errs.push(format!(
                "input_surface '{}': component '{}' is not defined",
                s.id, s.component
            ));
        }
    }
    errs
}

fn dup_check<'a>(errs: &mut Vec<String>, kind: &str, ids: impl Iterator<Item = &'a str>) {
    let mut seen = std::collections::HashSet::new();
    for id in ids {
        if id.is_empty() {
            continue;
        }
        if !seen.insert(id) {
            errs.push(format!("duplicate {kind} id '{id}'"));
        }
    }
}

// ---------------------------------------------------------------------------
// Deterministic layered layout
// ---------------------------------------------------------------------------

const NODE_W: i64 = 212;
const NODE_H: i64 = 78;
const COL_GAP: i64 = 104;
const ROW_GAP: i64 = 30;
const MARGIN_X: i64 = 40;
const MARGIN_TOP: i64 = 72;
const MARGIN_BOTTOM: i64 = 64;
const COL_PITCH: i64 = NODE_W + COL_GAP;
const ROW_PITCH: i64 = NODE_H + ROW_GAP;
const BARY_SCALE: i64 = 1000;

const ZONE_ACCENTS: [&str; 6] = [
    "var(--blue)",
    "var(--violet)",
    "var(--green)",
    "var(--amber)",
    "var(--link)",
    "var(--muted)",
];

struct Node {
    comp: usize, // index into components
    col: usize,
    input_index: usize,
    x: i64,
    y: i64,
}

struct Edge {
    from: usize, // node index
    to: usize,   // node index
    crossing: bool,
}

struct Diagram {
    nodes: Vec<Node>,
    edges: Vec<Edge>,
    width: i64,
    height: i64,
}

fn layout(a: &ArchitectureFile) -> Diagram {
    // Column per zone, in the file's zone order; a component whose zone is
    // unknown goes to a trailing synthetic column.
    let zone_col: std::collections::HashMap<&str, usize> = a
        .zones
        .iter()
        .enumerate()
        .map(|(i, z)| (z.id.as_str(), i))
        .collect();
    let unknown_col = a.zones.len();
    let mut has_unknown = false;

    let mut nodes: Vec<Node> = Vec::with_capacity(a.components.len());
    for (i, c) in a.components.iter().enumerate() {
        let col = match zone_col.get(c.zone.as_str()) {
            Some(&c) => c,
            None => {
                has_unknown = true;
                unknown_col
            }
        };
        nodes.push(Node {
            comp: i,
            col,
            input_index: i,
            x: 0,
            y: 0,
        });
    }
    let col_count = a.zones.len() + if has_unknown { 1 } else { 0 };

    // node index for each component id (first wins)
    let comp_node: std::collections::HashMap<&str, usize> = {
        let mut m = std::collections::HashMap::new();
        for (ni, n) in nodes.iter().enumerate() {
            m.entry(a.components[n.comp].id.as_str()).or_insert(ni);
        }
        m
    };

    // columns -> ordered node indices, initialised in input order
    let mut columns: Vec<Vec<usize>> = vec![Vec::new(); col_count.max(1)];
    for (ni, n) in nodes.iter().enumerate() {
        columns[n.col].push(ni);
    }

    // adjacency (undirected) for the barycenter heuristic, plus directed edges
    let mut adj: Vec<Vec<usize>> = vec![Vec::new(); nodes.len()];
    let mut edges: Vec<Edge> = Vec::new();
    for f in &a.flows {
        let (Some(&fi), Some(&ti)) = (comp_node.get(f.from.as_str()), comp_node.get(f.to.as_str()))
        else {
            continue; // dangling flow: skip in the diagram, validate reports it
        };
        if fi == ti {
            continue;
        }
        adj[fi].push(ti);
        adj[ti].push(fi);
        let crossing = !f.crosses.is_empty()
            || a.components[nodes[fi].comp].zone != a.components[nodes[ti].comp].zone;
        edges.push(Edge {
            from: fi,
            to: ti,
            crossing,
        });
    }

    // row index of each node within its column, kept current across sweeps
    let mut row_of: Vec<usize> = vec![0; nodes.len()];
    let refresh_rows = |columns: &Vec<Vec<usize>>, row_of: &mut Vec<usize>| {
        for col in columns {
            for (r, &ni) in col.iter().enumerate() {
                row_of[ni] = r;
            }
        }
    };
    refresh_rows(&columns, &mut row_of);

    // Four barycenter sweeps. Deterministic: ties break by input order then id.
    for sweep in 0..4 {
        let order: Vec<usize> = if sweep % 2 == 0 {
            (0..columns.len()).collect()
        } else {
            (0..columns.len()).rev().collect()
        };
        for c in order {
            // compute a sort key for each node in column c
            let mut keyed: Vec<(i64, usize, &str, usize)> = columns[c]
                .iter()
                .map(|&ni| {
                    let neighbors = &adj[ni];
                    let bary = if neighbors.is_empty() {
                        row_of[ni] as i64 * BARY_SCALE
                    } else {
                        let sum: i64 = neighbors.iter().map(|&nb| row_of[nb] as i64).sum();
                        sum * BARY_SCALE / neighbors.len() as i64
                    };
                    (
                        bary,
                        nodes[ni].input_index,
                        a.components[nodes[ni].comp].id.as_str(),
                        ni,
                    )
                })
                .collect();
            keyed.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)).then(a.2.cmp(b.2)));
            columns[c] = keyed.into_iter().map(|t| t.3).collect();
            refresh_rows(&columns, &mut row_of);
        }
    }

    // Coordinates. Each column is vertically centred against the tallest.
    let col_height = |n: usize| -> i64 {
        if n == 0 {
            0
        } else {
            n as i64 * NODE_H + (n as i64 - 1) * ROW_GAP
        }
    };
    let max_h = columns
        .iter()
        .map(|col| col_height(col.len()))
        .max()
        .unwrap_or(0);
    for (c, col) in columns.iter().enumerate() {
        let h = col_height(col.len());
        let y_off = (max_h - h) / 2;
        for (r, &ni) in col.iter().enumerate() {
            nodes[ni].x = MARGIN_X + c as i64 * COL_PITCH;
            nodes[ni].y = MARGIN_TOP + y_off + r as i64 * ROW_PITCH;
        }
    }

    let cols = col_count.max(1) as i64;
    let width = MARGIN_X * 2 + cols * NODE_W + (cols - 1).max(0) * COL_GAP;
    let height = MARGIN_TOP + max_h + MARGIN_BOTTOM;
    Diagram {
        nodes,
        edges,
        width,
        height,
    }
}

// ---------------------------------------------------------------------------
// SVG rendering (integer coords, solid fills, polygon arrowheads, no url())
// ---------------------------------------------------------------------------

fn trunc(s: &str, n: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= n {
        s.to_string()
    } else {
        let mut t: String = chars[..n.saturating_sub(1)].iter().collect();
        t.push('\u{2026}');
        t
    }
}

fn accent_for(a: &ArchitectureFile, comp: usize) -> &'static str {
    let c = &a.components[comp];
    if c.entry_point || is_surface(a, &c.id) {
        return "var(--red)";
    }
    match a.zones.iter().position(|z| z.id == c.zone) {
        Some(i) => ZONE_ACCENTS[i % ZONE_ACCENTS.len()],
        None => "var(--muted)",
    }
}

fn is_surface(a: &ArchitectureFile, comp_id: &str) -> bool {
    a.input_surfaces.iter().any(|s| s.component == comp_id)
}

fn render_svg(a: &ArchitectureFile, d: &Diagram) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "<svg viewBox=\"0 0 {w} {h}\" width=\"{w}\" height=\"{h}\" role=\"img\" aria-label=\"Architecture flow graph of the reviewed application\" class=\"arch-svg\">",
        w = d.width,
        h = d.height
    ));

    // zone bands + headers (background)
    for (c, z) in a.zones.iter().enumerate() {
        let x = MARGIN_X + c as i64 * COL_PITCH - COL_GAP / 2;
        let bw = NODE_W + COL_GAP;
        s.push_str(&format!(
            "<rect x=\"{x}\" y=\"{y}\" width=\"{bw}\" height=\"{bh}\" rx=\"14\" class=\"arch-band\"/>",
            x = x,
            y = MARGIN_TOP - 36,
            bh = d.height - (MARGIN_TOP - 36) - 16
        ));
        let cx = MARGIN_X + c as i64 * COL_PITCH + NODE_W / 2;
        s.push_str(&format!(
            "<text x=\"{cx}\" y=\"{y}\" text-anchor=\"middle\" class=\"arch-zone\">{name}</text>",
            cx = cx,
            y = MARGIN_TOP - 44,
            name = html_escape(&trunc(zone_label(z), 26))
        ));
    }

    // edges first (under nodes)
    for e in &d.edges {
        let (fx2, fcy) = (d.nodes[e.from].x + NODE_W, d.nodes[e.from].y + NODE_H / 2);
        let (bx, bcy) = (d.nodes[e.to].x, d.nodes[e.to].y + NODE_H / 2);
        let class = if e.crossing {
            "arch-edge crossing"
        } else {
            "arch-edge"
        };
        if bx >= fx2 {
            // forward: smooth S curve with horizontal tangents
            let dx = ((bx - fx2) / 2).clamp(40, 160);
            s.push_str(&format!(
                "<path d=\"M{fx2} {fcy} C {c1x} {fcy} {c2x} {bcy} {bx} {bcy}\" class=\"{class}\" fill=\"none\"/>",
                fx2 = fx2,
                fcy = fcy,
                c1x = fx2 + dx,
                c2x = bx - dx,
                bcy = bcy,
                bx = bx,
                class = class
            ));
        } else {
            // same column or backward: arc out to the right and back, bowed
            // away from the midline so it clears the nodes.
            let bow = 54;
            let out = 70;
            let dir = if bcy <= fcy { -1 } else { 1 };
            s.push_str(&format!(
                "<path d=\"M{fx2} {fcy} C {c1x} {c1y} {c2x} {c2y} {bx} {bcy}\" class=\"{class}\" fill=\"none\"/>",
                fx2 = fx2,
                fcy = fcy,
                c1x = fx2 + out,
                c1y = fcy + dir * bow,
                c2x = bx - out,
                c2y = bcy + dir * bow,
                bx = bx,
                bcy = bcy,
                class = class
            ));
        }
        // arrowhead (polygon) pointing into the target's left edge
        let color = if e.crossing {
            "var(--amber)"
        } else {
            "var(--faint)"
        };
        s.push_str(&format!(
            "<polygon points=\"{ax},{ay1} {bx},{bcy} {ax},{ay2}\" fill=\"{color}\"/>",
            ax = bx - 10,
            ay1 = bcy - 5,
            bx = bx,
            bcy = bcy,
            ay2 = bcy + 5,
            color = color
        ));
    }

    // nodes
    for n in &d.nodes {
        let c = &a.components[n.comp];
        let accent = accent_for(a, n.comp);
        let surface = c.entry_point || is_surface(a, &c.id);
        s.push_str(&format!(
            "<rect x=\"{x}\" y=\"{y}\" width=\"{w}\" height=\"{h}\" rx=\"12\" class=\"arch-node\"/>",
            x = n.x,
            y = n.y,
            w = NODE_W,
            h = NODE_H
        ));
        s.push_str(&format!(
            "<rect x=\"{x}\" y=\"{y}\" width=\"5\" height=\"{h}\" rx=\"2\" fill=\"{accent}\"/>",
            x = n.x,
            y = n.y,
            h = NODE_H,
            accent = accent
        ));
        if surface {
            s.push_str(&format!(
                "<circle cx=\"{cx}\" cy=\"{cy}\" r=\"4\" fill=\"var(--red)\"/>",
                cx = n.x + NODE_W - 14,
                cy = n.y + 14
            ));
        }
        s.push_str(&format!(
            "<text x=\"{tx}\" y=\"{y}\" class=\"arch-name\">{name}</text>",
            tx = n.x + 18,
            y = n.y + 28,
            name = html_escape(&trunc(&c.name, 24))
        ));
        let kind = c.kind.as_deref().unwrap_or("");
        if !kind.is_empty() {
            s.push_str(&format!(
                "<text x=\"{tx}\" y=\"{y}\" class=\"arch-kind\">{k}</text>",
                tx = n.x + 18,
                y = n.y + 46,
                k = html_escape(&trunc(kind, 26))
            ));
        }
        let sub = if !c.tech.is_empty() {
            c.tech.as_str()
        } else {
            c.path.as_str()
        };
        if !sub.is_empty() {
            s.push_str(&format!(
                "<text x=\"{tx}\" y=\"{y}\" class=\"arch-sub\">{t}</text>",
                tx = n.x + 18,
                y = n.y + 64,
                t = html_escape(&trunc(sub, 28))
            ));
        }
    }

    s.push_str("</svg>");
    s
}

fn zone_label(z: &Zone) -> &str {
    if !z.name.is_empty() {
        &z.name
    } else {
        &z.id
    }
}

// ---------------------------------------------------------------------------
// Markdown
// ---------------------------------------------------------------------------

fn md_inline(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '|' => out.push_str("\\|"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\n' | '\r' => out.push(' '),
            '`' => out.push('\''),
            _ => out.push(ch),
        }
    }
    out
}

fn join_list(items: &[String]) -> String {
    if items.is_empty() {
        "none".to_string()
    } else {
        items
            .iter()
            .map(|i| md_inline(i))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

pub fn render_architecture_markdown(a: &ArchitectureFile) -> String {
    let mut m = String::new();
    m.push_str(&format!("# Architecture: {}\n\n", md_inline(&a.target)));
    if !a.source_ref.is_empty() {
        m.push_str(&format!("Source: `{}`\n\n", md_inline(&a.source_ref)));
    }
    m.push_str("Descriptive map produced during reconnaissance. It records how the reviewed application is built and what was examined; it never asserts a finding or a verdict.\n\n");

    m.push_str("## Stack\n\n");
    m.push_str(&format!("- Languages: {}\n", join_list(&a.stack.languages)));
    m.push_str(&format!(
        "- Frameworks: {}\n",
        join_list(&a.stack.frameworks)
    ));
    m.push_str(&format!(
        "- Package managers: {}\n",
        join_list(&a.stack.package_managers)
    ));
    m.push_str(&format!("- Runtimes: {}\n", join_list(&a.stack.runtimes)));
    m.push_str(&format!(
        "- Datastores: {}\n",
        join_list(&a.stack.datastores)
    ));
    if !a.stack.notes.is_empty() {
        m.push_str(&format!("- Notes: {}\n", md_inline(&a.stack.notes)));
    }
    m.push('\n');

    m.push_str("## Components by trust zone\n\n");
    for z in &a.zones {
        let members: Vec<&Component> = a.components.iter().filter(|c| c.zone == z.id).collect();
        m.push_str(&format!(
            "### {}{}\n\n",
            md_inline(zone_label(z)),
            z.trust
                .as_deref()
                .map(|t| format!(" ({})", md_inline(t)))
                .unwrap_or_default()
        ));
        if members.is_empty() {
            m.push_str("_No components mapped in this zone._\n\n");
            continue;
        }
        m.push_str("| Component | Kind | Tech / path | Surface |\n|---|---|---|---|\n");
        for c in members {
            m.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                md_inline(&c.name),
                md_inline(c.kind.as_deref().unwrap_or("")),
                md_inline(if !c.tech.is_empty() { &c.tech } else { &c.path }),
                if c.entry_point || is_surface(a, &c.id) {
                    "yes"
                } else {
                    ""
                }
            ));
        }
        m.push('\n');
    }

    if !a.input_surfaces.is_empty() {
        m.push_str("## Attack surface\n\n");
        m.push_str("| Entry point | Component | Reachable by |\n|---|---|---|\n");
        for s in &a.input_surfaces {
            let comp = a
                .components
                .iter()
                .find(|c| c.id == s.component)
                .map(|c| c.name.as_str())
                .unwrap_or(s.component.as_str());
            m.push_str(&format!(
                "| {} | {} | {} |\n",
                md_inline(if !s.name.is_empty() { &s.name } else { &s.id }),
                md_inline(comp),
                md_inline(&s.attacker)
            ));
        }
        m.push('\n');
    }

    if !a.boundaries.is_empty() {
        m.push_str("## Trust boundaries\n\n");
        for b in &a.boundaries {
            m.push_str(&format!("- **{}**", md_inline(&b.name)));
            if b.between.len() == 2 {
                m.push_str(&format!(
                    " ({} to {})",
                    md_inline(zone_name(a, &b.between[0])),
                    md_inline(zone_name(a, &b.between[1]))
                ));
            }
            if !b.enforcement.is_empty() {
                m.push_str(&format!(" enforced by {}", join_list(&b.enforcement)));
            }
            m.push('\n');
        }
        m.push('\n');
    }

    if !a.flows.is_empty() {
        m.push_str("## Data flows\n\n");
        m.push_str("| From | To | Data | Protocol | Authn | Authz | Crosses |\n|---|---|---|---|---|---|---|\n");
        for f in &a.flows {
            m.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {} |\n",
                md_inline(comp_name(a, &f.from)),
                md_inline(comp_name(a, &f.to)),
                md_inline(&f.data),
                md_inline(&f.protocol),
                md_inline(&f.authn),
                md_inline(&f.authz),
                if f.crosses.is_empty() {
                    String::new()
                } else {
                    md_inline(&f.crosses)
                }
            ));
        }
        m.push('\n');
    }

    if !a.principals.is_empty() {
        m.push_str("## Principals\n\n");
        for p in &a.principals {
            m.push_str(&format!(
                "- {}{}\n",
                md_inline(&p.name),
                p.kind
                    .as_deref()
                    .map(|k| format!(" ({})", md_inline(k)))
                    .unwrap_or_default()
            ));
        }
        m.push('\n');
    }

    m.push_str("## Not examined\n\n");
    if a.unexamined.is_empty() {
        m.push_str(
            "_Nothing recorded as unexamined. Absence of an entry is not a claim of coverage._\n\n",
        );
    } else {
        for u in &a.unexamined {
            m.push_str(&format!("- {}\n", md_inline(u)));
        }
        m.push('\n');
    }
    if !a.notes.is_empty() {
        m.push_str(&format!("## Notes\n\n{}\n", md_inline(&a.notes)));
    }
    m
}

fn zone_name<'a>(a: &'a ArchitectureFile, id: &'a str) -> &'a str {
    a.zones
        .iter()
        .find(|z| z.id == id)
        .map(zone_label)
        .unwrap_or(id)
}
fn comp_name<'a>(a: &'a ArchitectureFile, id: &'a str) -> &'a str {
    a.components
        .iter()
        .find(|c| c.id == id)
        .map(|c| c.name.as_str())
        .unwrap_or(id)
}

// ---------------------------------------------------------------------------
// HTML
// ---------------------------------------------------------------------------

pub fn render_architecture_html(a: &ArchitectureFile) -> String {
    let d = layout(a);
    let svg = render_svg(a, &d);

    let mut body = String::new();

    // diagram
    body.push_str("<section class=\"sec\" id=\"diagram\" aria-labelledby=\"diagram-h\">");
    body.push_str("<h2 id=\"diagram-h\">Architecture</h2>");
    body.push_str("<p class=\"intro\">Components grouped by trust zone, left (least trusted) to right. Arrows are data flows; amber arrows cross a trust boundary. A red marker and left edge mark an externally reachable attack surface.</p>");
    body.push_str(&format!("<div class=\"arch-wrap\">{svg}</div>"));
    body.push_str("<ul class=\"arch-legend\"><li><span class=\"swatch surface\"></span>attack surface</li><li><span class=\"swatch cross\"></span>boundary-crossing flow</li></ul>");
    body.push_str("</section>");

    // stack
    body.push_str("<section class=\"sec\" id=\"stack\" aria-labelledby=\"stack-h\">");
    body.push_str("<h2 id=\"stack-h\">Stack</h2><dl class=\"facts\">");
    stack_row(&mut body, "Languages", &a.stack.languages);
    stack_row(&mut body, "Frameworks", &a.stack.frameworks);
    stack_row(&mut body, "Package managers", &a.stack.package_managers);
    stack_row(&mut body, "Runtimes", &a.stack.runtimes);
    stack_row(&mut body, "Datastores", &a.stack.datastores);
    body.push_str("</dl>");
    if !a.stack.notes.is_empty() {
        body.push_str(&format!(
            "<p class=\"note\">{}</p>",
            html_escape(&a.stack.notes)
        ));
    }
    body.push_str("</section>");

    // attack surface
    if !a.input_surfaces.is_empty() {
        body.push_str("<section class=\"sec\" id=\"surface\" aria-labelledby=\"surface-h\">");
        body.push_str("<h2 id=\"surface-h\">Attack surface</h2>");
        body.push_str("<table class=\"grid\"><thead><tr><th>Entry point</th><th>Component</th><th>Reachable by</th></tr></thead><tbody>");
        for s in &a.input_surfaces {
            body.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
                html_escape(if !s.name.is_empty() { &s.name } else { &s.id }),
                html_escape(comp_name(a, &s.component)),
                html_escape(&s.attacker)
            ));
        }
        body.push_str("</tbody></table></section>");
    }

    // components by zone
    body.push_str("<section class=\"sec\" id=\"components\" aria-labelledby=\"components-h\">");
    body.push_str("<h2 id=\"components-h\">Components</h2>");
    for z in &a.zones {
        let members: Vec<&Component> = a.components.iter().filter(|c| c.zone == z.id).collect();
        body.push_str(&format!(
            "<h3>{}{}</h3>",
            html_escape(zone_label(z)),
            z.trust
                .as_deref()
                .map(|t| format!(" <span class=\"muted\">({})</span>", html_escape(t)))
                .unwrap_or_default()
        ));
        if members.is_empty() {
            body.push_str("<p class=\"empty\">No components mapped in this zone.</p>");
            continue;
        }
        body.push_str("<table class=\"grid\"><thead><tr><th>Component</th><th>Kind</th><th>Tech / path</th><th>Surface</th></tr></thead><tbody>");
        for c in members {
            body.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                html_escape(&c.name),
                html_escape(c.kind.as_deref().unwrap_or("")),
                html_escape(if !c.tech.is_empty() { &c.tech } else { &c.path }),
                if c.entry_point || is_surface(a, &c.id) {
                    "yes"
                } else {
                    ""
                }
            ));
        }
        body.push_str("</tbody></table>");
    }
    body.push_str("</section>");

    // boundaries
    if !a.boundaries.is_empty() {
        body.push_str("<section class=\"sec\" id=\"boundaries\" aria-labelledby=\"boundaries-h\">");
        body.push_str("<h2 id=\"boundaries-h\">Trust boundaries</h2><ul class=\"stack-list\">");
        for b in &a.boundaries {
            let between = if b.between.len() == 2 {
                format!(
                    " <span class=\"muted\">({} to {})</span>",
                    html_escape(zone_name(a, &b.between[0])),
                    html_escape(zone_name(a, &b.between[1]))
                )
            } else {
                String::new()
            };
            let enf = if b.enforcement.is_empty() {
                String::new()
            } else {
                format!(" enforced by {}", html_escape(&b.enforcement.join(", ")))
            };
            body.push_str(&format!(
                "<li><strong>{}</strong>{}{}</li>",
                html_escape(&b.name),
                between,
                enf
            ));
        }
        body.push_str("</ul></section>");
    }

    // flows
    if !a.flows.is_empty() {
        body.push_str("<section class=\"sec\" id=\"flows\" aria-labelledby=\"flows-h\">");
        body.push_str("<h2 id=\"flows-h\">Data flows</h2>");
        body.push_str("<table class=\"grid\"><thead><tr><th>From</th><th>To</th><th>Data</th><th>Protocol</th><th>Authn</th><th>Authz</th><th>Crosses</th></tr></thead><tbody>");
        for f in &a.flows {
            body.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                html_escape(comp_name(a, &f.from)),
                html_escape(comp_name(a, &f.to)),
                html_escape(&f.data),
                html_escape(&f.protocol),
                html_escape(&f.authn),
                html_escape(&f.authz),
                html_escape(&f.crosses)
            ));
        }
        body.push_str("</tbody></table></section>");
    }

    // not examined
    body.push_str("<section class=\"sec\" id=\"unexamined\" aria-labelledby=\"unexamined-h\">");
    body.push_str("<h2 id=\"unexamined-h\">Not examined</h2>");
    if a.unexamined.is_empty() {
        body.push_str("<p class=\"empty\">Nothing recorded as unexamined. Absence of an entry is not a claim of coverage.</p>");
    } else {
        body.push_str("<ul class=\"stack-list\">");
        for u in &a.unexamined {
            body.push_str(&format!("<li>{}</li>", html_escape(u)));
        }
        body.push_str("</ul>");
    }
    body.push_str("</section>");

    let masthead = format!(
        "<header class=\"masthead\"><div class=\"wrap\"><p class=\"eyebrow\">OMGS architecture map</p><h1>{target}</h1><dl class=\"meta\"><div><dt>Source</dt><dd>{src}</dd></div><div><dt>Zones</dt><dd>{zones}</dd></div><div><dt>Components</dt><dd>{comps}</dd></div><div><dt>Data flows</dt><dd>{flows}</dd></div></dl></div></header>",
        target = html_escape(if a.target.is_empty() { "application" } else { &a.target }),
        src = html_escape(if a.source_ref.is_empty() { "not recorded" } else { &a.source_ref }),
        zones = a.zones.len(),
        comps = a.components.len(),
        flows = a.flows.len(),
    );
    let footer = format!(
        "<footer class=\"colophon\"><div class=\"wrap\"><p>Generated by omgs {version} from architecture.json. The same input renders the same page. This is a descriptive map, not a finding.</p><p>No OMGS cloud. No telemetry. This page loads no external resources and runs no scripts.</p></div></footer>",
        version = html_escape(env!("CARGO_PKG_VERSION"))
    );

    format!(
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><meta name=\"color-scheme\" content=\"light dark\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\"><title>OMGS architecture map: {repo}</title><style>{css}</style></head><body><a class=\"skip\" href=\"#main\">Skip to map</a>{masthead}<main id=\"main\"><div class=\"wrap\">{body}</div></main>{footer}</body></html>\n",
        repo = html_escape(if a.target.is_empty() { "application" } else { &a.target }),
        css = CSS,
        masthead = masthead,
        body = body,
        footer = footer
    )
}

fn stack_row(body: &mut String, label: &str, items: &[String]) {
    let val = if items.is_empty() {
        "none detected".to_string()
    } else {
        items
            .iter()
            .map(|i| html_escape(i))
            .collect::<Vec<_>>()
            .join(", ")
    };
    body.push_str(&format!("<div><dt>{label}</dt><dd>{val}</dd></div>"));
}

const CSS: &str = r#"
:root{color-scheme:light dark;--bg:#f6f6f4;--surface:#fff;--sunk:#efefec;--text:#18181b;--muted:#4f4f57;--faint:#66666e;--line:#deded9;--link:#1d4ed8;--red:#b42318;--amber:#8a5300;--green:#166534;--violet:#5b3cc4;--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
@media (prefers-color-scheme:dark){:root{--bg:#111113;--surface:#18181b;--sunk:#222226;--text:#ececef;--muted:#b4b4bc;--faint:#9a9aa3;--line:#2e2e34;--link:#9ab8ff;--red:#ff9b93;--amber:#f0c36a;--green:#86d9a0;--violet:#c0b0ff}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.6 system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif}
.wrap{max-width:1040px;margin:0 auto;padding:0 24px}
.skip{position:absolute;left:-9999px}
.skip:focus{left:16px;top:12px;z-index:10;background:var(--surface);color:var(--text);padding:6px 10px;border:1px solid var(--line)}
.masthead{background:var(--surface);border-bottom:1px solid var(--line);padding:32px 0 24px}
.eyebrow{margin:0 0 6px;font-size:12px;font-weight:600;letter-spacing:.08em;text-transform:uppercase;color:var(--faint)}
h1{margin:0 0 18px;font-size:26px;line-height:1.25;font-weight:650;overflow-wrap:anywhere}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px 28px;margin:0}
.meta dt{font-size:11.5px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;color:var(--faint)}
.meta dd{margin:2px 0 0;overflow-wrap:anywhere}
main{padding:4px 0 40px}
.sec{margin-top:40px}
h2{margin:0 0 6px;font-size:19px;font-weight:650}
h3{margin:22px 0 8px;font-size:15px}
.intro{margin:0 0 16px;max-width:74ch;color:var(--muted)}
.note{margin:12px 0 0;font-size:13.5px;color:var(--muted)}
.muted{color:var(--muted);font-weight:400}
.empty{margin:0;padding:14px 16px;border:1px dashed var(--line);border-radius:8px;background:var(--surface);color:var(--muted)}
.facts{display:grid;grid-template-columns:max-content 1fr;gap:6px 18px;margin:0}
.facts div{display:contents}
.facts dt{font-size:11.5px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;color:var(--faint);padding-top:2px}
.facts dd{margin:0;overflow-wrap:anywhere}
.grid{width:100%;border-collapse:collapse;background:var(--surface);border:1px solid var(--line);font-size:14px;margin:0 0 8px}
.grid th{text-align:left;padding:9px 12px;border-bottom:1px solid var(--line);font-size:11.5px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;color:var(--faint)}
.grid td{padding:9px 12px;border-top:1px solid var(--line);vertical-align:top;overflow-wrap:anywhere}
.stack-list{margin:0;padding-left:20px}
.stack-list li{margin:4px 0}
.arch-wrap{overflow-x:auto;border:1px solid var(--line);border-radius:10px;background:var(--surface);padding:12px}
.arch-svg{display:block;max-width:100%;height:auto}
.arch-band{fill:var(--sunk);opacity:.5}
.arch-zone{font-size:12px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;fill:var(--faint)}
.arch-node{fill:var(--surface);stroke:var(--line);stroke-width:1}
.arch-name{font-size:14px;font-weight:650;fill:var(--text)}
.arch-kind{font-size:11px;font-weight:600;letter-spacing:.04em;text-transform:uppercase;fill:var(--muted)}
.arch-sub{font-size:11.5px;fill:var(--faint);font-family:var(--mono)}
.arch-edge{stroke:var(--faint);stroke-width:2;opacity:.85}
.arch-edge.crossing{stroke:var(--amber);stroke-width:3}
.arch-legend{list-style:none;display:flex;flex-wrap:wrap;gap:18px;margin:12px 0 0;padding:0;font-size:13px;color:var(--muted)}
.arch-legend li{display:flex;align-items:center;gap:7px}
.swatch{width:14px;height:14px;border-radius:4px;display:inline-block}
.swatch.surface{background:var(--red)}
.swatch.cross{background:var(--amber)}
.colophon{padding:18px 0 28px;border-top:1px solid var(--line);font-size:12.5px;color:var(--faint)}
.colophon p{margin:0 0 4px}
@media (max-width:640px){.wrap{padding:0 16px}.facts,.meta{grid-template-columns:1fr}}
"#;
