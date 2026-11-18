//! Progress page for Telltale Hooks harness work.
//!
//! `docs/hooks/progress.html` is generated from `docs/hooks/harness-tracker.md`:
//! its Milestones and Progress tables and the newest date in its Log. The test
//! fails when the committed page drifts from the tracker, so the page changes
//! in the same commit as the tracker. Regenerate with
//! `TELLTALE_UPDATE_HOOKS_PROGRESS=1 cargo test --locked --test hooks_progress`.
//!
//! The tracker also has to name every client in the pinned client catalog
//! (`crates/telltale-discover/data/tokscale-registry.tsv`), so a catalog update
//! that adds a client fails here until the tracker has a row for it.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

const UPDATE_ENV: &str = "TELLTALE_UPDATE_HOOKS_PROGRESS";
const TRACKER: &str = "docs/hooks/harness-tracker.md";
const PAGE: &str = "docs/hooks/progress.html";
const CATALOG: &str = "crates/telltale-discover/data/tokscale-registry.tsv";

const MILESTONE_HEADER: [&str; 3] = ["Milestone", "Name", "Reached when"];
const PROGRESS_HEADER: [&str; 12] = [
    "Harness",
    "Catalog",
    "Milestone",
    "Mechanism",
    "Survey",
    "Contract",
    "Capture",
    "Adapter",
    "E2E",
    "Documented",
    "Pin",
    "Next",
];
/// The stage columns of the Progress table.
const STAGES: std::ops::Range<usize> = 4..10;
/// Positions within a harness's stages.
const SURVEY: usize = 0;
const ADAPTER: usize = 3;
const E2E: usize = 4;
/// The Milestone cell of a harness that belongs to none, and the Catalog cell
/// of a harness the catalog does not list.
const NONE: &str = "—";

#[derive(Clone, Copy, PartialEq)]
enum Stage {
    Done,
    Wip,
    Todo,
    NotApplicable,
}

impl Stage {
    fn parse(cell: &str, harness: &str) -> Self {
        match cell {
            "done" => Self::Done,
            "wip" => Self::Wip,
            "todo" => Self::Todo,
            "n/a" => Self::NotApplicable,
            other => panic!("{TRACKER}: {harness} has stage {other:?}; use done, wip, todo or n/a"),
        }
    }

    /// A glyph and a word, so the state never rests on color.
    fn label(self) -> &'static str {
        match self {
            Self::Done => "● done",
            Self::Wip => "◐ in progress",
            Self::Todo => "○ to do",
            Self::NotApplicable => "– n/a",
        }
    }
}

struct Milestone {
    id: String,
    name: String,
    reached_when: String,
}

struct Harness {
    name: String,
    /// The catalog client IDs this row accounts for.
    catalog: Vec<String>,
    milestone: Option<String>,
    mechanism: String,
    stages: Vec<Stage>,
    next: String,
}

struct Tracker {
    milestones: Vec<Milestone>,
    harnesses: Vec<Harness>,
    updated: String,
}

/// Stage counts of a set of harnesses; `n/a` stages are left out.
#[derive(Clone, Copy)]
struct Tally {
    done: usize,
    wip: usize,
    stages: usize,
}

impl Tally {
    fn of<'a>(harnesses: impl Iterator<Item = &'a Harness>) -> Self {
        let mut tally = Self {
            done: 0,
            wip: 0,
            stages: 0,
        };
        for stage in harnesses.flat_map(|harness| harness.stages.iter()) {
            match stage {
                Stage::Done => tally.done += 1,
                Stage::Wip => tally.wip += 1,
                Stage::Todo | Stage::NotApplicable => {}
            }
            if *stage != Stage::NotApplicable {
                tally.stages += 1;
            }
        }
        tally
    }

    /// Whole percent, rounded down; a stage in progress counts half.
    fn percent(self) -> usize {
        (2 * self.done + self.wip) * 100 / (2 * self.stages)
    }
}

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

/// The first table under `heading`: header row first, separator row dropped.
fn table_under(text: &str, heading: &str) -> Vec<Vec<String>> {
    let rows = text
        .lines()
        .skip_while(|line| line.trim() != heading)
        .skip(1)
        .take_while(|line| !line.starts_with('#'))
        .filter(|line| line.starts_with('|'))
        .map(|line| {
            line.trim()
                .trim_matches('|')
                .split('|')
                .map(|cell| cell.trim().to_owned())
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    assert!(rows.len() > 2, "{TRACKER}: no table under {heading:?}");
    let mut rows = rows;
    rows.remove(1);
    rows
}

fn parse_tracker(text: &str) -> Tracker {
    let mut milestone_rows = table_under(text, "## Milestones");
    assert_eq!(
        milestone_rows.remove(0),
        MILESTONE_HEADER,
        "{TRACKER}: Milestones table columns changed"
    );
    let milestones = milestone_rows
        .into_iter()
        .map(|row| {
            let [id, name, reached_when] = <[String; 3]>::try_from(row)
                .unwrap_or_else(|row| panic!("{TRACKER}: malformed milestone row {row:?}"));
            Milestone {
                id,
                name,
                reached_when,
            }
        })
        .collect::<Vec<_>>();

    let mut progress_rows = table_under(text, "## Progress");
    assert_eq!(
        progress_rows.remove(0),
        PROGRESS_HEADER,
        "{TRACKER}: Progress table columns changed"
    );
    let harnesses = progress_rows
        .into_iter()
        .map(|row| {
            assert_eq!(
                row.len(),
                PROGRESS_HEADER.len(),
                "{TRACKER}: malformed progress row {row:?}"
            );
            let name = row[0].clone();
            let catalog = row[1]
                .split(',')
                .map(|id| id.trim().trim_matches('`').to_owned())
                .filter(|id| id != NONE)
                .collect();
            let milestone = (row[2] != NONE).then(|| row[2].clone());
            if let Some(id) = &milestone {
                assert!(
                    milestones.iter().any(|milestone| &milestone.id == id),
                    "{TRACKER}: {name} names unknown milestone {id:?}"
                );
            }
            Harness {
                stages: row[STAGES]
                    .iter()
                    .map(|cell| Stage::parse(cell, &name))
                    .collect(),
                mechanism: row[3].clone(),
                next: row[11].clone(),
                catalog,
                milestone,
                name,
            }
        })
        .collect::<Vec<_>>();

    for milestone in &milestones {
        assert!(
            Tally::of(members(&harnesses, &milestone.id)).stages > 0,
            "{TRACKER}: milestone {} has no harness stage to complete",
            milestone.id
        );
    }

    let updated = text
        .lines()
        .skip_while(|line| line.trim() != "## Log")
        .filter_map(|line| line.strip_prefix("- "))
        .filter_map(|entry| entry.split_once(':'))
        .map(|(date, _)| date)
        .filter(|date| date.len() == 10 && date.bytes().all(|b| b.is_ascii_digit() || b == b'-'))
        .max()
        .unwrap_or_else(|| panic!("{TRACKER}: the Log has no dated entry"))
        .to_owned();

    Tracker {
        milestones,
        harnesses,
        updated,
    }
}

fn members<'a>(harnesses: &'a [Harness], milestone: &'a str) -> impl Iterator<Item = &'a Harness> {
    harnesses
        .iter()
        .filter(move |harness| harness.milestone.as_deref() == Some(milestone))
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Escaped text with Markdown code spans as `<code>`.
fn inline(text: &str) -> String {
    escape(text)
        .split('`')
        .enumerate()
        .map(|(index, part)| {
            if index % 2 == 1 {
                format!("<code>{part}</code>")
            } else {
                part.to_owned()
            }
        })
        .collect()
}

const STYLE: &str = "\
:root{--plane:#f9f9f7;--surface:#fcfcfb;--ink:#0b0b0b;--ink2:#52514e;--muted:#898781;--hair:#e1e0d9;--fill:#2a78d6;--track:#cde2fb}
@media (prefers-color-scheme:dark){:root{--plane:#0d0d0d;--surface:#1a1a19;--ink:#f0efec;--ink2:#c3c2b7;--hair:#2c2c2a;--fill:#3987e5;--track:#104281}}
*{box-sizing:border-box}
body{margin:0;background:var(--plane);color:var(--ink);font:15px/1.5 system-ui,sans-serif}
main{max-width:960px;margin:0 auto;padding:32px 20px 64px}
section{background:var(--surface);border:1px solid var(--hair);border-radius:8px;padding:20px 24px;margin-top:20px}
h1{font-size:22px;margin:0 0 4px}
h2{font-size:16px;margin:0 0 12px}
a{color:inherit}
code{font-size:13px}
.note,.sub{color:var(--ink2);margin:0}
.hero{font-size:56px;font-weight:600;line-height:1.1;margin:0}
.track{background:var(--track);border-radius:999px;overflow:hidden}
.fill{background:var(--fill);height:100%;border-radius:999px}
.overall{display:flex;gap:2px;margin-top:16px}
.seg{min-width:0}
.seg .track{height:12px}
.seg-label{display:block;color:var(--ink2);font-size:13px;margin-bottom:4px}
.meters{display:grid;grid-template-columns:minmax(0,5fr) minmax(0,4fr) auto;gap:14px 20px;align-items:center}
.meters .track{height:8px}
.meters .name{font-weight:600}
.figure{font-variant-numeric:tabular-nums;text-align:right;white-space:nowrap}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px 20px;margin-top:12px}
.value{font-size:28px;font-weight:600;line-height:1.2;font-variant-numeric:tabular-nums}
.label{color:var(--ink2);font-size:13px}
.scroll{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{text-align:left;padding:6px 10px 6px 0;border-bottom:1px solid var(--hair);vertical-align:top}
th{color:var(--ink2);font-weight:600;white-space:nowrap}
td.stage{white-space:nowrap}
td.todo,td.na{color:var(--muted)}
@media (max-width:640px){.meters{grid-template-columns:minmax(0,1fr) auto}.meters .track{grid-column:1/-1;grid-row:auto}}
";

fn render(tracker: &Tracker) -> String {
    let planned = Tally::of(
        tracker
            .harnesses
            .iter()
            .filter(|harness| harness.milestone.is_some()),
    );
    let tallies = tracker
        .milestones
        .iter()
        .map(|milestone| Tally::of(members(&tracker.harnesses, &milestone.id)))
        .collect::<Vec<_>>();
    let summary = tracker
        .milestones
        .iter()
        .zip(&tallies)
        .map(|(milestone, tally)| format!("{} {}%", milestone.id, tally.percent()))
        .collect::<Vec<_>>()
        .join(", ");

    let mut page = String::new();
    let out = &mut page;
    out.push_str("<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n");
    out.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
    out.push_str("<title>Telltale Hooks: harness progress</title>\n<style>\n");
    out.push_str(STYLE);
    out.push_str("</style>\n</head>\n<body>\n<main>\n");
    out.push_str("<h1>Telltale Hooks: harness progress</h1>\n");
    writeln!(
        out,
        "<p class=\"note\">Generated from <a href=\"harness-tracker.md\">harness-tracker.md</a>, \
         last updated {}. Do not edit this file; change the tracker and regenerate.</p>",
        escape(&tracker.updated)
    )
    .unwrap();

    out.push_str("<section>\n<h2>Checklist completion</h2>\n");
    writeln!(out, "<p class=\"hero\">{}%</p>", planned.percent()).unwrap();
    writeln!(
        out,
        "<p class=\"sub\">{} of {} milestone stages done, {} in progress. \
         A stage in progress counts half. Verify each milestone against its run reports.</p>",
        planned.done, planned.stages, planned.wip
    )
    .unwrap();
    writeln!(
        out,
        "<div class=\"overall\" role=\"img\" aria-label=\"Overall {}%: {}\">",
        planned.percent(),
        escape(&summary)
    )
    .unwrap();
    for (milestone, tally) in tracker.milestones.iter().zip(&tallies) {
        writeln!(
            out,
            "<div class=\"seg\" style=\"flex:{}\" title=\"{} {}: {}%\">\
             <span class=\"seg-label\">{}</span>\
             <div class=\"track\"><div class=\"fill\" style=\"width:{}%\"></div></div></div>",
            tally.stages,
            escape(&milestone.id),
            escape(&milestone.name),
            tally.percent(),
            escape(&milestone.id),
            tally.percent()
        )
        .unwrap();
    }
    out.push_str("</div>\n</section>\n");

    let count = |keep: fn(&Harness) -> bool| tracker.harnesses.iter().filter(|h| keep(h)).count();
    let coverage = [
        ("Tracked", tracker.harnesses.len()),
        ("Surveyed", count(|h| h.stages[SURVEY] == Stage::Done)),
        (
            "Hook found",
            count(|h| h.stages[SURVEY] == Stage::Done && h.stages[ADAPTER] != Stage::NotApplicable),
        ),
        ("Adapter", count(|h| h.stages[ADAPTER] == Stage::Done)),
        ("E2E evidence", count(|h| h.stages[E2E] == Stage::Done)),
    ];
    out.push_str("<section>\n<h2>Coverage</h2>\n");
    out.push_str(
        "<p class=\"sub\">Every harness on the tracker, with or without a milestone. The tracker \
         names every client in the pinned client catalog and others found separately; it is not \
         a complete list of agents.</p>\n<div class=\"tiles\">\n",
    );
    for (label, value) in coverage {
        writeln!(
            out,
            "<div><div class=\"value\">{value}</div><div class=\"label\">{label}</div></div>"
        )
        .unwrap();
    }
    out.push_str("</div>\n</section>\n");

    out.push_str("<section>\n<h2>Milestones</h2>\n<div class=\"meters\">\n");
    for (milestone, tally) in tracker.milestones.iter().zip(&tallies) {
        let figure = format!("{}%", tally.percent());
        writeln!(
            out,
            "<div><div class=\"name\">{} {}</div><div class=\"sub\">{}</div></div>\n\
             <div class=\"track\" title=\"{} of {} stages done, {} in progress\">\
             <div class=\"fill\" style=\"width:{}%\"></div></div>\n\
             <div class=\"figure\">{}</div>",
            escape(&milestone.id),
            inline(&milestone.name),
            inline(&milestone.reached_when),
            tally.done,
            tally.stages,
            tally.wip,
            tally.percent(),
            figure
        )
        .unwrap();
    }
    out.push_str("</div>\n</section>\n");

    out.push_str("<section>\n<h2>Harnesses</h2>\n<div class=\"scroll\">\n<table>\n<thead><tr>");
    for column in PROGRESS_HEADER
        .iter()
        .filter(|column| !["Catalog", "Pin", "Next"].contains(column))
    {
        write!(out, "<th>{column}</th>").unwrap();
    }
    out.push_str("<th>Next</th></tr></thead>\n<tbody>\n");
    for harness in &tracker.harnesses {
        write!(
            out,
            "<tr><td>{}</td><td>{}</td><td>{}</td>",
            inline(&harness.name),
            escape(harness.milestone.as_deref().unwrap_or("Backlog")),
            inline(&harness.mechanism)
        )
        .unwrap();
        for stage in &harness.stages {
            let class = match stage {
                Stage::Done => "done",
                Stage::Wip => "wip",
                Stage::Todo => "todo",
                Stage::NotApplicable => "na",
            };
            write!(out, "<td class=\"stage {class}\">{}</td>", stage.label()).unwrap();
        }
        writeln!(out, "<td>{}</td></tr>", inline(&harness.next)).unwrap();
    }
    out.push_str("</tbody>\n</table>\n</div>\n</section>\n</main>\n</body>\n</html>\n");
    page
}

/// The committed progress page is what the tracker's tables render to, so a
/// tracker change that leaves the page behind fails here.
#[test]
fn progress_page_matches_the_tracker() {
    let tracker = fs::read_to_string(repo_path(TRACKER))
        .expect("read the harness tracker")
        .replace("\r\n", "\n");
    let page = render(&parse_tracker(&tracker));
    if std::env::var_os(UPDATE_ENV).is_some() {
        fs::write(repo_path(PAGE), page).expect("write the progress page");
        return;
    }
    let committed = fs::read_to_string(repo_path(PAGE))
        .unwrap_or_default()
        .replace("\r\n", "\n");
    assert!(
        committed == page,
        "{PAGE} is stale; regenerate with {UPDATE_ENV}=1 cargo test --locked --test hooks_progress"
    );
}

/// One done stage and one stage in progress out of three applicable stages is
/// half the work: in-progress counts half and `n/a` stages are left out.
#[test]
fn a_stage_in_progress_counts_half_and_not_applicable_stages_are_left_out() {
    let tracker = "\
## Milestones

| Milestone | Name | Reached when |
| --- | --- | --- |
| M1 | First | The example harness is enforced |

## Progress

| Harness | Catalog | Milestone | Mechanism | Survey | Contract | Capture | Adapter | E2E | Documented | Pin | Next |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Example | `example` | M1 | Command hook | done | wip | todo | n/a | n/a | n/a | 1.0 | Capture |
| Later | — | — | Command hook | done | done | done | done | done | done | 1.0 | None |

## Log

- 2026-01-02: example.
";

    let page = render(&parse_tracker(tracker));

    assert!(page.contains("<p class=\"hero\">50%</p>"), "{page}");
}

/// Coverage counts every harness on the tracker, with or without a milestone:
/// here three tracked, two surveyed, one of those with a hook, and that one
/// has an adapter and E2E evidence.
#[test]
fn coverage_counts_every_harness_whether_or_not_it_has_a_milestone() {
    let tracker = "\
## Milestones

| Milestone | Name | Reached when |
| --- | --- | --- |
| M1 | First | The example harness is enforced |

## Progress

| Harness | Catalog | Milestone | Mechanism | Survey | Contract | Capture | Adapter | E2E | Documented | Pin | Next |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Enforced | `enforced` | M1 | Command hook | done | done | done | done | done | done | 1.0 | None |
| Hookless | `hookless` | — | None | done | n/a | n/a | n/a | n/a | n/a | — | Recheck |
| Unknown | — | — | Unverified | todo | todo | todo | todo | todo | todo | — | Survey |

## Log

- 2026-01-02: example.
";

    let page = render(&parse_tracker(tracker));

    assert!(
        page.contains(
            "<div><div class=\"value\">3</div><div class=\"label\">Tracked</div></div>\n\
             <div><div class=\"value\">2</div><div class=\"label\">Surveyed</div></div>\n\
             <div><div class=\"value\">1</div><div class=\"label\">Hook found</div></div>\n\
             <div><div class=\"value\">1</div><div class=\"label\">Adapter</div></div>\n\
             <div><div class=\"value\">1</div><div class=\"label\">E2E evidence</div></div>\n"
        ),
        "{page}"
    );
}

/// The tracker accounts for every client in the pinned client catalog, once,
/// and names no client the catalog does not have. A catalog update that adds
/// a client fails here until the tracker has a row for it.
#[test]
fn the_tracker_names_every_catalog_client_once() {
    let catalog = fs::read_to_string(repo_path(CATALOG)).expect("read the client catalog");
    let mut expected = catalog
        .lines()
        .skip(1)
        .map(|line| {
            line.split('\t')
                .nth(2)
                .expect("catalog id column")
                .to_owned()
        })
        .collect::<Vec<_>>();
    expected.sort();
    let tracker = fs::read_to_string(repo_path(TRACKER)).expect("read the harness tracker");
    let mut tracked = parse_tracker(&tracker)
        .harnesses
        .into_iter()
        .flat_map(|harness| harness.catalog)
        .collect::<Vec<_>>();
    tracked.sort();

    assert_eq!(tracked, expected);
}
