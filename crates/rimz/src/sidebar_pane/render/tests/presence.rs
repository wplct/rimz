use super::*;
use crate::remote::link::LinkTier;
use ratatui::style::Color;

fn footer_text(snapshot: &SidebarSnapshot, width: usize) -> String {
    crate::sidebar_pane::render::chrome::footer_lines(
        snapshot,
        &crate::sidebar_pane::render::theme::Theme::fixed(true),
        width,
    )[0]
    .spans
    .iter()
    .map(|span| span.content.as_ref())
    .collect()
}

fn footer_spans(snapshot: &SidebarSnapshot, width: usize) -> Vec<ratatui::text::Span<'static>> {
    crate::sidebar_pane::render::chrome::footer_lines(
        snapshot,
        &crate::sidebar_pane::render::theme::Theme::fixed(false),
        width,
    )[0]
    .spans
    .clone()
}

fn with_presence(presence: Option<crate::store::snapshot::SidebarPresence>) -> SidebarSnapshot {
    let mut snapshot = snapshot_with(Vec::new());
    snapshot.presence = presence;
    snapshot
}

#[test]
fn idle_presence_badge_renders_muted_elapsed_time() {
    let snapshot = with_presence(Some(crate::store::snapshot::SidebarPresence::Idle {
        idle_ms: 17 * 60_000,
    }));

    let text = footer_text(&snapshot, 32);

    assert!(text.starts_with("zᶻ idle · 17m"));
    assert!(text.ends_with("Alt+p sidebar · ?"));
    let spans = footer_spans(&snapshot, 32);
    let badge = spans
        .iter()
        .find(|span| span.content.contains("idle"))
        .unwrap();
    assert_eq!(badge.style.fg, Some(Color::Indexed(102)));
}

#[test]
fn idle_presence_badge_omits_sub_minute_elapsed_time() {
    let snapshot = with_presence(Some(crate::store::snapshot::SidebarPresence::Idle {
        idle_ms: 17_000,
    }));

    let text = footer_text(&snapshot, 32);

    assert!(text.starts_with("zᶻ idle"));
    assert!(!text.starts_with("zᶻ idle ·"));
    assert!(text.ends_with("Alt+p sidebar · ?"));
}

#[test]
fn idle_presence_badge_floors_elapsed_time_to_minutes() {
    let snapshot = with_presence(Some(crate::store::snapshot::SidebarPresence::Idle {
        idle_ms: 90_000,
    }));

    let text = footer_text(&snapshot, 32);

    assert!(text.starts_with("zᶻ idle · 1m"));
    assert!(text.ends_with("Alt+p sidebar · ?"));
}

#[test]
fn detached_presence_badge_renders_away() {
    let snapshot = with_presence(Some(crate::store::snapshot::SidebarPresence::Detached));

    let text = footer_text(&snapshot, 28);

    assert!(text.starts_with("zᶻ away"));
    assert!(text.ends_with("Alt+p sidebar · ?"));
}

#[test]
fn active_and_unknown_presence_render_no_badge() {
    let active = with_presence(Some(crate::store::snapshot::SidebarPresence::Active));
    let unknown = with_presence(None);

    assert_eq!(footer_text(&active, 20), "   Alt+p sidebar · ?");
    assert_eq!(footer_text(&unknown, 20), "   Alt+p sidebar · ?");
}

#[test]
fn footer_explains_the_configured_sidebar_toggle() {
    let mut snapshot = with_presence(None);

    assert!(
        footer_text(&snapshot, 54).ends_with("Alt+p sidebar/back · ? for help"),
        "the default reminder explains both directions of the toggle",
    );
    assert_eq!(
        footer_text(&snapshot, 22),
        "     Alt+p sidebar · ?",
        "the minimum sidebar width keeps the focus chord visible",
    );

    snapshot.sidebar.focus_key = "control-s".to_owned();
    assert!(
        footer_text(&snapshot, 54).ends_with("Ctrl+s sidebar/back · ? for help"),
        "the reminder uses the binding that RimZ actually parses",
    );

    snapshot.sidebar.focus_key = "off".to_owned();
    assert!(footer_text(&snapshot, 54).ends_with("? for help"));
    assert!(!footer_text(&snapshot, 54).contains("sidebar"));

    snapshot.sidebar.focus_key = "not-a-chord".to_owned();
    assert!(footer_text(&snapshot, 54).ends_with("? for help"));
    assert!(!footer_text(&snapshot, 54).contains("not-a-chord"));
}

#[test]
fn presence_badge_precedes_remote_link_when_both_fit() {
    let mut snapshot = with_presence(Some(crate::store::snapshot::SidebarPresence::Detached));
    snapshot.link = Some(crate::store::snapshot::SidebarLinkHealth {
        rtt_ms: Some(42),
        miss_pct: 0,
        tier: LinkTier::Good,
        freshness: crate::store::snapshot::SidebarLinkFreshness::Fresh,
        sampled_at_ms: 1_700_000_000_000,
    });

    let text = footer_text(&snapshot, 44);

    assert!(text.starts_with("zᶻ away  ⇄ remote 42ms"));
    assert!(text.ends_with("Alt+p sidebar · ?"));
}

#[test]
fn presence_badge_drops_remote_link_when_footer_is_narrow() {
    let mut snapshot = with_presence(Some(crate::store::snapshot::SidebarPresence::Detached));
    snapshot.link = Some(crate::store::snapshot::SidebarLinkHealth {
        rtt_ms: Some(42),
        miss_pct: 0,
        tier: LinkTier::Good,
        freshness: crate::store::snapshot::SidebarLinkFreshness::Fresh,
        sampled_at_ms: 1_700_000_000_000,
    });

    let text = footer_text(&snapshot, 24);

    assert!(text.starts_with("zᶻ away"));
    assert!(!text.contains("remote"));
    assert!(text.ends_with("Alt+p sidebar"));
}

#[test]
fn link_badge_does_not_replace_presence_when_only_link_fits() {
    let mut snapshot = with_presence(Some(crate::store::snapshot::SidebarPresence::Idle {
        idle_ms: 17 * 60_000,
    }));
    snapshot.link = Some(crate::store::snapshot::SidebarLinkHealth {
        rtt_ms: None,
        miss_pct: 0,
        tier: LinkTier::Good,
        freshness: crate::store::snapshot::SidebarLinkFreshness::Stale,
        sampled_at_ms: 1_700_000_000_000,
    });

    let text = footer_text(&snapshot, 22);

    assert!(text.starts_with("zᶻ idle · 17m"));
    assert!(text.ends_with("? help"));
    assert!(!text.contains("remote"));
}
