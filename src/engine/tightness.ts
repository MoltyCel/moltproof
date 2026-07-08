import type { Mandate, Tightness } from "../types.js";
import { compareDecimal } from "./evaluate.js";

// Mandate-tightness (0 = trivially wide / gameable, 1 = tight). Surfaced next to
// every verdict: an "ADHERENT" over a mandate that allows everything is not a
// strong claim, and the score makes that visible instead of hideable.

// A notional cap this large or larger is treated as effectively "no cap".
const HUGE_NOTIONAL = "1000000000"; // 1e9 quote units
// A validity window this long or longer is treated as effectively "eternal".
const LONG_WINDOW_DAYS = 365;

export function computeTightness(mandate: Mandate): Tightness {
  const c = mandate.constraints;
  const notes: string[] = [];

  // Venue specificity: fewer allowed venues => tighter. 1 venue ~ 1.0, decays.
  const nVenues = Math.max(1, c.allowed_venues.length);
  const venueSpecificity = clamp01(1 / nVenues);
  if (c.allowed_venues.length === 0) notes.push("no venue whitelist — any venue allowed");
  else if (c.allowed_venues.length > 8) notes.push("very broad venue whitelist");

  // Notional tightness: finite, non-huge cap => tighter.
  let notionalTightness: number;
  if (!c.max_position_notional || compareDecimal(c.max_position_notional, HUGE_NOTIONAL) >= 0) {
    notionalTightness = 0;
    notes.push("position cap is effectively unbounded");
  } else {
    // log-scaled: smaller cap => closer to 1. Reference midpoint at 1e5.
    const n = Number(c.max_position_notional);
    notionalTightness = clamp01(1 - Math.log10(Math.max(1, n)) / 9); // 1e0->1 .. 1e9->0
  }

  // Window tightness: bounded, non-eternal window => tighter.
  const from = Date.parse(c.valid_from);
  const until = Date.parse(c.valid_until);
  let windowTightness: number;
  if (!Number.isFinite(from) || !Number.isFinite(until) || until <= from) {
    windowTightness = 0;
    notes.push("validity window missing or non-positive");
  } else {
    const days = (until - from) / 86_400_000;
    windowTightness = clamp01(1 - days / LONG_WINDOW_DAYS);
    if (days >= LONG_WINDOW_DAYS) notes.push("validity window is a year or longer");
  }

  const score = round2((venueSpecificity + notionalTightness + windowTightness) / 3);
  if (score < 0.34) notes.push("LOW tightness — an ADHERENT verdict here is weak; the mandate is permissive");

  return {
    score,
    factors: {
      venueSpecificity: round2(venueSpecificity),
      notionalTightness: round2(notionalTightness),
      windowTightness: round2(windowTightness),
    },
    notes,
  };
}

function clamp01(x: number): number {
  return Math.max(0, Math.min(1, x));
}
function round2(x: number): number {
  return Math.round(x * 100) / 100;
}
