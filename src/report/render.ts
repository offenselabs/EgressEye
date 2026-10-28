import { SessionSummary, SummaryRow, Verdict } from "../store/session.js";

/**
 * Report rendering: a compact terminal table (ANSI color when supported) and
 * a markdown export. The headline line is the product:
 *   "N contacted — M flagged (malicious x, suspicious y), K unknown, C allowlisted"
 */

const VERDICT_LABEL: Record<Verdict, string> = {
  malicious: "MALICIOUS",
  suspicious: "suspicious",
  unknown: "unknown",
  clean: "clean",
};

function colorize(text: string, code: string, useColor: boolean): string {
  return useColor ? `\x1b[${code}m${text}\x1b[0m` : text;
}

function verdictColor(v: Verdict | null): string {
  switch (v) {
    case "malicious":
      return "1;31";
    case "suspicious":
      return "33";
    case "clean":
      return "2";
    default:
      return "0";
  }
}

function truncate(s: string, max: number): string {
  return s.length <= max ? s : s.slice(0, max - 1) + "…";
}

export function headlineLine(s: SessionSummary): string {
  const parts = [
    `${s.urlUnique} URL${s.urlUnique === 1 ? "" : "s"} contacted`,
    `${s.flaggedCount} flagged (malicious ${s.byVerdict.malicious}, suspicious ${s.byVerdict.suspicious})`,
    `${s.unknownCount} unknown`,
    `${s.cleanCount} allowlisted`,
    `${s.secretCount} secret finding${s.secretCount === 1 ? "" : "s"}`,
  ];
  return parts.join(" — ");
}

export function renderSummary(s: SessionSummary, opts: { color?: boolean; markdown?: boolean; maxRows?: number; all?: boolean } = {}): string {
  const useColor = opts.color ?? Boolean(process.stdout.isTTY && !process.env.NO_COLOR);
  const maxRows = opts.maxRows ?? 25;

  if (opts.markdown) return renderMarkdown(s, Boolean(opts.all));

  const lines: string[] = [];
  lines.push(`EgressEye — session ${s.id}`);
  if (s.startedAt) lines.push(`Started ${s.startedAt}`);
  lines.push(`Tool calls inspected: ${s.toolCalls}`);
  lines.push(headlineLine(s));
  lines.push("");

  const interesting = opts.all ? s.rows : s.rows.filter((r) => r.kind === "secret" || (r.verdict && r.verdict !== "clean"));
  const shown = interesting.slice(0, maxRows);
  const hidden = interesting.length - shown.length;

  if (interesting.length === 0) {
    lines.push("No flagged external contacts. (Allowlisted hosts are omitted; run with --all to see everything.)");
  } else {
    const header = ["VERDICT", "TARGET", "REASON (source)", "SEEN", "TOOLS"];
    const rows = shown.map((r) => ({
      cells: [
        r.kind === "secret" ? "SECRET" : VERDICT_LABEL[r.verdict as Verdict]!,
        r.kind === "secret" ? `${r.value} ${r.reason ?? ""}`.trim() : r.value,
        r.kind === "secret" ? "" : `${truncate(r.reason ?? "", 90)} (${r.source ?? "none"})`,
        `${r.count}×`,
        r.tools.join(","),
      ],
      verdict: r.verdict,
    }));
    lines.push(
      ...renderTable(
        header,
        rows.map((r) => r.cells),
        (rowIdx, col, cell) => (col === 0 ? colorize(cell, verdictColor(rows[rowIdx]?.verdict ?? null), useColor) : cell),
      ),
    );
  }

  for (const agg of s.aggregates) {
    lines.push("");
    lines.push(colorize(`⚠ ${agg}`, "1;33", useColor));
  }
  if (hidden > 0) lines.push(`…and ${hidden} more rows (raise --max-rows)`);
  return lines.join("\n");
}

function renderTable(header: string[], rows: string[][], decorate?: (rowIdx: number, col: number, cell: string) => string): string[] {
  const widths = header.map((h, i) => Math.max(h.length, ...rows.map((r) => (r[i] ?? "").length)));
  const fmt = (cells: string[]) => cells.map((c, i) => (c ?? "").padEnd(widths[i] ?? 0)).join("  ");
  const out: string[] = [];
  out.push(fmt(header));
  out.push(widths.map((w) => "-".repeat(w)).join("  "));
  rows.forEach((row, rowIdx) => {
    const cells = row.map((c, i) => (decorate ? decorate(rowIdx, i, c ?? "") : c ?? ""));
    out.push(cells.map((c, i) => padPlain(c, widths[i] ?? 0)).join("  "));
  });
  return out;
}

function padPlain(s: string, width: number): string {
  const visible = s.replace(/\x1b\[[0-9;]*m/g, "");
  return s + " ".repeat(Math.max(0, width - visible.length));
}

export function renderMarkdown(s: SessionSummary, all = false): string {  const lines: string[] = [];
  lines.push(`## EgressEye report — session \`${s.id}\``);
  lines.push("");
  lines.push(`Tool calls inspected: **${s.toolCalls}**`);
  lines.push("");
  lines.push(headlineLine(s));
  lines.push("");
  if (s.rows.length > 0) {
    lines.push("| Verdict | Target | Reason | Source | Seen | Tools |");
    lines.push("|---|---|---|---|---|---|");
    for (const r of s.rows) {
      if (!all && r.kind === "url" && r.verdict === "clean") continue;
      if (r.kind === "secret") {
        lines.push(`| SECRET | \`${r.value}\` | ${r.reason ?? ""} | | ${r.count}× | ${r.tools.join(", ")} |`);
      } else {
        lines.push(`| ${VERDICT_LABEL[r.verdict as Verdict]} | \`${r.value}\` | ${r.reason ?? ""} | ${r.source ?? ""} | ${r.count}× | ${r.tools.join(", ")} |`);
      }
    }
  } else {
    lines.push("No external URLs or secrets observed.");
  }
  if (s.aggregates.length > 0) {
    lines.push("");
    lines.push("**Session-level patterns:**");
    for (const a of s.aggregates) lines.push(`- ⚠️ ${a}`);
  }
  return lines.join("\n");
}

export type { SummaryRow };
