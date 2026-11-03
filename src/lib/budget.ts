/**
 * Whole-hook wall-clock budget. Harnesses run hooks under their own timeout
 * and silently skip the tool call when it fires, so the worst-case hook work
 * (a cold feed refresh plus Safe Browsing/RDAP lookups) must stay inside that
 * window. Individual fetch timeouts are bounded by the remaining budget;
 * stages that no longer fit are skipped with an honest note instead of being
 * abandoned mid-flight. The default leaves room under the tightest harness
 * timeout plus the 5 s stdin cap.
 *
 * EGRESS_EYE_HOOK_BUDGET_MS sets the budget in ms (default 8000); `0`
 * disables it entirely.
 */

export interface Deadline {
  remainingMs(): number;
  expired(): boolean;
}

const DEFAULT_BUDGET_MS = 8000;

export class HookBudget implements Deadline {
  private readonly start: number;

  private constructor(private readonly budgetMs: number) {
    this.start = Date.now();
  }

  static fromEnv(): HookBudget {
    const raw = process.env.EGRESS_EYE_HOOK_BUDGET_MS;
    if (raw === undefined || raw === "") return new HookBudget(DEFAULT_BUDGET_MS);
    const n = Number(raw);
    if (n === 0) return new HookBudget(0);
    return new HookBudget(Number.isFinite(n) && n > 0 ? n : DEFAULT_BUDGET_MS);
  }

  remainingMs(): number {
    if (this.budgetMs <= 0) return Infinity; // disabled — never expires
    return this.budgetMs - (Date.now() - this.start);
  }

  expired(): boolean {
    return this.remainingMs() <= 0;
  }
}

/**
 * Fetch timeout bounded by the deadline, so no single request can outlive
 * the budget. Leaves a margin for parsing and the report write.
 */
export function boundedTimeoutMs(deadline: Deadline | undefined, capMs: number): number {
  if (!deadline) return capMs;
  const remaining = deadline.remainingMs() - 500;
  return remaining <= 0 ? 0 : Math.min(capMs, remaining);
}
