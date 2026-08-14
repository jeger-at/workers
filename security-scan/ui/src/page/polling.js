export const ACTIVE_POLL_MS = 2_000
export const FALLBACK_POLL_MS = 10_000
export const RECOVERY_POLL_MS = 30_000

/**
 * Preserve a slow recovery sweep even with a healthy stream binding. Stream
 * frames are doorbells, not durable state, so a dropped frame must only delay
 * convergence rather than prevent it.
 *
 * @param {boolean} hasNonTerminalRun
 * @param {boolean} live
 */
export function pollIntervalFor(hasNonTerminalRun, live) {
  if (hasNonTerminalRun) return ACTIVE_POLL_MS
  return live ? RECOVERY_POLL_MS : FALLBACK_POLL_MS
}
