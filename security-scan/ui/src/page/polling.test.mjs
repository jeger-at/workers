import assert from 'node:assert/strict'
import test from 'node:test'
import {
  ACTIVE_POLL_MS,
  FALLBACK_POLL_MS,
  pollIntervalFor,
  RECOVERY_POLL_MS,
} from './polling.js'

test('polls active runs quickly regardless of stream state', () => {
  assert.equal(pollIntervalFor(true, true), ACTIVE_POLL_MS)
  assert.equal(pollIntervalFor(true, false), ACTIVE_POLL_MS)
})

test('keeps fallback and live recovery sweeps distinct', () => {
  assert.equal(pollIntervalFor(false, false), FALLBACK_POLL_MS)
  assert.equal(pollIntervalFor(false, true), RECOVERY_POLL_MS)
})
