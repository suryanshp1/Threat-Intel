import test from 'node:test';
import assert from 'node:assert/strict';
import { hasSeenTour, rememberTour, TOUR_STORAGE_KEY, tourSteps } from '../src/tour-data.ts';

test('tour invitation appears for new browsers and stays dismissed after replay or reload', () => {
  const values = new Map();
  const storage = {
    getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value),
  };
  assert.equal(hasSeenTour(storage), false);
  rememberTour(storage);
  assert.equal(values.get(TOUR_STORAGE_KEY), 'seen');
  assert.equal(hasSeenTour(storage), true);
  rememberTour(storage);
  assert.equal(hasSeenTour(storage), true);
});

test('blocked browser storage does not prevent onboarding or dismissal', () => {
  const storage = {
    getItem() { throw new Error('Storage blocked'); },
    setItem() { throw new Error('Quota exceeded'); },
  };
  assert.equal(hasSeenTour(storage), false);
  assert.doesNotThrow(() => rememberTour(storage));
});

test('unknown preference values do not silently dismiss a new tour', () => {
  assert.equal(hasSeenTour({ getItem: () => 'unexpected' }), false);
});

test('the guide visits public workspace screens without submitting analysis or admin actions', () => {
  assert.deepEqual(tourSteps.map(step => step.path), [
    '/vi', '/vi/explore', '/vi/threat-actors', '/vi/supply-chain',
    '/vi/tools/kb-lookup', '/vi/tools/sbom-vex', '/vi/sources', '/vi/developers',
  ]);
});
