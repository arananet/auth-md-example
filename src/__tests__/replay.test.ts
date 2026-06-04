import { checkAndStoreJti } from '../services/replay';
import { resetDb } from '../db';

beforeEach(() => resetDb());
afterAll(() => resetDb());

describe('JTI replay detection', () => {
  it('accepts a fresh jti', () => {
    const exp = Date.now() + 60_000;
    expect(checkAndStoreJti('jti-1', exp)).toBe(true);
  });

  it('rejects a replayed jti', () => {
    const exp = Date.now() + 60_000;
    checkAndStoreJti('jti-2', exp);
    expect(checkAndStoreJti('jti-2', exp)).toBe(false);
  });

  it('treats different jtis as independent', () => {
    const exp = Date.now() + 60_000;
    expect(checkAndStoreJti('jti-a', exp)).toBe(true);
    expect(checkAndStoreJti('jti-b', exp)).toBe(true);
  });
});
