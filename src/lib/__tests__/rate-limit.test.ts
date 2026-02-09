import { jest } from '@jest/globals';
import { checkRateLimit, resetRateLimit, AUTH_RATE_LIMITS } from '../rate-limit';
import { checkAccountLockout, incrementFailedAttempts, resetFailedAttempts } from '../account-lockout';

// Mock Redis
jest.mock('../redis', () => ({
  enabled: true,
  client: {
    multi: jest.fn(() => ({
      zremrangebyscore: jest.fn(),
      zcard: jest.fn(),
      zrange: jest.fn(),
      zadd: jest.fn(),
      expire: jest.fn(),
      exec: jest.fn(() => Promise.resolve([
        [null, 0], // zremrangebyscore
        [null, 0], // zcard (attempt count)
        [null, []], // zrange (oldest attempt)
        [null, 1], // zadd
        [null, 1], // expire
      ])),
    })),
    del: jest.fn(() => Promise.resolve(1)),
    get: jest.fn(() => Promise.resolve(null)),
    incr: jest.fn(() => Promise.resolve(1)),
    set: jest.fn(() => Promise.resolve('OK')),
  },
}));

describe('Rate Limiting', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('checkRateLimit', () => {
    it('should allow requests within limit', async () => {
      const config = AUTH_RATE_LIMITS['/api/auth/login'];
      const identifier = '/api/auth/login:127.0.0.1';

      const result = await checkRateLimit(identifier, config);

      expect(result.allowed).toBe(true);
      expect(result.limit).toBe(config.maxAttempts);
      expect(result.remaining).toBe(config.maxAttempts - 1);
    });

    it('should block requests over limit', async () => {
      const redis = require('../redis').default;
      // Mock attempt count over limit
      redis.client.multi().exec.mockResolvedValueOnce([
        [null, 0], // zremrangebyscore
        [null, 6], // zcard (over limit)
        [null, [['attempt', '1234567890']]], // zrange
        [null, 1], // zadd
        [null, 1], // expire
      ]);

      const config = AUTH_RATE_LIMITS['/api/auth/login'];
      const identifier = '/api/auth/login:127.0.0.1';

      const result = await checkRateLimit(identifier, config);

      expect(result.allowed).toBe(false);
      expect(result.retryAfter).toBeDefined();
      expect(result.retryAfter).toBeGreaterThan(0);
    });

    it('should handle Redis errors gracefully', async () => {
      const redis = require('../redis').default;
      redis.client.multi().exec.mockRejectedValueOnce(new Error('Redis error'));

      const config = AUTH_RATE_LIMITS['/api/auth/login'];
      const identifier = '/api/auth/login:127.0.0.1';

      const result = await checkRateLimit(identifier, config);

      // Should fail open on Redis error
      expect(result.allowed).toBe(true);
    });
  });

  describe('resetRateLimit', () => {
    it('should delete the rate limit key', async () => {
      const redis = require('../redis').default;
      const config = AUTH_RATE_LIMITS['/api/auth/login'];
      const identifier = '/api/auth/login:127.0.0.1';

      await resetRateLimit(identifier, config);

      expect(redis.client.del).toHaveBeenCalledWith('rate_limit:/api/auth/login:127.0.0.1');
    });
  });

  describe('Account Lockout', () => {
    describe('checkAccountLockout', () => {
      it('should return unlocked for new account', async () => {
        const result = await checkAccountLockout('testuser');

        expect(result.isLocked).toBe(false);
        expect(result.failedAttempts).toBe(0);
      });

      it('should detect locked account', async () => {
        const redis = require('../redis').default;
        const lockExpiry = Date.now() + 30 * 60 * 1000;
        redis.client.get.mockImplementation((key: string) => {
          if (key === 'account_lockout:testuser') return Promise.resolve(lockExpiry.toString());
          if (key === 'failed_attempts:testuser') return Promise.resolve('10');
          return Promise.resolve(null);
        });

        const result = await checkAccountLockout('testuser');

        expect(result.isLocked).toBe(true);
        expect(result.failedAttempts).toBe(10);
        expect(result.lockoutExpiry).toBeInstanceOf(Date);
      });
    });

    describe('incrementFailedAttempts', () => {
      it('should increment failed attempts', async () => {
        const redis = require('../redis').default;
        redis.client.incr.mockResolvedValueOnce(3);

        const result = await incrementFailedAttempts('testuser');

        expect(result.failedAttempts).toBe(3);
        expect(result.isLocked).toBe(false);
        expect(redis.client.incr).toHaveBeenCalledWith('failed_attempts:testuser');
      });

      it('should lock account after max attempts', async () => {
        const redis = require('../redis').default;
        redis.client.incr.mockResolvedValueOnce(10);

        const result = await incrementFailedAttempts('testuser');

        expect(result.failedAttempts).toBe(10);
        expect(result.isLocked).toBe(true);
        expect(result.lockoutExpiry).toBeInstanceOf(Date);
        expect(redis.client.set).toHaveBeenCalled();
      });
    });

    describe('resetFailedAttempts', () => {
      it('should reset both failed attempts and lockout', async () => {
        const redis = require('../redis').default;

        await resetFailedAttempts('testuser');

        expect(redis.client.del).toHaveBeenCalledWith(
          'failed_attempts:testuser',
          'account_lockout:testuser'
        );
      });
    });
  });
});

// Integration test with actual rate limit configurations
describe('Rate Limit Configurations', () => {
  it('should have proper configurations for all auth endpoints', () => {
    expect(AUTH_RATE_LIMITS['/api/auth/login']).toBeDefined();
    expect(AUTH_RATE_LIMITS['/api/auth/verify']).toBeDefined();
    expect(AUTH_RATE_LIMITS['/api/auth/sso']).toBeDefined();

    // Login should have the strictest limits
    expect(AUTH_RATE_LIMITS['/api/auth/login'].maxAttempts).toBe(5);
    expect(AUTH_RATE_LIMITS['/api/auth/login'].windowMs).toBe(15 * 60 * 1000);

    // Verify should have higher limits
    expect(AUTH_RATE_LIMITS['/api/auth/verify'].maxAttempts).toBe(20);

    // All should use the same window
    Object.values(AUTH_RATE_LIMITS).forEach(config => {
      expect(config.windowMs).toBe(15 * 60 * 1000);
    });
  });
});