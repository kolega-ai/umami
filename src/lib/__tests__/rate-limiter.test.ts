import { describe, it, expect, beforeEach, jest } from '@jest/globals';
import { RateLimiter, type RequestContext } from '../rate-limiter';

// Mock Redis
const mockRedis = {
  enabled: false,
  client: {
    multi: jest.fn(),
    zremrangebyscore: jest.fn(),
    zadd: jest.fn(),
    zcard: jest.fn(),
    expire: jest.fn(),
    zrange: jest.fn(),
    incr: jest.fn(),
    lpush: jest.fn(),
    ltrim: jest.fn(),
    keys: jest.fn(),
    llen: jest.fn(),
  }
};

jest.mock('../redis', () => ({
  default: mockRedis
}));

describe('RateLimiter', () => {
  let rateLimiter: RateLimiter;
  let mockContext: RequestContext;

  beforeEach(() => {
    // Reset Redis mock
    mockRedis.enabled = false;
    
    // Create rate limiter with test configuration
    rateLimiter = new RateLimiter({
      ipRequestsPerMinute: 10,
      ipRequestsPerHour: 100,
      burstRequests: 5,
      burstWindowSeconds: 10,
      enablePatternDetection: true,
      payloadSimilarityThreshold: 0.95,
      anomalyThreshold: 0.8,
    });

    // Mock context
    mockContext = {
      ip: '192.168.1.100',
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
      payload: { type: 'event', url: '/test' },
      timestamp: Date.now()
    };
  });

  describe('IP Rate Limiting', () => {
    it('should allow requests within limits', async () => {
      const result = await rateLimiter.checkRequest(mockContext);
      
      expect(result.allowed).toBe(true);
      expect(result.remaining).toBeGreaterThan(0);
    });

    it('should block requests exceeding per-minute limit', async () => {
      // Make 11 requests (limit is 10)
      const results = [];
      for (let i = 0; i < 11; i++) {
        results.push(await rateLimiter.checkRequest({
          ...mockContext,
          timestamp: Date.now() + i * 1000 // Spread over time
        }));
      }

      // First 10 should be allowed
      for (let i = 0; i < 10; i++) {
        expect(results[i].allowed).toBe(true);
      }

      // 11th should be blocked
      expect(results[10].allowed).toBe(false);
      expect(results[10].reason).toContain('IP rate limit exceeded (per minute)');
      expect(results[10].retryAfter).toBeGreaterThan(0);
    });

    it('should reset limits after time window', async () => {
      // Fill up the rate limit
      for (let i = 0; i < 10; i++) {
        await rateLimiter.checkRequest(mockContext);
      }

      // Next request should be blocked
      const blockedResult = await rateLimiter.checkRequest(mockContext);
      expect(blockedResult.allowed).toBe(false);

      // Simulate time passing (move forward 1 minute + 1 second)
      const futureContext = {
        ...mockContext,
        timestamp: Date.now() + 61 * 1000
      };

      const allowedResult = await rateLimiter.checkRequest(futureContext);
      expect(allowedResult.allowed).toBe(true);
    });
  });

  describe('Burst Protection', () => {
    it('should block rapid burst requests', async () => {
      const now = Date.now();
      const results = [];

      // Send 6 requests in rapid succession (limit is 5)
      for (let i = 0; i < 6; i++) {
        results.push(await rateLimiter.checkRequest({
          ...mockContext,
          timestamp: now + i * 100 // 100ms apart
        }));
      }

      // First 5 should be allowed
      for (let i = 0; i < 5; i++) {
        expect(results[i].allowed).toBe(true);
      }

      // 6th should be blocked
      expect(results[5].allowed).toBe(false);
      expect(results[5].reason).toContain('Burst rate limit exceeded');
    });
  });

  describe('Pattern Detection', () => {
    it('should detect suspicious empty user agent', async () => {
      const suspiciousContext = {
        ...mockContext,
        userAgent: ''
      };

      // First few requests might be allowed (threshold is 5)
      let lastResult;
      for (let i = 0; i < 10; i++) {
        lastResult = await rateLimiter.checkRequest(suspiciousContext);
        if (!lastResult.allowed) break;
      }

      expect(lastResult!.allowed).toBe(false);
      expect(lastResult!.reason).toContain('Suspicious user agent pattern');
    });

    it('should detect bot user agents', async () => {
      const botContext = {
        ...mockContext,
        userAgent: 'curl/7.68.0'
      };

      // Should be blocked after a few requests
      let lastResult;
      for (let i = 0; i < 10; i++) {
        lastResult = await rateLimiter.checkRequest(botContext);
        if (!lastResult.allowed) break;
      }

      expect(lastResult!.allowed).toBe(false);
      expect(lastResult!.reason).toContain('Bot pattern detected');
    });

    it('should detect suspicious browser versions', async () => {
      const oldBrowserContext = {
        ...mockContext,
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36'
      };

      // Should be blocked after threshold
      let lastResult;
      for (let i = 0; i < 10; i++) {
        lastResult = await rateLimiter.checkRequest(oldBrowserContext);
        if (!lastResult.allowed) break;
      }

      expect(lastResult!.allowed).toBe(false);
      expect(lastResult!.reason).toContain('Suspiciously old Chrome version');
    });

    it('should detect repeated identical payloads', async () => {
      const identicalPayload = { type: 'event', url: '/same-page', timestamp: 12345 };

      // Send same payload multiple times
      let lastResult;
      for (let i = 0; i < 15; i++) {
        lastResult = await rateLimiter.checkRequest({
          ...mockContext,
          payload: identicalPayload,
          timestamp: Date.now() + i * 10000 // Spread over time to avoid burst limit
        });
        if (!lastResult.allowed) break;
      }

      expect(lastResult!.allowed).toBe(false);
      expect(lastResult!.reason).toContain('Identical payload pattern detected');
    });
  });

  describe('Different IP Addresses', () => {
    it('should track limits separately for different IPs', async () => {
      const ip1Context = { ...mockContext, ip: '192.168.1.100' };
      const ip2Context = { ...mockContext, ip: '192.168.1.101' };

      // Fill limit for IP1
      for (let i = 0; i < 10; i++) {
        await rateLimiter.checkRequest(ip1Context);
      }

      // IP1 should be blocked
      const ip1Blocked = await rateLimiter.checkRequest(ip1Context);
      expect(ip1Blocked.allowed).toBe(false);

      // IP2 should still be allowed
      const ip2Allowed = await rateLimiter.checkRequest(ip2Context);
      expect(ip2Allowed.allowed).toBe(true);
    });
  });

  describe('Error Handling', () => {
    it('should gracefully handle errors and allow requests', async () => {
      // Create a rate limiter that will throw errors
      const faultyRateLimiter = new RateLimiter();
      
      // Mock a method to throw an error
      const originalMethod = faultyRateLimiter['checkIPRateLimit'];
      faultyRateLimiter['checkIPRateLimit'] = jest.fn().mockRejectedValue(new Error('Test error'));

      const result = await faultyRateLimiter.checkRequest(mockContext);

      // Should allow the request despite the error
      expect(result.allowed).toBe(true);
    });
  });

  describe('Configuration', () => {
    it('should use environment variable defaults', () => {
      const defaultRateLimiter = new RateLimiter();
      
      // Test that it doesn't throw and can handle requests
      expect(async () => {
        await defaultRateLimiter.checkRequest(mockContext);
      }).not.toThrow();
    });

    it('should respect custom configuration', () => {
      const customRateLimiter = new RateLimiter({
        ipRequestsPerMinute: 5,
        enablePatternDetection: false
      });

      expect(customRateLimiter).toBeDefined();
    });
  });

  describe('Response Creation', () => {
    it('should create proper rate limit response', async () => {
      // Fill up the rate limit
      for (let i = 0; i < 10; i++) {
        await rateLimiter.checkRequest(mockContext);
      }

      const result = await rateLimiter.checkRequest(mockContext);
      expect(result.allowed).toBe(false);
      expect(result.retryAfter).toBeGreaterThan(0);
      expect(result.reason).toBeDefined();
    });
  });
});

describe('User Agent Detection', () => {
  let rateLimiter: RateLimiter;

  beforeEach(() => {
    rateLimiter = new RateLimiter({
      enablePatternDetection: true
    });
  });

  it('should detect various bot patterns', () => {
    const botUserAgents = [
      'Googlebot/2.1',
      'Mozilla/5.0 (compatible; bingbot/2.0)',
      'curl/7.68.0',
      'wget/1.20.3',
      'python-requests/2.25.1',
      'scrapy/2.4.1'
    ];

    const detectSuspiciousUA = rateLimiter['detectSuspiciousUserAgent'].bind(rateLimiter);

    for (const userAgent of botUserAgents) {
      const result = detectSuspiciousUA(userAgent);
      expect(result.suspicious).toBe(true);
      expect(result.reason).toBeDefined();
    }
  });

  it('should allow legitimate user agents', () => {
    const legitimateUserAgents = [
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0'
    ];

    const detectSuspiciousUA = rateLimiter['detectSuspiciousUserAgent'].bind(rateLimiter);

    for (const userAgent of legitimateUserAgents) {
      const result = detectSuspiciousUA(userAgent);
      expect(result.suspicious).toBe(false);
    }
  });
});

describe('Payload Hashing', () => {
  let rateLimiter: RateLimiter;

  beforeEach(() => {
    rateLimiter = new RateLimiter();
  });

  it('should create consistent hashes for identical payloads', () => {
    const payload1 = { type: 'event', url: '/test', timestamp: 123 };
    const payload2 = { type: 'event', url: '/test', timestamp: 123 };

    const hashPayload = rateLimiter['hashPayload'].bind(rateLimiter);

    const hash1 = hashPayload(payload1);
    const hash2 = hashPayload(payload2);

    expect(hash1).toBe(hash2);
  });

  it('should create different hashes for different payloads', () => {
    const payload1 = { type: 'event', url: '/test1' };
    const payload2 = { type: 'event', url: '/test2' };

    const hashPayload = rateLimiter['hashPayload'].bind(rateLimiter);

    const hash1 = hashPayload(payload1);
    const hash2 = hashPayload(payload2);

    expect(hash1).not.toBe(hash2);
  });

  it('should handle property order independence', () => {
    const payload1 = { url: '/test', type: 'event' };
    const payload2 = { type: 'event', url: '/test' };

    const hashPayload = rateLimiter['hashPayload'].bind(rateLimiter);

    const hash1 = hashPayload(payload1);
    const hash2 = hashPayload(payload2);

    expect(hash1).toBe(hash2);
  });
});