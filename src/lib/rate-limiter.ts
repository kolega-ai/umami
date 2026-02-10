import { UAParser } from 'ua-parser-js';
import redis from '@/lib/redis';

export interface RateLimitConfig {
  // Basic IP rate limiting
  ipRequestsPerMinute: number;
  ipRequestsPerHour: number;
  
  // Burst protection
  burstRequests: number;
  burstWindowSeconds: number;
  
  // Pattern detection
  enablePatternDetection: boolean;
  payloadSimilarityThreshold: number;
  anomalyThreshold: number;
}

export interface RateLimitResult {
  allowed: boolean;
  reason?: string;
  remaining?: number;
  retryAfter?: number;
  resetAt?: Date;
}

export interface RequestContext {
  ip: string;
  userAgent: string;
  payload: any;
  timestamp: number;
}

const DEFAULT_CONFIG: RateLimitConfig = {
  ipRequestsPerMinute: parseInt(process.env.RATE_LIMIT_IP_PER_MINUTE || '100', 10),
  ipRequestsPerHour: parseInt(process.env.RATE_LIMIT_IP_PER_HOUR || '1000', 10),
  burstRequests: parseInt(process.env.RATE_LIMIT_BURST_REQUESTS || '20', 10),
  burstWindowSeconds: parseInt(process.env.RATE_LIMIT_BURST_WINDOW_SECONDS || '10', 10),
  enablePatternDetection: process.env.RATE_LIMIT_ENABLE_PATTERN_DETECTION === 'true',
  payloadSimilarityThreshold: parseFloat(process.env.RATE_LIMIT_PAYLOAD_SIMILARITY_THRESHOLD || '0.95'),
  anomalyThreshold: parseFloat(process.env.RATE_LIMIT_ANOMALY_THRESHOLD || '0.8'),
};

export class RateLimiter {
  private config: RateLimitConfig;
  private localCache = new Map<string, any>();
  private readonly keyPrefix = process.env.RATE_LIMIT_REDIS_PREFIX || 'umami_rl';

  constructor(config: Partial<RateLimitConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  async checkRequest(context: RequestContext): Promise<RateLimitResult> {
    try {
      // Multi-layer rate limiting checks
      const checks = [
        this.checkIPRateLimit(context),
        this.checkBurstLimit(context),
      ];

      if (this.config.enablePatternDetection) {
        checks.push(this.checkSuspiciousPatterns(context));
      }

      const results = await Promise.all(checks);
      
      // Return the first failing check
      const blocked = results.find(result => !result.allowed);
      if (blocked) {
        await this.logBlockedRequest(context, blocked.reason || 'Rate limit exceeded');
        return blocked;
      }

      return { allowed: true };
    } catch (error) {
      // Log error but don't block requests on rate limiter failure
      console.error('Rate limiter error:', error);
      return { allowed: true };
    }
  }

  private async checkIPRateLimit(context: RequestContext): Promise<RateLimitResult> {
    const { ip } = context;
    const now = Date.now();
    
    // Check minute-based limit
    const minuteResult = await this.checkSlidingWindow(
      `ip_minute:${ip}`,
      60 * 1000, // 1 minute window
      this.config.ipRequestsPerMinute,
      now
    );

    if (!minuteResult.allowed) {
      return {
        ...minuteResult,
        reason: 'IP rate limit exceeded (per minute)'
      };
    }

    // Check hour-based limit
    const hourResult = await this.checkSlidingWindow(
      `ip_hour:${ip}`,
      60 * 60 * 1000, // 1 hour window
      this.config.ipRequestsPerHour,
      now
    );

    if (!hourResult.allowed) {
      return {
        ...hourResult,
        reason: 'IP rate limit exceeded (per hour)'
      };
    }

    return { allowed: true, remaining: Math.min(minuteResult.remaining || 0, hourResult.remaining || 0) };
  }

  private async checkBurstLimit(context: RequestContext): Promise<RateLimitResult> {
    const { ip } = context;
    const now = Date.now();
    const windowMs = this.config.burstWindowSeconds * 1000;

    return await this.checkSlidingWindow(
      `burst:${ip}`,
      windowMs,
      this.config.burstRequests,
      now,
      'Burst rate limit exceeded'
    );
  }

  private async checkSuspiciousPatterns(context: RequestContext): Promise<RateLimitResult> {
    const { ip, userAgent, payload } = context;
    
    // Check for suspicious user agent patterns
    const suspiciousUA = this.detectSuspiciousUserAgent(userAgent);
    if (suspiciousUA.suspicious) {
      const key = `suspicious_ua:${ip}`;
      const count = await this.incrementCounter(key, 60 * 1000); // 1 minute window
      
      if (count > 5) { // Allow some false positives
        return {
          allowed: false,
          reason: `Suspicious user agent pattern: ${suspiciousUA.reason}`,
          retryAfter: 60
        };
      }
    }

    // Check for payload similarity (possible bot behavior)
    if (payload && typeof payload === 'object') {
      const payloadHash = this.hashPayload(payload);
      const key = `payload:${ip}:${payloadHash}`;
      const count = await this.incrementCounter(key, 5 * 60 * 1000); // 5 minute window
      
      if (count > 10) { // Same payload more than 10 times in 5 minutes
        return {
          allowed: false,
          reason: 'Identical payload pattern detected',
          retryAfter: 300
        };
      }
    }

    return { allowed: true };
  }

  private async checkSlidingWindow(
    key: string, 
    windowMs: number, 
    limit: number, 
    now: number,
    reason?: string
  ): Promise<RateLimitResult> {
    const redisKey = `${this.keyPrefix}:${key}`;

    if (redis.enabled) {
      try {
        return await this.redisSlidingWindow(redisKey, windowMs, limit, now, reason);
      } catch (error) {
        console.warn('Redis rate limiter failed, falling back to local cache:', error);
        return this.localSlidingWindow(key, windowMs, limit, now, reason);
      }
    } else {
      return this.localSlidingWindow(key, windowMs, limit, now, reason);
    }
  }

  private async redisSlidingWindow(
    key: string,
    windowMs: number,
    limit: number,
    now: number,
    reason?: string
  ): Promise<RateLimitResult> {
    const windowStart = now - windowMs;
    const client = redis.client;

    // Use Redis pipeline for atomic operations
    const pipeline = client.multi();
    
    // Remove old entries
    pipeline.zremrangebyscore(key, 0, windowStart);
    
    // Add current request
    pipeline.zadd(key, now, `${now}-${Math.random()}`);
    
    // Count current requests in window
    pipeline.zcard(key);
    
    // Set expiry
    pipeline.expire(key, Math.ceil(windowMs / 1000) + 10);

    const results = await pipeline.exec();
    const count = results[2][1] as number;

    if (count > limit) {
      // Get oldest timestamp to calculate retry-after
      const oldest = await client.zrange(key, 0, 0, { REV: false, WITHSCORES: true });
      const oldestTimestamp = oldest[1] ? parseFloat(oldest[1] as string) : now;
      const retryAfter = Math.ceil((oldestTimestamp + windowMs - now) / 1000);

      return {
        allowed: false,
        reason: reason || 'Rate limit exceeded',
        remaining: 0,
        retryAfter: Math.max(retryAfter, 1),
        resetAt: new Date(oldestTimestamp + windowMs)
      };
    }

    return {
      allowed: true,
      remaining: limit - count,
      resetAt: new Date(now + windowMs)
    };
  }

  private localSlidingWindow(
    key: string,
    windowMs: number,
    limit: number,
    now: number,
    reason?: string
  ): RateLimitResult {
    if (!this.localCache.has(key)) {
      this.localCache.set(key, []);
    }

    const timestamps: number[] = this.localCache.get(key) || [];
    const windowStart = now - windowMs;

    // Remove old timestamps
    while (timestamps.length > 0 && timestamps[0] < windowStart) {
      timestamps.shift();
    }

    if (timestamps.length >= limit) {
      const oldestInWindow = timestamps[0];
      const retryAfter = Math.ceil((oldestInWindow + windowMs - now) / 1000);

      return {
        allowed: false,
        reason: reason || 'Rate limit exceeded',
        remaining: 0,
        retryAfter: Math.max(retryAfter, 1),
        resetAt: new Date(oldestInWindow + windowMs)
      };
    }

    // Add current timestamp
    timestamps.push(now);
    this.localCache.set(key, timestamps);

    // Clean up cache periodically (simple approach)
    if (Math.random() < 0.01) { // 1% chance
      this.cleanupLocalCache();
    }

    return {
      allowed: true,
      remaining: limit - timestamps.length,
      resetAt: new Date(now + windowMs)
    };
  }

  private async incrementCounter(key: string, windowMs: number): Promise<number> {
    const redisKey = `${this.keyPrefix}:counter:${key}`;
    const ttlSeconds = Math.ceil(windowMs / 1000);

    if (redis.enabled) {
      try {
        const client = redis.client;
        const pipeline = client.multi();
        pipeline.incr(redisKey);
        pipeline.expire(redisKey, ttlSeconds);
        const results = await pipeline.exec();
        return results[0][1] as number;
      } catch (error) {
        console.warn('Redis counter failed, using local fallback:', error);
      }
    }

    // Local fallback
    const localKey = `counter:${key}`;
    const data = this.localCache.get(localKey) || { count: 0, expires: Date.now() + windowMs };
    
    if (Date.now() > data.expires) {
      data.count = 1;
      data.expires = Date.now() + windowMs;
    } else {
      data.count++;
    }

    this.localCache.set(localKey, data);
    return data.count;
  }

  private detectSuspiciousUserAgent(userAgent: string): { suspicious: boolean; reason?: string } {
    if (!userAgent || userAgent.trim().length === 0) {
      return { suspicious: true, reason: 'Empty user agent' };
    }

    // Check for obvious bot patterns
    const botPatterns = [
      /bot/i,
      /crawler/i,
      /spider/i,
      /scraper/i,
      /curl/i,
      /wget/i,
      /python/i,
      /requests/i,
      /httpie/i
    ];

    for (const pattern of botPatterns) {
      if (pattern.test(userAgent)) {
        return { suspicious: true, reason: `Bot pattern detected: ${pattern}` };
      }
    }

    // Check for suspicious characteristics
    try {
      const parser = UAParser(userAgent);
      const { browser, os, device } = parser;

      // Very old browsers (potential spoofing)
      if (browser.name && browser.version) {
        const version = parseFloat(browser.version);
        if (browser.name.toLowerCase().includes('chrome') && version < 70) {
          return { suspicious: true, reason: 'Suspiciously old Chrome version' };
        }
        if (browser.name.toLowerCase().includes('firefox') && version < 60) {
          return { suspicious: true, reason: 'Suspiciously old Firefox version' };
        }
      }

      // Inconsistent browser/OS combinations
      if (browser.name && os.name) {
        const browserName = browser.name.toLowerCase();
        const osName = os.name.toLowerCase();
        
        if (browserName.includes('safari') && osName.includes('windows')) {
          return { suspicious: true, reason: 'Inconsistent browser/OS combination' };
        }
      }
    } catch (error) {
      // If parsing fails, it might be a malformed user agent
      return { suspicious: true, reason: 'Malformed user agent' };
    }

    // Check for unusually short or long user agents
    if (userAgent.length < 20 || userAgent.length > 500) {
      return { suspicious: true, reason: 'Unusual user agent length' };
    }

    return { suspicious: false };
  }

  private hashPayload(payload: any): string {
    try {
      // Create a normalized hash of the payload
      const normalized = JSON.stringify(payload, Object.keys(payload).sort());
      return this.simpleHash(normalized);
    } catch (error) {
      return 'invalid';
    }
  }

  private simpleHash(str: string): string {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32bit integer
    }
    return hash.toString();
  }

  private cleanupLocalCache(): void {
    const now = Date.now();
    const keysToDelete: string[] = [];

    for (const [key, value] of this.localCache.entries()) {
      if (Array.isArray(value)) {
        // Clean up sliding window arrays
        const filtered = value.filter((timestamp: number) => now - timestamp < 3600000); // Keep last hour
        if (filtered.length === 0) {
          keysToDelete.push(key);
        } else {
          this.localCache.set(key, filtered);
        }
      } else if (value && typeof value === 'object' && value.expires) {
        // Clean up counter objects
        if (now > value.expires) {
          keysToDelete.push(key);
        }
      }
    }

    keysToDelete.forEach(key => this.localCache.delete(key));
  }

  private async logBlockedRequest(context: RequestContext, reason: string): Promise<void> {
    try {
      const logData = {
        timestamp: new Date().toISOString(),
        ip: context.ip,
        userAgent: context.userAgent,
        reason,
        payload: typeof context.payload === 'object' ? JSON.stringify(context.payload) : context.payload
      };

      if (redis.enabled) {
        // Log to Redis for centralized monitoring
        const key = `${this.keyPrefix}:blocked_requests`;
        await redis.client.lpush(key, JSON.stringify(logData));
        await redis.client.ltrim(key, 0, 999); // Keep last 1000 entries
        await redis.client.expire(key, 24 * 60 * 60); // 24 hours
      }

      // Also log to console for immediate visibility
      console.warn('Rate limit blocked request:', logData);
    } catch (error) {
      console.error('Failed to log blocked request:', error);
    }
  }

  // Utility method to get current metrics
  async getMetrics(): Promise<any> {
    if (!redis.enabled) {
      return { error: 'Metrics require Redis' };
    }

    try {
      const client = redis.client;
      const keys = await client.keys(`${this.keyPrefix}:*`);
      
      const metrics = {
        activeKeys: keys.length,
        blockedRequestsLast24h: 0,
      };

      const blockedKey = `${this.keyPrefix}:blocked_requests`;
      if (keys.includes(blockedKey)) {
        metrics.blockedRequestsLast24h = await client.llen(blockedKey);
      }

      return metrics;
    } catch (error) {
      return { error: error.message };
    }
  }
}

// Singleton instance
let rateLimiterInstance: RateLimiter;

export function getRateLimiter(): RateLimiter {
  if (!rateLimiterInstance) {
    rateLimiterInstance = new RateLimiter();
  }
  return rateLimiterInstance;
}

export function createRateLimitResponse(result: RateLimitResult) {
  const headers: Record<string, string> = {
    'X-RateLimit-Remaining': String(result.remaining || 0),
  };

  if (result.retryAfter) {
    headers['Retry-After'] = String(result.retryAfter);
  }

  if (result.resetAt) {
    headers['X-RateLimit-Reset'] = result.resetAt.toISOString();
  }

  return new Response(
    JSON.stringify({
      error: result.reason || 'Rate limit exceeded',
      retryAfter: result.retryAfter,
    }),
    {
      status: 429,
      headers: {
        'Content-Type': 'application/json',
        ...headers,
      },
    }
  );
}