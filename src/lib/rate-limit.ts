import redis from '@/lib/redis';

export interface RateLimitConfig {
  windowMs: number;      // Time window in milliseconds
  maxAttempts: number;   // Maximum attempts allowed
  keyPrefix?: string;    // Optional prefix for Redis keys
  skipSuccessfulRequests?: boolean; // Whether to skip counting successful requests
}

export interface RateLimitResult {
  allowed: boolean;
  limit: number;
  remaining: number;
  resetAt: Date;
  retryAfter?: number; // Seconds to wait before retry (for exponential backoff)
}

// Default rate limit configurations for different endpoints
export const AUTH_RATE_LIMITS: Record<string, RateLimitConfig> = {
  '/api/auth/login': {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxAttempts: 5,
    skipSuccessfulRequests: false,
  },
  '/api/auth/verify': {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxAttempts: 20,
    skipSuccessfulRequests: false,
  },
  '/api/auth/sso': {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxAttempts: 10,
    skipSuccessfulRequests: false,
  },
};

/**
 * Check rate limit for a given identifier and configuration
 * Implements sliding window algorithm with atomic Redis operations
 */
export async function checkRateLimit(
  identifier: string,
  config: RateLimitConfig
): Promise<RateLimitResult> {
  // If Redis is not available, allow the request but log warning
  if (!redis.enabled) {
    console.warn('Redis not available for rate limiting');
    return {
      allowed: true,
      limit: config.maxAttempts,
      remaining: config.maxAttempts,
      resetAt: new Date(Date.now() + config.windowMs),
    };
  }

  const key = `${config.keyPrefix || 'rate_limit'}:${identifier}`;
  const now = Date.now();
  const windowStart = now - config.windowMs;

  try {
    // Use Redis multi for atomic operations
    const multi = redis.client.multi();
    
    // Remove old entries outside the window
    multi.zremrangebyscore(key, '-inf', windowStart);
    
    // Count current attempts in the window
    multi.zcard(key);
    
    // Get the oldest attempt timestamp for reset calculation
    multi.zrange(key, 0, 0, 'WITHSCORES');
    
    // Add current attempt
    multi.zadd(key, now, `${now}-${Math.random()}`);
    
    // Set expiry to clean up old keys
    multi.expire(key, Math.ceil(config.windowMs / 1000));
    
    const results = await multi.exec();
    
    if (!results) {
      throw new Error('Redis multi execution failed');
    }

    const attemptCount = (results[1][1] as number) || 0;
    const oldestAttempt = results[2][1] as Array<[string, string]> || [];
    
    // Calculate exponential backoff if over limit
    let retryAfter: number | undefined;
    if (attemptCount >= config.maxAttempts && oldestAttempt.length > 0) {
      const failureCount = attemptCount - config.maxAttempts + 1;
      // Exponential backoff: 2^(failures-1) * 60 seconds, max 1 hour
      retryAfter = Math.min(Math.pow(2, failureCount - 1) * 60, 3600);
    }

    const resetAt = new Date(
      oldestAttempt.length > 0 
        ? parseInt(oldestAttempt[0][1]) + config.windowMs
        : now + config.windowMs
    );

    return {
      allowed: attemptCount < config.maxAttempts,
      limit: config.maxAttempts,
      remaining: Math.max(0, config.maxAttempts - attemptCount - 1),
      resetAt,
      retryAfter,
    };
  } catch (error) {
    console.error('Rate limit check failed:', error);
    // On error, fail open but log the issue
    return {
      allowed: true,
      limit: config.maxAttempts,
      remaining: config.maxAttempts,
      resetAt: new Date(now + config.windowMs),
    };
  }
}

/**
 * Reset rate limit for a given identifier
 * Used for successful logins to clear previous failed attempts
 */
export async function resetRateLimit(
  identifier: string,
  config: RateLimitConfig
): Promise<void> {
  if (!redis.enabled) return;

  const key = `${config.keyPrefix || 'rate_limit'}:${identifier}`;
  try {
    await redis.client.del(key);
  } catch (error) {
    console.error('Failed to reset rate limit:', error);
  }
}

/**
 * Format rate limit headers for HTTP response
 */
export function getRateLimitHeaders(result: RateLimitResult): Record<string, string> {
  const headers: Record<string, string> = {
    'X-RateLimit-Limit': result.limit.toString(),
    'X-RateLimit-Remaining': result.remaining.toString(),
    'X-RateLimit-Reset': Math.floor(result.resetAt.getTime() / 1000).toString(),
  };

  if (!result.allowed && result.retryAfter) {
    headers['Retry-After'] = result.retryAfter.toString();
  }

  return headers;
}