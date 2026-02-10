# Authentication Rate Limiting Implementation

## Overview

This implementation addresses the **CWE-307: Improper Restriction of Excessive Authentication Attempts** vulnerability by adding comprehensive rate limiting to all authentication endpoints. The solution includes both IP-based rate limiting and account-specific lockout mechanisms to prevent brute force attacks.

## Features

### 1. IP-Based Rate Limiting

- **Sliding Window Algorithm**: Uses Redis sorted sets for accurate rate limiting with atomic operations
- **Exponential Backoff**: Failed attempts result in exponentially increasing retry delays
- **Per-Endpoint Configuration**: Different limits for different authentication endpoints
- **Rate Limit Headers**: Standard HTTP headers (`X-RateLimit-*`) included in all responses

### 2. Account Lockout Protection

- **Cross-IP Protection**: Protects individual accounts from distributed brute force attacks
- **Temporary Lockouts**: 30-minute lockout after 10 failed attempts within 1 hour
- **Automatic Reset**: Successful login clears both rate limiting and failed attempt counters

### 3. Graceful Degradation

- **Redis Fallback**: If Redis is unavailable, the system fails open but logs warnings
- **Error Resilience**: Redis errors don't block authentication; they're logged for monitoring

## Configuration

### Rate Limit Settings

```typescript
export const AUTH_RATE_LIMITS: Record<string, RateLimitConfig> = {
  '/api/auth/login': {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxAttempts: 5,           // 5 attempts per window
    skipSuccessfulRequests: false,
  },
  '/api/auth/verify': {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxAttempts: 20,          // 20 attempts per window
    skipSuccessfulRequests: false,
  },
  '/api/auth/sso': {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxAttempts: 10,          // 10 attempts per window
    skipSuccessfulRequests: false,
  },
};
```

### Account Lockout Settings

```typescript
const LOCKOUT_DURATION = 30 * 60 * 1000; // 30 minutes
const MAX_FAILED_ATTEMPTS = 10;          // Across all IPs
```

## Implementation Details

### Architecture

The rate limiting is implemented at the request parsing level by extending the existing `parseRequest()` function:

1. **Integration Point**: Added to `src/lib/request.ts` as an optional feature
2. **Selective Application**: Only applied to authentication endpoints or when explicitly configured
3. **Header Passing**: Rate limit information is passed through to route handlers for response inclusion

### Redis Data Structure

#### Rate Limiting Keys
- **Format**: `rate_limit:{endpoint}:{ip}`
- **Type**: Redis Sorted Set (ZSET)
- **Values**: Timestamp-based entries with automatic expiry
- **TTL**: Automatically set to window duration

#### Account Lockout Keys
- **Failed Attempts**: `failed_attempts:{username}` (Redis String with TTL)
- **Lockout Status**: `account_lockout:{username}` (Redis String with expiry)

### Security Considerations

#### IP Address Detection
- Uses existing `getIpAddress()` function from `src/lib/ip.ts`
- Handles various proxy headers (X-Forwarded-For, X-Real-IP, etc.)
- Supports custom IP header configuration via `CLIENT_IP_HEADER` environment variable

#### Attack Mitigation
- **Brute Force**: Rate limiting prevents rapid authentication attempts
- **Distributed Attacks**: Account lockout protects against attacks from multiple IPs
- **IP Spoofing**: Uses trusted proxy headers and supports CIDR blocking
- **Resource Exhaustion**: Automatic key expiry prevents Redis memory bloat

## HTTP Response Codes

### Rate Limiting Responses

```http
HTTP/1.1 429 Too Many Requests
X-RateLimit-Limit: 5
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1643723400
Retry-After: 120
Content-Type: application/json

{
  "error": "Too many requests",
  "message": "Rate limit exceeded. Please try again in 120 seconds.",
  "retryAfter": 120
}
```

### Account Lockout Responses

```http
HTTP/1.1 423 Locked
X-RateLimit-Limit: 5
X-RateLimit-Remaining: 2
X-RateLimit-Reset: 1643723400
Content-Type: application/json

{
  "code": "account-locked",
  "message": "Account is temporarily locked due to multiple failed login attempts. Please try again in 25 minute(s)."
}
```

## Monitoring and Logging

### Logged Events

1. **Rate Limit Violations**: When requests are blocked due to rate limiting
2. **Account Lockouts**: When accounts are locked due to failed attempts
3. **Redis Errors**: When Redis operations fail (with fallback behavior)
4. **Configuration Issues**: When Redis is unavailable

### Monitoring Recommendations

1. **Alert on High Failed Attempts**: Monitor for accounts with many failed attempts
2. **Track Rate Limit Violations**: High violation rates may indicate attacks
3. **Redis Health**: Monitor Redis connectivity and performance
4. **IP Analysis**: Track top failing IP addresses for potential blocking

## Testing

### Unit Tests

The implementation includes comprehensive unit tests covering:

- Rate limiting logic with various scenarios
- Account lockout functionality
- Error handling and fallback behavior
- Configuration validation

### Manual Testing

```bash
# Test rate limiting
for i in {1..10}; do
  curl -X POST http://localhost:3000/api/auth/login \
    -H "Content-Type: application/json" \
    -d '{"username":"test","password":"wrong"}' \
    -v
done

# Check rate limit headers
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"wrong"}' \
  -I
```

## Performance Impact

### Redis Operations
- **Per Request**: 5 Redis operations in a single multi/exec transaction
- **Memory Usage**: Minimal - keys auto-expire and sorted sets are space-efficient
- **Network**: Single round-trip to Redis per rate-limited request

### Response Time
- **With Redis**: ~1-2ms additional latency
- **Without Redis**: No additional latency (fallback mode)

## Deployment Considerations

### Environment Variables

```bash
# Required for rate limiting
REDIS_URL=redis://localhost:6379

# Optional customization
CLIENT_IP_HEADER=x-forwarded-for  # Custom IP header
```

### Redis Configuration

Recommended Redis configuration for production:

```redis
# Memory optimization
maxmemory-policy allkeys-lru
maxmemory 256mb

# Persistence (optional for rate limiting)
save ""
appendonly no

# Performance
tcp-keepalive 60
timeout 300
```

## Maintenance

### Key Cleanup
Redis keys automatically expire, but for monitoring:

```bash
# Count rate limiting keys
redis-cli --scan --pattern "rate_limit:*" | wc -l

# Count account lockout keys  
redis-cli --scan --pattern "account_lockout:*" | wc -l

# Clean up expired keys (if needed)
redis-cli --scan --pattern "rate_limit:*" | xargs redis-cli del
```

### Configuration Updates

Rate limits can be adjusted by modifying the `AUTH_RATE_LIMITS` configuration object. Changes require application restart.

## Security Best Practices

1. **Monitor Logs**: Regularly review rate limiting and lockout logs
2. **IP Allowlisting**: Consider allowlisting trusted IP addresses
3. **Account Monitoring**: Track accounts with frequent lockouts
4. **Redis Security**: Ensure Redis is properly secured and not publicly accessible
5. **Backup Strategy**: Consider Redis persistence for critical rate limiting data

## Compliance

This implementation helps meet various security compliance requirements:

- **OWASP Top 10**: Addresses A07 (Identification and Authentication Failures)
- **NIST Cybersecurity Framework**: Supports access control (PR.AC-1, PR.AC-7)
- **PCI DSS**: Requirement 8.1.6 (Account lockout after failed attempts)
- **SOC 2**: Access control and monitoring requirements