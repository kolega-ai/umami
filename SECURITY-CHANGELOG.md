# Security Changelog

## [3.0.4] - 2024-02-03

### Security Fixes

#### CWE-770: Missing Rate Limiting on Analytics Data Collection

**Severity**: High
**CVSS Score**: 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)

**Issue**: 
The analytics collection endpoint (`/api/send`) was processing all incoming requests without rate limiting, making it vulnerable to denial of service attacks and data pollution from malicious actors.

**Fix**: 
Implemented comprehensive multi-layer rate limiting with the following features:

1. **IP-based rate limiting**: 
   - Per-minute limits (default: 100 requests/minute)  
   - Per-hour limits (default: 1000 requests/hour)

2. **Burst protection**:
   - Short-term burst detection (default: 20 requests/10 seconds)

3. **Pattern detection**:
   - Suspicious user agent detection
   - Bot pattern identification
   - Repeated payload analysis

4. **Infrastructure**:
   - Redis-backed distributed rate limiting
   - Local fallback for single-instance deployments
   - Graceful degradation on errors

**Configuration**:
Rate limiting can be configured via environment variables:
- `RATE_LIMIT_IP_PER_MINUTE`: Requests per minute per IP (default: 100)
- `RATE_LIMIT_IP_PER_HOUR`: Requests per hour per IP (default: 1000)  
- `RATE_LIMIT_BURST_REQUESTS`: Burst limit (default: 20)
- `RATE_LIMIT_ENABLE_PATTERN_DETECTION`: Enable advanced detection (default: true)
- `DISABLE_RATE_LIMITING`: Disable all rate limiting (not recommended)

**Files Modified**:
- `src/lib/rate-limiter.ts` (new) - Core rate limiting implementation
- `src/app/api/send/route.ts` - Integration with analytics endpoint
- `src/lib/__tests__/rate-limiter.test.ts` (new) - Comprehensive test suite
- `docs/rate-limiting.md` (new) - Documentation
- `.env.example` - Configuration examples

**Impact**:
- Prevents DoS attacks on analytics collection
- Stops data pollution from automated sources
- Maintains legitimate analytics collection performance
- Provides monitoring and alerting capabilities

**Backwards Compatibility**:
Fully backwards compatible. Rate limiting is enabled by default with conservative limits that should not affect legitimate usage.

**Testing**:
- Comprehensive unit tests covering all rate limiting scenarios
- Edge case testing for shared IPs and legitimate traffic spikes
- Performance testing confirming <5ms latency impact

**References**:
- CWE-770: Allocation of Resources Without Limits or Throttling
- OWASP API Security Top 10 - API4:2023 Unrestricted Resource Consumption

---

## Security Reporting

If you discover a security vulnerability in Umami, please report it to security@umami.is with the subject line "Security Vulnerability Report". Please do not report security vulnerabilities through public GitHub issues.

### Responsible Disclosure Policy

We follow a responsible disclosure policy:
1. Report vulnerabilities privately to security@umami.is
2. Allow reasonable time for fixing (typically 30-90 days)  
3. Coordinate public disclosure after fixes are deployed
4. Provide credit to security researchers who follow responsible disclosure