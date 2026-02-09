import redis from '@/lib/redis';

const LOCKOUT_DURATION = 30 * 60 * 1000; // 30 minutes in milliseconds
const MAX_FAILED_ATTEMPTS = 10; // Across all IPs for account protection

export interface AccountLockoutResult {
  isLocked: boolean;
  failedAttempts: number;
  lockoutExpiry?: Date;
}

/**
 * Check if an account is currently locked out
 * @param username - The username to check
 * @returns Account lockout status
 */
export async function checkAccountLockout(username: string): Promise<AccountLockoutResult> {
  if (!redis.enabled) {
    return { isLocked: false, failedAttempts: 0 };
  }

  const lockKey = `account_lockout:${username}`;
  const attemptKey = `failed_attempts:${username}`;

  try {
    const [lockData, attemptCount] = await Promise.all([
      redis.client.get(lockKey),
      redis.client.get(attemptKey),
    ]);

    const isLocked = !!lockData;
    const failedAttempts = parseInt(attemptCount || '0');
    let lockoutExpiry: Date | undefined;

    if (isLocked && lockData) {
      // Parse lockout expiry from stored data
      lockoutExpiry = new Date(parseInt(lockData));
    }

    return {
      isLocked,
      failedAttempts,
      lockoutExpiry,
    };
  } catch (error) {
    console.error('Failed to check account lockout:', error);
    // Fail open on error to prevent service disruption
    return { isLocked: false, failedAttempts: 0 };
  }
}

/**
 * Increment failed login attempts for an account
 * @param username - The username that failed login
 * @returns New failed attempt count and lockout status
 */
export async function incrementFailedAttempts(username: string): Promise<AccountLockoutResult> {
  if (!redis.enabled) {
    return { isLocked: false, failedAttempts: 0 };
  }

  const attemptKey = `failed_attempts:${username}`;
  const lockKey = `account_lockout:${username}`;

  try {
    // Increment failed attempts counter
    const attempts = await redis.client.incr(attemptKey);

    // Set expiry on first attempt (1 hour window for failed attempts)
    if (attempts === 1) {
      await redis.client.expire(attemptKey, 3600);
    }

    // Lock account if too many attempts
    if (attempts >= MAX_FAILED_ATTEMPTS) {
      const lockExpiry = Date.now() + LOCKOUT_DURATION;
      await redis.client.set(lockKey, lockExpiry.toString(), 'PX', LOCKOUT_DURATION);

      return {
        isLocked: true,
        failedAttempts: attempts,
        lockoutExpiry: new Date(lockExpiry),
      };
    }

    return {
      isLocked: false,
      failedAttempts: attempts,
    };
  } catch (error) {
    console.error('Failed to increment failed attempts:', error);
    return { isLocked: false, failedAttempts: 0 };
  }
}

/**
 * Reset failed login attempts for an account (called on successful login)
 * @param username - The username that successfully logged in
 */
export async function resetFailedAttempts(username: string): Promise<void> {
  if (!redis.enabled) return;

  const attemptKey = `failed_attempts:${username}`;
  const lockKey = `account_lockout:${username}`;

  try {
    // Remove both failed attempts counter and any lockout
    await redis.client.del(attemptKey, lockKey);
  } catch (error) {
    console.error('Failed to reset failed attempts:', error);
  }
}

/**
 * Get human-readable lockout message
 * @param lockoutResult - Result from checkAccountLockout
 * @returns Formatted error message
 */
export function getLockoutMessage(lockoutResult: AccountLockoutResult): string {
  if (!lockoutResult.isLocked) {
    return '';
  }

  if (lockoutResult.lockoutExpiry) {
    const minutesRemaining = Math.ceil(
      (lockoutResult.lockoutExpiry.getTime() - Date.now()) / (1000 * 60)
    );
    return `Account is temporarily locked due to multiple failed login attempts. Please try again in ${minutesRemaining} minute(s).`;
  }

  return 'Account is temporarily locked due to multiple failed login attempts. Please try again later.';
}