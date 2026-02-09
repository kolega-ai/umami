import { z } from 'zod';
import { saveAuth } from '@/lib/auth';
import { ROLES } from '@/lib/constants';
import { secret } from '@/lib/crypto';
import { createSecureToken } from '@/lib/jwt';
import { checkPassword } from '@/lib/password';
import redis from '@/lib/redis';
import { parseRequest } from '@/lib/request';
import { json, unauthorized } from '@/lib/response';
import { getAllUserTeams, getUserByUsername } from '@/queries/prisma';
import { resetRateLimit, AUTH_RATE_LIMITS } from '@/lib/rate-limit';
import { getIpAddress } from '@/lib/ip';
import { 
  checkAccountLockout, 
  incrementFailedAttempts, 
  resetFailedAttempts,
  getLockoutMessage 
} from '@/lib/account-lockout';

export async function POST(request: Request) {
  const schema = z.object({
    username: z.string(),
    password: z.string(),
  });

  const { body, error, rateLimitHeaders } = await parseRequest(request, schema, { 
    skipAuth: true,
    rateLimitConfig: AUTH_RATE_LIMITS['/api/auth/login']
  });

  if (error) {
    return error();
  }

  const { username, password } = body;

  // Check if account is locked out
  const lockoutResult = await checkAccountLockout(username);
  if (lockoutResult.isLocked) {
    return new Response(
      JSON.stringify({ 
        code: 'account-locked',
        message: getLockoutMessage(lockoutResult)
      }),
      {
        status: 423, // 423 Locked
        headers: {
          'Content-Type': 'application/json',
          ...rateLimitHeaders,
        },
      }
    );
  }

  const user = await getUserByUsername(username, { includePassword: true });

  if (!user || !checkPassword(password, user.password)) {
    // Failed login attempt - increment failed attempts for account protection
    await incrementFailedAttempts(username);
    
    return new Response(
      JSON.stringify({ code: 'incorrect-username-password' }),
      {
        status: 401,
        headers: {
          'Content-Type': 'application/json',
          ...rateLimitHeaders,
        },
      }
    );
  }

  const { id, role, createdAt } = user;

  let token: string;

  if (redis.enabled) {
    token = await saveAuth({ userId: id, role });
  } else {
    token = createSecureToken({ userId: user.id, role }, secret());
  }

  // Successful login - reset rate limit and failed attempts
  const ipAddress = getIpAddress(request.headers);
  const identifier = `/api/auth/login:${ipAddress}`;
  await Promise.all([
    resetRateLimit(identifier, AUTH_RATE_LIMITS['/api/auth/login']),
    resetFailedAttempts(username)
  ]);

  const teams = await getAllUserTeams(id);

  return new Response(
    JSON.stringify({
      token,
      user: { id, username, role, createdAt, isAdmin: role === ROLES.admin, teams },
    }),
    {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        ...rateLimitHeaders,
      },
    }
  );
}
