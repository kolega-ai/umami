import { saveAuth } from '@/lib/auth';
import redis from '@/lib/redis';
import { parseRequest } from '@/lib/request';
import { json } from '@/lib/response';
import { AUTH_RATE_LIMITS } from '@/lib/rate-limit';

export async function POST(request: Request) {
  const { auth, error, rateLimitHeaders } = await parseRequest(request, undefined, {
    skipAuth: false,
    rateLimitConfig: AUTH_RATE_LIMITS['/api/auth/sso']
  });

  if (error) {
    return error();
  }

  if (redis.enabled) {
    const token = await saveAuth({ userId: auth.user.id }, 86400);

    return new Response(
      JSON.stringify({ user: auth.user, token }),
      {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          ...rateLimitHeaders,
        },
      }
    );
  }

  return new Response(
    JSON.stringify({ error: 'SSO not available' }),
    {
      status: 503,
      headers: {
        'Content-Type': 'application/json',
        ...rateLimitHeaders,
      },
    }
  );
}
