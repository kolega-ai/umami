import { parseRequest } from '@/lib/request';
import { json } from '@/lib/response';
import { getAllUserTeams } from '@/queries/prisma';
import { AUTH_RATE_LIMITS } from '@/lib/rate-limit';

export async function POST(request: Request) {
  const { auth, error, rateLimitHeaders } = await parseRequest(request, undefined, {
    skipAuth: false,
    rateLimitConfig: AUTH_RATE_LIMITS['/api/auth/verify']
  });

  if (error) {
    return error();
  }

  const teams = await getAllUserTeams(auth.user.id);

  return new Response(
    JSON.stringify({ ...auth.user, teams }),
    {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        ...rateLimitHeaders,
      },
    }
  );
}
