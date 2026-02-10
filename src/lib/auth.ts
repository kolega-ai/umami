import debug from 'debug';
import { ROLE_PERMISSIONS, ROLES, SHARE_TOKEN_HEADER } from '@/lib/constants';
import { secret } from '@/lib/crypto';
import { getRandomChars } from '@/lib/generate';
import { createSecureToken, parseSecureToken, parseToken } from '@/lib/jwt';
import redis from '@/lib/redis';
import { ensureArray } from '@/lib/utils';
import { getUser } from '@/queries/prisma/user';

const log = debug('umami:auth');

export function getBearerToken(request: Request) {
  const auth = request.headers.get('authorization');

  return auth?.split(' ')[1];
}

export async function checkAuth(request: Request) {
  const token = getBearerToken(request);
  const payload = parseSecureToken(token, secret());
  const shareToken = await parseShareToken(request);

  let user = null;
  const { userId, authKey } = payload || {};

  if (userId) {
    user = await getUser(userId);
  } else if (redis.enabled && authKey) {
    const key = await redis.client.get(authKey);

    if (key?.userId) {
      user = await getUser(key.userId);
    }
  }

  if (user) {
    user.isAdmin = user.role === ROLES.admin;
  }

  // Determine authentication method with priority: user > share > none
  let authMethod: 'user' | 'share' | 'none' = 'none';
  
  if (user?.id) {
    authMethod = 'user';
  } else if (shareToken) {
    authMethod = 'share';
  }

  log({ token, payload, authKey, shareToken, user, authMethod });

  if (authMethod === 'none') {
    log('No valid authentication found');
    return null;
  }

  return {
    token,
    authKey,
    shareToken,
    user,
    authMethod,
  };
}

export async function requireUserAuth(request: Request) {
  const auth = await checkAuth(request);
  
  if (!auth || auth.authMethod !== 'user') {
    log('User authentication required but not provided');
    return null;
  }
  
  return auth;
}

export async function allowShareAuth(request: Request) {
  const auth = await checkAuth(request);
  
  if (!auth || auth.authMethod === 'none') {
    log('Authentication required but not provided');
    return null;
  }
  
  return auth;
}

export async function saveAuth(data: any, expire = 0) {
  const authKey = `auth:${getRandomChars(32)}`;

  if (redis.enabled) {
    await redis.client.set(authKey, data);

    if (expire) {
      await redis.client.expire(authKey, expire);
    }
  }

  return createSecureToken({ authKey }, secret());
}

export async function hasPermission(role: string, permission: string | string[]) {
  return ensureArray(permission).some(e => ROLE_PERMISSIONS[role]?.includes(e));
}

export function parseShareToken(request: Request) {
  try {
    return parseToken(request.headers.get(SHARE_TOKEN_HEADER), secret());
  } catch (e) {
    log(e);
    return null;
  }
}
