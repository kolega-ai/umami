import { z } from 'zod';
import { checkAuth } from '@/lib/auth';
import { DEFAULT_PAGE_SIZE, FILTER_COLUMNS } from '@/lib/constants';
import { getAllowedUnits, getMinimumUnit, maxDate, parseDateRange } from '@/lib/date';
import { fetchWebsite } from '@/lib/load';
import { filtersArrayToObject } from '@/lib/params';
import { badRequest, unauthorized } from '@/lib/response';
import type { QueryFilters } from '@/lib/types';
import { getWebsiteSegment } from '@/queries/prisma';
import { getIpAddress } from '@/lib/ip';
import { 
  checkRateLimit, 
  AUTH_RATE_LIMITS, 
  getRateLimitHeaders,
  type RateLimitConfig 
} from '@/lib/rate-limit';

export async function parseRequest(
  request: Request,
  schema?: any,
  options?: { skipAuth: boolean; rateLimitConfig?: RateLimitConfig | false },
): Promise<any> {
  const url = new URL(request.url);
  let query = Object.fromEntries(url.searchParams);
  let body = await getJsonBody(request);
  let error: (() => Response) | undefined;
  let auth = null;
  let rateLimitHeaders: Record<string, string> = {};

  // Check rate limiting if configured
  if (options?.rateLimitConfig !== false) {
    const pathname = url.pathname;
    const rateLimitConfig = options?.rateLimitConfig || AUTH_RATE_LIMITS[pathname];
    
    if (rateLimitConfig) {
      const ipAddress = getIpAddress(request.headers);
      const identifier = `${pathname}:${ipAddress}`;
      const rateLimitResult = await checkRateLimit(identifier, rateLimitConfig);
      
      rateLimitHeaders = getRateLimitHeaders(rateLimitResult);
      
      if (!rateLimitResult.allowed) {
        error = () => {
          const errorMessage = rateLimitResult.retryAfter 
            ? `Rate limit exceeded. Please try again in ${rateLimitResult.retryAfter} seconds.`
            : 'Rate limit exceeded. Please try again later.';
            
          return new Response(
            JSON.stringify({
              error: 'Too many requests',
              message: errorMessage,
              retryAfter: rateLimitResult.retryAfter,
            }),
            {
              status: 429,
              headers: {
                'Content-Type': 'application/json',
                ...rateLimitHeaders,
              },
            }
          );
        };
      }
    }
  }

  if (schema) {
    const isGet = request.method === 'GET';
    const result = schema.safeParse(isGet ? query : body);

    if (!result.success) {
      const originalError = () => badRequest(z.treeifyError(result.error));
      error = () => {
        const response = originalError();
        // Add rate limit headers to validation errors
        const headers = new Headers(response.headers);
        Object.entries(rateLimitHeaders).forEach(([key, value]) => {
          headers.set(key, value);
        });
        return new Response(response.body, {
          status: response.status,
          headers,
        });
      };
    } else if (isGet) {
      query = result.data;
    } else {
      body = result.data;
    }
  }

  if (!options?.skipAuth && !error) {
    auth = await checkAuth(request);

    if (!auth) {
      const originalError = () => unauthorized();
      error = () => {
        const response = originalError();
        // Add rate limit headers to auth errors
        const headers = new Headers(response.headers);
        Object.entries(rateLimitHeaders).forEach(([key, value]) => {
          headers.set(key, value);
        });
        return new Response(response.body, {
          status: response.status,
          headers,
        });
      };
    }
  }

  return { url, query, body, auth, error, rateLimitHeaders };
}

export async function getJsonBody(request: Request) {
  try {
    return await request.clone().json();
  } catch {
    return undefined;
  }
}

export function getRequestDateRange(query: Record<string, string>) {
  const { startAt, endAt, unit, timezone } = query;

  const startDate = new Date(+startAt);
  const endDate = new Date(+endAt);

  return {
    startDate,
    endDate,
    timezone,
    unit: getAllowedUnits(startDate, endDate).includes(unit)
      ? unit
      : getMinimumUnit(startDate, endDate),
  };
}

export function getRequestFilters(query: Record<string, any>) {
  const result: Record<string, any> = {};

  for (const key of Object.keys(FILTER_COLUMNS)) {
    const value = query[key];
    if (value !== undefined) {
      result[key] = value;
    }
  }

  return result;
}

export async function setWebsiteDate(websiteId: string, data: Record<string, any>) {
  const website = await fetchWebsite(websiteId);

  if (website?.resetAt) {
    data.startDate = maxDate(data.startDate, new Date(website?.resetAt));
  }

  return data;
}

export async function getQueryFilters(
  params: Record<string, any>,
  websiteId?: string,
): Promise<QueryFilters> {
  const dateRange = getRequestDateRange(params);
  const filters = getRequestFilters(params);

  if (websiteId) {
    await setWebsiteDate(websiteId, dateRange);

    if (params.segment) {
      const segmentParams = (await getWebsiteSegment(websiteId, params.segment))
        ?.parameters as Record<string, any>;

      Object.assign(filters, filtersArrayToObject(segmentParams.filters));
    }

    if (params.cohort) {
      const cohortParams = (await getWebsiteSegment(websiteId, params.cohort))
        ?.parameters as Record<string, any>;

      const { startDate, endDate } = parseDateRange(cohortParams.dateRange);

      const cohortFilters = cohortParams.filters.map(({ name, ...props }) => ({
        ...props,
        name: `cohort_${name}`,
      }));

      cohortFilters.push({
        name: `cohort_${cohortParams.action.type}`,
        operator: 'eq',
        value: cohortParams.action.value,
      });

      Object.assign(filters, {
        ...filtersArrayToObject(cohortFilters),
        cohort_startDate: startDate,
        cohort_endDate: endDate,
      });
    }
  }

  return {
    ...dateRange,
    ...filters,
    page: params?.page,
    pageSize: params?.pageSize ? params?.pageSize || DEFAULT_PAGE_SIZE : undefined,
    orderBy: params?.orderBy,
    sortDescending: params?.sortDescending,
    search: params?.search,
    compare: params?.compare,
  };
}
