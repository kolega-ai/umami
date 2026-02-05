import { PrismaPg } from '@prisma/adapter-pg';
import { readReplicas } from '@prisma/extension-read-replicas';
import debug from 'debug';
import { PrismaClient } from '@/generated/prisma/client';
import { DEFAULT_PAGE_SIZE, FILTER_COLUMNS, OPERATORS, SESSION_COLUMNS, UNIT_TYPES } from './constants';
import { filtersObjectToArray } from './params';
import type { Operator, QueryFilters, QueryOptions } from './types';

const log = debug('umami:prisma');

const PRISMA = 'prisma';

const PRISMA_LOG_OPTIONS = {
  log: [
    {
      emit: 'event' as const,
      level: 'query' as const,
    },
  ],
};

// Security: Valid database field names based on schema analysis
const VALID_FIELD_NAMES = new Set([
  'created_at',
  'date_value',
  'website_event.created_at',
  'session.created_at',
  'revenue.created_at',
  'event_data.created_at',
  'session_data.created_at',
]);

// Security: Valid timezones - comprehensive list of PostgreSQL-compatible timezones
const VALID_TIMEZONES = new Set([
  'UTC', 'GMT', 
  // Americas
  'America/New_York', 'America/Chicago', 'America/Denver', 'America/Los_Angeles',
  'America/Toronto', 'America/Vancouver', 'America/Mexico_City', 'America/Sao_Paulo',
  'America/Argentina/Buenos_Aires', 'America/Lima', 'America/Bogota',
  // Europe
  'Europe/London', 'Europe/Paris', 'Europe/Berlin', 'Europe/Rome', 'Europe/Madrid',
  'Europe/Amsterdam', 'Europe/Brussels', 'Europe/Vienna', 'Europe/Stockholm',
  'Europe/Copenhagen', 'Europe/Helsinki', 'Europe/Warsaw', 'Europe/Prague',
  'Europe/Budapest', 'Europe/Zurich', 'Europe/Athens', 'Europe/Istanbul',
  'Europe/Moscow', 'Europe/Kiev', 'Europe/Bucharest', 'Europe/Sofia',
  // Asia
  'Asia/Tokyo', 'Asia/Shanghai', 'Asia/Hong_Kong', 'Asia/Singapore',
  'Asia/Seoul', 'Asia/Bangkok', 'Asia/Jakarta', 'Asia/Manila',
  'Asia/Mumbai', 'Asia/Kolkata', 'Asia/Dhaka', 'Asia/Karachi',
  'Asia/Dubai', 'Asia/Tehran', 'Asia/Baghdad', 'Asia/Riyadh',
  // Australia/Pacific
  'Australia/Sydney', 'Australia/Melbourne', 'Australia/Brisbane', 'Australia/Perth',
  'Australia/Adelaide', 'Australia/Darwin', 'Australia/Hobart',
  'Pacific/Auckland', 'Pacific/Fiji', 'Pacific/Honolulu', 'Pacific/Tahiti',
  // Africa
  'Africa/Cairo', 'Africa/Lagos', 'Africa/Johannesburg', 'Africa/Nairobi',
  'Africa/Casablanca', 'Africa/Tunis', 'Africa/Algiers',
]);

// Security: Regex for numeric timezone offsets (+03:00, -0530, etc.)
const TIMEZONE_OFFSET_REGEX = /^[+-](?:0[0-9]|1[0-4])(?::?[0-5][0-9])?$/;

// Security: Valid date units (uses existing UNIT_TYPES constant)
const VALID_DATE_UNITS = new Set(UNIT_TYPES);

const DATE_FORMATS = {
  minute: 'YYYY-MM-DD HH24:MI:00',
  hour: 'YYYY-MM-DD HH24:00:00',
  day: 'YYYY-MM-DD HH24:00:00',
  month: 'YYYY-MM-01 HH24:00:00',
  year: 'YYYY-01-01 HH24:00:00',
};

const DATE_FORMATS_UTC = {
  minute: 'YYYY-MM-DD"T"HH24:MI:00"Z"',
  hour: 'YYYY-MM-DD"T"HH24:00:00"Z"',
  day: 'YYYY-MM-DD"T"HH24:00:00"Z"',
  month: 'YYYY-MM-01"T"HH24:00:00"Z"',
  year: 'YYYY-01-01"T"HH24:00:00"Z"',
};

/**
 * Security: Escape PostgreSQL string literals by doubling single quotes
 */
function escapePostgreSQLString(str: string): string {
  if (typeof str !== 'string') {
    throw new Error('Input must be a string');
  }
  
  // Escape single quotes by doubling them (PostgreSQL standard)
  // Remove potentially dangerous characters that could break SQL syntax
  return str
    .replace(/'/g, "''")
    .replace(/[\\;`\0\n\r\x1a]/g, ''); // Remove backslash, semicolon, backtick, null, newlines, substitute
}

/**
 * Security: Validate field name parameter against whitelist
 * Prevents SQL injection through field parameter
 */
function validateFieldName(field: string): string {
  if (!field || typeof field !== 'string') {
    log('Security: Invalid field name type attempted:', typeof field);
    throw new Error('Field name is required and must be a string');
  }
  
  const trimmedField = field.trim();
  
  if (!VALID_FIELD_NAMES.has(trimmedField)) {
    log('Security: Invalid field name attempted:', trimmedField);
    throw new Error(`Invalid field name: ${trimmedField}. Must be a valid database field.`);
  }
  
  return trimmedField;
}

/**
 * Security: Validate date unit parameter against allowed values
 * Prevents SQL injection through unit parameter
 */
function validateDateUnit(unit: string): string {
  if (!unit || typeof unit !== 'string') {
    log('Security: Invalid date unit type attempted:', typeof unit);
    throw new Error('Date unit is required and must be a string');
  }
  
  const trimmedUnit = unit.trim().toLowerCase();
  
  if (!VALID_DATE_UNITS.has(trimmedUnit)) {
    log('Security: Invalid date unit attempted:', trimmedUnit);
    throw new Error(`Invalid date unit: ${trimmedUnit}. Must be one of: ${Array.from(VALID_DATE_UNITS).join(', ')}`);
  }
  
  return trimmedUnit;
}

/**
 * Security: Validate timezone parameter against whitelist
 * Prevents SQL injection through timezone parameter
 */
function validateTimezone(timezone?: string): string | undefined {
  if (!timezone) {
    return timezone; // undefined/empty is valid (uses server default)
  }
  
  if (typeof timezone !== 'string') {
    log('Security: Invalid timezone type attempted:', typeof timezone);
    throw new Error('Timezone must be a string');
  }
  
  const trimmedTimezone = timezone.trim();
  
  // Check against whitelist of valid timezones
  if (VALID_TIMEZONES.has(trimmedTimezone)) {
    return trimmedTimezone;
  }
  
  // Check if it's a valid numeric offset format
  if (TIMEZONE_OFFSET_REGEX.test(trimmedTimezone)) {
    return trimmedTimezone;
  }
  
  // Log security event for monitoring
  log('Security: Invalid timezone attempted:', trimmedTimezone);
  throw new Error(`Invalid timezone: ${trimmedTimezone}. Must be a valid IANA timezone identifier or numeric offset.`);
}

function getAddIntervalQuery(field: string, interval: string): string {
  return `${field} + interval '${interval}'`;
}

function getDayDiffQuery(field1: string, field2: string): string {
  return `${field1}::date - ${field2}::date`;
}

function getCastColumnQuery(field: string, type: string): string {
  return `${field}::${type}`;
}

function getDateSQL(field: string, unit: string, timezone?: string): string {
  // Security: Validate and sanitize all user inputs to prevent SQL injection
  const validField = validateFieldName(field);
  const validUnit = validateDateUnit(unit);
  const validTimezone = validateTimezone(timezone);

  // Get the format string from our controlled object
  const format = validTimezone && validTimezone !== 'utc' ? DATE_FORMATS[validUnit] : DATE_FORMATS_UTC[validUnit];

  if (validTimezone && validTimezone !== 'utc') {
    // Security: Escape the validated timezone as additional defense
    const escapedTimezone = escapePostgreSQLString(validTimezone);
    return `to_char(date_trunc('${validUnit}', ${validField} at time zone '${escapedTimezone}'), '${format}')`;
  }

  return `to_char(date_trunc('${validUnit}', ${validField}), '${format}')`;
}

function getDateWeeklySQL(field: string, timezone?: string) {
  // Security: Validate and sanitize all user inputs to prevent SQL injection
  const validField = validateFieldName(field);
  const validTimezone = validateTimezone(timezone);

  if (validTimezone) {
    // Security: Escape the validated timezone as additional defense
    const escapedTimezone = escapePostgreSQLString(validTimezone);
    return `concat(extract(dow from (${validField} at time zone '${escapedTimezone}')), ':', to_char((${validField} at time zone '${escapedTimezone}'), 'HH24'))`;
  }

  return `concat(extract(dow from ${validField}), ':', to_char(${validField}, 'HH24'))`;
}

export function getTimestampSQL(field: string) {
  return `floor(extract(epoch from ${field}))`;
}

function getTimestampDiffSQL(field1: string, field2: string): string {
  return `floor(extract(epoch from (${field2} - ${field1})))`;
}

function getSearchSQL(column: string, param: string = 'search'): string {
  return `and ${column} ilike {{${param}}}`;
}

function mapFilter(column: string, operator: string, name: string, type: string = '') {
  const value = `{{${name}${type ? `::${type}` : ''}}}`;

  switch (operator) {
    case OPERATORS.equals:
      return `${column} = ${value}`;
    case OPERATORS.notEquals:
      return `${column} != ${value}`;
    case OPERATORS.contains:
      return `${column} ilike ${value}`;
    case OPERATORS.doesNotContain:
      return `${column} not ilike ${value}`;
    default:
      return '';
  }
}

function getFilterQuery(filters: Record<string, any>, options: QueryOptions = {}): string {
  const query = filtersObjectToArray(filters, options).reduce(
    (arr, { name, column, operator, prefix = '' }) => {
      const isCohort = options?.isCohort;

      if (isCohort) {
        column = FILTER_COLUMNS[name.slice('cohort_'.length)];
      }

      if (column) {
        arr.push(`and ${mapFilter(`${prefix}${column}`, operator, name)}`);

        if (name === 'referrer') {
          arr.push(
            `and (website_event.referrer_domain != website_event.hostname or website_event.referrer_domain is null)`,
          );
        }
      }

      return arr;
    },
    [],
  );

  return query.join('\n');
}

function getCohortQuery(filters: QueryFilters = {}) {
  if (!filters || Object.keys(filters).length === 0) {
    return '';
  }

  const filterQuery = getFilterQuery(filters, { isCohort: true });

  return `join
    (select distinct website_event.session_id
    from website_event
    join session on session.session_id = website_event.session_id
      and session.website_id = website_event.website_id
    where website_event.website_id = {{websiteId}}
      and website_event.created_at between {{cohort_startDate}} and {{cohort_endDate}}
      ${filterQuery}
    ) cohort
    on cohort.session_id = website_event.session_id
    `;
}

function getDateQuery(filters: Record<string, any>) {
  const { startDate, endDate } = filters;

  if (startDate) {
    if (endDate) {
      return `and website_event.created_at between {{startDate}} and {{endDate}}`;
    } else {
      return `and website_event.created_at >= {{startDate}}`;
    }
  }

  return '';
}

function getQueryParams(filters: Record<string, any>) {
  return {
    ...filters,
    ...filtersObjectToArray(filters).reduce((obj, { name, operator, value }) => {
      obj[name] = ([OPERATORS.contains, OPERATORS.doesNotContain] as Operator[]).includes(operator)
        ? `%${value}%`
        : value;

      return obj;
    }, {}),
  };
}

function parseFilters(filters: Record<string, any>, options?: QueryOptions) {
  const joinSession = Object.keys(filters).find(key =>
    ['referrer', ...SESSION_COLUMNS].includes(key),
  );

  const cohortFilters = Object.fromEntries(
    Object.entries(filters).filter(([key]) => key.startsWith('cohort_')),
  );

  return {
    joinSessionQuery:
      options?.joinSession || joinSession
        ? `inner join session on website_event.session_id = session.session_id and website_event.website_id = session.website_id`
        : '',
    dateQuery: getDateQuery(filters),
    filterQuery: getFilterQuery(filters, options),
    queryParams: getQueryParams(filters),
    cohortQuery: getCohortQuery(cohortFilters),
  };
}

async function rawQuery(sql: string, data: Record<string, any>, name?: string): Promise<any> {
  if (process.env.LOG_QUERY) {
    log('QUERY:\n', sql);
    log('PARAMETERS:\n', data);
    log('NAME:\n', name);
  }
  const params = [];
  const schema = getSchema();

  if (schema) {
    await client.$executeRawUnsafe(`SET search_path TO "${schema}";`);
  }

  const query = sql?.replaceAll(/\{\{\s*(\w+)(::\w+)?\s*}}/g, (...args) => {
    const [, name, type] = args;

    const value = data[name];

    params.push(value);

    return `$${params.length}${type ?? ''}`;
  });

  if (process.env.DATABASE_REPLICA_URL && '$replica' in client) {
    return client.$replica().$queryRawUnsafe(query, ...params);
  }

  return client.$queryRawUnsafe(query, ...params);
}

async function pagedQuery<T>(model: string, criteria: T, filters?: QueryFilters) {
  const { page = 1, pageSize, orderBy, sortDescending = false, search } = filters || {};
  const size = +pageSize || DEFAULT_PAGE_SIZE;

  const data = await client[model].findMany({
    ...criteria,
    ...{
      ...(size > 0 && { take: +size, skip: +size * (+page - 1) }),
      ...(orderBy && {
        orderBy: [
          {
            [orderBy]: sortDescending ? 'desc' : 'asc',
          },
        ],
      }),
    },
  });

  const count = await client[model].count({ where: (criteria as any).where });

  return { data, count, page: +page, pageSize: size, orderBy, search };
}

async function pagedRawQuery(
  query: string,
  queryParams: Record<string, any>,
  filters: QueryFilters,
  name?: string,
) {
  const { page = 1, pageSize, orderBy, sortDescending = false } = filters;
  const size = +pageSize || DEFAULT_PAGE_SIZE;
  const offset = +size * (+page - 1);
  const direction = sortDescending ? 'desc' : 'asc';

  const statements = [
    orderBy && `order by ${orderBy} ${direction}`,
    +size > 0 && `limit ${+size} offset ${offset}`,
  ]
    .filter(n => n)
    .join('\n');

  const count = await rawQuery(`select count(*) as num from (${query}) t`, queryParams).then(
    res => res[0].num,
  );

  const data = await rawQuery(`${query}${statements}`, queryParams, name);

  return { data, count, page: +page, pageSize: size, orderBy };
}

function getSearchParameters(query: string, filters: Record<string, any>[]) {
  if (!query) return;

  const parseFilter = (filter: Record<string, any>) => {
    const [[key, value]] = Object.entries(filter);

    return {
      [key]:
        typeof value === 'string'
          ? {
              [value]: query,
              mode: 'insensitive',
            }
          : parseFilter(value),
    };
  };

  const params = filters.map(filter => parseFilter(filter));

  return {
    AND: {
      OR: params,
    },
  };
}

function transaction(input: any, options?: any) {
  return client.$transaction(input, options);
}

function getSchema() {
  const connectionUrl = new URL(process.env.DATABASE_URL);

  return connectionUrl.searchParams.get('schema');
}

function getClient() {
  const url = process.env.DATABASE_URL;
  const replicaUrl = process.env.DATABASE_REPLICA_URL;
  const logQuery = process.env.LOG_QUERY;
  const schema = getSchema();

  const baseAdapter = new PrismaPg({ connectionString: url }, { schema });

  const baseClient = new PrismaClient({
    adapter: baseAdapter,
    errorFormat: 'pretty',
    ...(logQuery ? PRISMA_LOG_OPTIONS : {}),
  });

  if (logQuery) {
    baseClient.$on('query', log);
  }

  if (!replicaUrl) {
    log('Prisma initialized');
    globalThis[PRISMA] ??= baseClient;
    return baseClient;
  }

  const replicaAdapter = new PrismaPg({ connectionString: replicaUrl }, { schema });

  const replicaClient = new PrismaClient({
    adapter: replicaAdapter,
    errorFormat: 'pretty',
    ...(logQuery ? PRISMA_LOG_OPTIONS : {}),
  });

  if (logQuery) {
    replicaClient.$on('query', log);
  }

  const extended = baseClient.$extends(
    readReplicas({
      replicas: [replicaClient],
    }),
  );

  log('Prisma initialized (with replica)');
  globalThis[PRISMA] ??= extended;

  return extended;
}

const client = (globalThis[PRISMA] || getClient()) as ReturnType<typeof getClient>;

export default {
  client,
  transaction,
  getAddIntervalQuery,
  getCastColumnQuery,
  getDayDiffQuery,
  getDateSQL,
  getDateWeeklySQL,
  getFilterQuery,
  getSearchParameters,
  getTimestampDiffSQL,
  getSearchSQL,
  pagedQuery,
  pagedRawQuery,
  parseFilters,
  rawQuery,
};
