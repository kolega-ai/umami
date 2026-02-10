import { PrismaPg } from '@prisma/adapter-pg';
import { readReplicas } from '@prisma/extension-read-replicas';
import debug from 'debug';
import { PrismaClient } from '@/generated/prisma/client';
import { DEFAULT_PAGE_SIZE, FILTER_COLUMNS, OPERATORS, SESSION_COLUMNS } from './constants';
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

// Security: Whitelist of valid PostgreSQL timezones
const VALID_TIMEZONES = new Set([
  'UTC',
  'GMT',
  'US/Eastern',
  'US/Central',
  'US/Mountain',
  'US/Pacific',
  'America/New_York',
  'America/Chicago',
  'America/Denver',
  'America/Los_Angeles',
  'America/Toronto',
  'America/Vancouver',
  'America/Mexico_City',
  'America/Sao_Paulo',
  'America/Argentina/Buenos_Aires',
  'Europe/London',
  'Europe/Paris',
  'Europe/Berlin',
  'Europe/Rome',
  'Europe/Madrid',
  'Europe/Amsterdam',
  'Europe/Brussels',
  'Europe/Vienna',
  'Europe/Zurich',
  'Europe/Stockholm',
  'Europe/Copenhagen',
  'Europe/Helsinki',
  'Europe/Oslo',
  'Europe/Warsaw',
  'Europe/Prague',
  'Europe/Budapest',
  'Europe/Bucharest',
  'Europe/Athens',
  'Europe/Istanbul',
  'Europe/Moscow',
  'Asia/Tokyo',
  'Asia/Shanghai',
  'Asia/Hong_Kong',
  'Asia/Singapore',
  'Asia/Seoul',
  'Asia/Taipei',
  'Asia/Bangkok',
  'Asia/Jakarta',
  'Asia/Manila',
  'Asia/Mumbai',
  'Asia/Dubai',
  'Asia/Jerusalem',
  'Australia/Sydney',
  'Australia/Melbourne',
  'Australia/Perth',
  'Pacific/Auckland',
  'Pacific/Honolulu',
  'Africa/Cairo',
  'Africa/Johannesburg',
  'Africa/Lagos',
]);

// Security: Valid date units for date_trunc function
const VALID_DATE_UNITS = new Set([
  'microseconds',
  'milliseconds',
  'second',
  'minute',
  'hour',
  'day',
  'week',
  'month',
  'quarter',
  'year',
  'decade',
  'century',
  'millennium',
]);

// Security: Validate field name to prevent SQL injection
function validateFieldName(field: string): boolean {
  if (!field || typeof field !== 'string') {
    return false;
  }
  // Field names should only contain alphanumeric, underscore, and dot (for table.column)
  const fieldRegex = /^[a-zA-Z_][a-zA-Z0-9_]*(\.[a-zA-Z_][a-zA-Z0-9_]*)?$/;
  return fieldRegex.test(field);
}

// Security: Validate and sanitize timezone
function validateTimezone(timezone?: string): string | null {
  if (!timezone || typeof timezone !== 'string') {
    return null;
  }

  // Check against whitelist of known timezones
  if (VALID_TIMEZONES.has(timezone)) {
    return timezone;
  }

  // Check for UTC offset format (e.g., '+05:30', '-08:00')
  const utcOffsetRegex = /^[+-](?:0[0-9]|1[0-4]):[0-5][0-9]$/;
  if (utcOffsetRegex.test(timezone)) {
    return timezone;
  }

  // Check for simple offset format (e.g., '+05', '-08')
  const simpleOffsetRegex = /^[+-](?:0[0-9]|1[0-4])$/;
  if (simpleOffsetRegex.test(timezone)) {
    return timezone;
  }

  // Log potential SQL injection attempt
  log('Invalid timezone provided:', timezone);
  
  return null;
}

// Security: Validate date unit
function validateDateUnit(unit: string): string | null {
  if (!unit || typeof unit !== 'string') {
    return null;
  }
  
  const lowerUnit = unit.toLowerCase();
  if (VALID_DATE_UNITS.has(lowerUnit)) {
    return lowerUnit;
  }
  
  log('Invalid date unit provided:', unit);
  return null;
}

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

function getAddIntervalQuery(field: string, interval: string): string {
  // Security: Validate field name to prevent SQL injection
  if (!validateFieldName(field)) {
    throw new Error(`Invalid field name: ${field}`);
  }

  // Security: Validate interval format (PostgreSQL interval syntax)
  const intervalRegex = /^(\d+\s+(microseconds?|milliseconds?|seconds?|minutes?|hours?|days?|weeks?|months?|years?))(\s+\d+\s+(microseconds?|milliseconds?|seconds?|minutes?|hours?|days?|weeks?|months?|years?))*$/i;
  if (!intervalRegex.test(interval.trim())) {
    throw new Error(`Invalid interval format: ${interval}`);
  }

  return `${field} + interval '${interval}'`;
}

function getDayDiffQuery(field1: string, field2: string): string {
  // Security: Validate both field names to prevent SQL injection
  if (!validateFieldName(field1)) {
    throw new Error(`Invalid field name: ${field1}`);
  }
  if (!validateFieldName(field2)) {
    throw new Error(`Invalid field name: ${field2}`);
  }

  return `${field1}::date - ${field2}::date`;
}

function getCastColumnQuery(field: string, type: string): string {
  // Security: Validate field name to prevent SQL injection
  if (!validateFieldName(field)) {
    throw new Error(`Invalid field name: ${field}`);
  }

  // Security: Validate PostgreSQL data type
  const validTypes = new Set([
    'bigint', 'int8', 'bigserial', 'serial8', 'bit', 'boolean', 'bool', 'box', 'bytea',
    'character', 'char', 'character varying', 'varchar', 'cidr', 'circle', 'date',
    'double precision', 'float8', 'inet', 'integer', 'int', 'int4', 'interval',
    'json', 'jsonb', 'line', 'lseg', 'macaddr', 'macaddr8', 'money', 'numeric',
    'decimal', 'path', 'pg_lsn', 'point', 'polygon', 'real', 'float4', 'smallint',
    'int2', 'smallserial', 'serial2', 'serial', 'serial4', 'text', 'time',
    'timestamp', 'timestamptz', 'timetz', 'tsquery', 'tsvector', 'txid_snapshot',
    'uuid', 'xml'
  ]);
  
  if (!validTypes.has(type.toLowerCase())) {
    throw new Error(`Invalid PostgreSQL data type: ${type}`);
  }

  return `${field}::${type}`;
}

function getDateSQL(field: string, unit: string, timezone?: string): string {
  // Security: Validate all inputs to prevent SQL injection
  if (!validateFieldName(field)) {
    throw new Error(`Invalid field name: ${field}`);
  }

  const validatedUnit = validateDateUnit(unit);
  if (!validatedUnit) {
    throw new Error(`Invalid date unit: ${unit}`);
  }

  // Security: If timezone is provided but invalid, throw error instead of falling back
  if (timezone && typeof timezone === 'string' && timezone !== '') {
    const validatedTimezone = validateTimezone(timezone);
    if (!validatedTimezone) {
      throw new Error(`Invalid timezone: ${timezone}`);
    }
    
    // Use validated timezone
    if (validatedTimezone.toLowerCase() !== 'utc') {
      const format = DATE_FORMATS[validatedUnit];
      if (!format) {
        throw new Error(`No format defined for unit: ${validatedUnit}`);
      }
      return `to_char(date_trunc('${validatedUnit}', ${field} at time zone '${validatedTimezone}'), '${format}')`;
    }
  }

  // Default to UTC behavior when no timezone is provided or timezone is 'utc'
  const formatUtc = DATE_FORMATS_UTC[validatedUnit];
  if (!formatUtc) {
    throw new Error(`No UTC format defined for unit: ${validatedUnit}`);
  }
  return `to_char(date_trunc('${validatedUnit}', ${field}), '${formatUtc}')`;
}

function getDateWeeklySQL(field: string, timezone?: string) {
  // Security: Validate field name to prevent SQL injection
  if (!validateFieldName(field)) {
    throw new Error(`Invalid field name: ${field}`);
  }

  // Security: If timezone is provided but invalid, throw error instead of falling back
  if (timezone && typeof timezone === 'string' && timezone !== '') {
    const validatedTimezone = validateTimezone(timezone);
    if (!validatedTimezone) {
      throw new Error(`Invalid timezone: ${timezone}`);
    }
    return `concat(extract(dow from (${field} at time zone '${validatedTimezone}')), ':', to_char((${field} at time zone '${validatedTimezone}'), 'HH24'))`;
  }

  // Default to UTC when no timezone is provided
  return `concat(extract(dow from (${field} at time zone 'UTC')), ':', to_char((${field} at time zone 'UTC'), 'HH24'))`;
}

export function getTimestampSQL(field: string) {
  // Security: Validate field name to prevent SQL injection
  if (!validateFieldName(field)) {
    throw new Error(`Invalid field name: ${field}`);
  }

  return `floor(extract(epoch from ${field}))`;
}

function getTimestampDiffSQL(field1: string, field2: string): string {
  // Security: Validate both field names to prevent SQL injection
  if (!validateFieldName(field1)) {
    throw new Error(`Invalid field name: ${field1}`);
  }
  if (!validateFieldName(field2)) {
    throw new Error(`Invalid field name: ${field2}`);
  }

  return `floor(extract(epoch from (${field2} - ${field1})))`;
}

function getSearchSQL(column: string, param: string = 'search'): string {
  // Security: Validate column name to prevent SQL injection
  if (!validateFieldName(column)) {
    throw new Error(`Invalid column name: ${column}`);
  }

  // Security: Validate parameter name (should be alphanumeric and underscore only)
  const paramRegex = /^[a-zA-Z_][a-zA-Z0-9_]*$/;
  if (!paramRegex.test(param)) {
    throw new Error(`Invalid parameter name: ${param}`);
  }

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
