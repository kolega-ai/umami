/**
 * Security Test Suite for Prisma SQL Injection Prevention
 * 
 * This test suite validates that the security fixes in prisma.ts
 * properly prevent SQL injection attacks while maintaining functionality.
 */

// Mock the required dependencies
const mockLog = jest.fn();
jest.mock('debug', () => () => mockLog);

// Mock constants
jest.mock('./constants', () => ({
  DEFAULT_PAGE_SIZE: 20,
  FILTER_COLUMNS: {},
  OPERATORS: {},
  SESSION_COLUMNS: [],
  UNIT_TYPES: ['year', 'month', 'hour', 'day', 'minute']
}));

// Mock other dependencies to isolate our security functions
jest.mock('@prisma/adapter-pg', () => ({
  PrismaPg: class {}
}));
jest.mock('@prisma/extension-read-replicas', () => ({
  readReplicas: () => {}
}));
jest.mock('@/generated/prisma/client', () => ({
  PrismaClient: class {}
}));
jest.mock('./params', () => ({
  filtersObjectToArray: () => []
}));
jest.mock('./types', () => ({}));

describe('Prisma SQL Injection Security Tests', () => {
  let getDateSQL, getDateWeeklySQL;

  beforeAll(() => {
    // Import the functions after mocking dependencies
    const prismaModule = require('./prisma');
    getDateSQL = prismaModule.default.getDateSQL;
    getDateWeeklySQL = prismaModule.default.getDateWeeklySQL;
  });

  beforeEach(() => {
    mockLog.mockClear();
  });

  describe('getDateSQL Security Tests', () => {
    describe('Valid inputs should work', () => {
      test('accepts valid field names', () => {
        const sql = getDateSQL('created_at', 'day');
        expect(sql).toContain('created_at');
        expect(sql).toContain('day');
        expect(sql).not.toContain("''; DROP TABLE"); // Should not contain injection
      });

      test('accepts qualified field names', () => {
        const sql = getDateSQL('website_event.created_at', 'hour');
        expect(sql).toContain('website_event.created_at');
        expect(sql).toContain('hour');
      });

      test('accepts valid timezone', () => {
        const sql = getDateSQL('created_at', 'day', 'UTC');
        expect(sql).toContain('created_at');
        expect(sql).toContain('day');
      });

      test('accepts numeric timezone offset', () => {
        const sql = getDateSQL('created_at', 'day', '+05:30');
        expect(sql).toContain('created_at');
        expect(sql).toContain('+05:30');
      });
    });

    describe('SQL injection prevention in field parameter', () => {
      test('rejects SQL injection in field name', () => {
        expect(() => {
          getDateSQL("created_at'; DROP TABLE users; --", 'day');
        }).toThrow('Invalid field name');
        expect(mockLog).toHaveBeenCalledWith(
          'Security: Invalid field name attempted:', 
          "created_at'; DROP TABLE users; --"
        );
      });

      test('rejects completely malicious field', () => {
        expect(() => {
          getDateSQL("1=1 UNION SELECT * FROM users", 'day');
        }).toThrow('Invalid field name');
      });

      test('rejects empty field', () => {
        expect(() => {
          getDateSQL('', 'day');
        }).toThrow('Field name is required');
      });

      test('rejects null field', () => {
        expect(() => {
          getDateSQL(null, 'day');
        }).toThrow('Field name is required');
      });
    });

    describe('SQL injection prevention in unit parameter', () => {
      test('rejects SQL injection in unit', () => {
        expect(() => {
          getDateSQL('created_at', "day'; DROP TABLE users; --");
        }).toThrow('Invalid date unit');
        expect(mockLog).toHaveBeenCalledWith(
          'Security: Invalid date unit attempted:', 
          "day'; drop table users; --"
        );
      });

      test('rejects invalid unit values', () => {
        expect(() => {
          getDateSQL('created_at', 'invalid_unit');
        }).toThrow('Invalid date unit');
      });

      test('rejects empty unit', () => {
        expect(() => {
          getDateSQL('created_at', '');
        }).toThrow('Date unit is required');
      });
    });

    describe('SQL injection prevention in timezone parameter', () => {
      test('rejects SQL injection in timezone', () => {
        expect(() => {
          getDateSQL('created_at', 'day', "UTC'; DROP TABLE users; --");
        }).toThrow('Invalid timezone');
        expect(mockLog).toHaveBeenCalledWith(
          'Security: Invalid timezone attempted:', 
          "UTC'; DROP TABLE users; --"
        );
      });

      test('rejects malformed timezone', () => {
        expect(() => {
          getDateSQL('created_at', 'day', 'Invalid/Timezone');
        }).toThrow('Invalid timezone');
      });

      test('allows undefined timezone', () => {
        const sql = getDateSQL('created_at', 'day', undefined);
        expect(sql).toContain('created_at');
        expect(sql).toContain('day');
      });

      test('allows null timezone', () => {
        const sql = getDateSQL('created_at', 'day', null);
        expect(sql).toContain('created_at');
        expect(sql).toContain('day');
      });
    });

    describe('String escaping defense-in-depth', () => {
      test('escapes quotes in timezone', () => {
        // This should be caught by validation, but test escaping as backup
        const testTimezone = "America/Test'Quote";
        // Validation should catch this, but if it somehow passed, escaping would double the quotes
        expect(() => {
          getDateSQL('created_at', 'day', testTimezone);
        }).toThrow('Invalid timezone'); // Should be caught by validation first
      });
    });
  });

  describe('getDateWeeklySQL Security Tests', () => {
    describe('Valid inputs should work', () => {
      test('accepts valid field names without timezone', () => {
        const sql = getDateWeeklySQL('created_at');
        expect(sql).toContain('created_at');
        expect(sql).toContain('extract(dow');
      });

      test('accepts valid field names with timezone', () => {
        const sql = getDateWeeklySQL('created_at', 'UTC');
        expect(sql).toContain('created_at');
        expect(sql).toContain('UTC');
      });
    });

    describe('SQL injection prevention', () => {
      test('rejects SQL injection in field name', () => {
        expect(() => {
          getDateWeeklySQL("created_at'; DROP TABLE users; --");
        }).toThrow('Invalid field name');
      });

      test('rejects SQL injection in timezone', () => {
        expect(() => {
          getDateWeeklySQL('created_at', "UTC'; DROP TABLE users; --");
        }).toThrow('Invalid timezone');
      });
    });
  });

  describe('Security logging', () => {
    test('logs security events for monitoring', () => {
      expect(() => {
        getDateSQL('invalid_field', 'day');
      }).toThrow();
      
      expect(mockLog).toHaveBeenCalledWith(
        'Security: Invalid field name attempted:',
        'invalid_field'
      );
    });

    test('logs attempted timezone injection', () => {
      expect(() => {
        getDateSQL('created_at', 'day', 'malicious_timezone');
      }).toThrow();
      
      expect(mockLog).toHaveBeenCalledWith(
        'Security: Invalid timezone attempted:',
        'malicious_timezone'
      );
    });
  });

  describe('Backward compatibility', () => {
    test('maintains same function signatures', () => {
      // Test that functions accept the same parameters as before
      expect(() => getDateSQL('created_at', 'day')).not.toThrow();
      expect(() => getDateSQL('created_at', 'day', 'UTC')).not.toThrow();
      expect(() => getDateWeeklySQL('created_at')).not.toThrow();
      expect(() => getDateWeeklySQL('created_at', 'UTC')).not.toThrow();
    });

    test('returns properly formatted SQL', () => {
      const sql = getDateSQL('created_at', 'day');
      expect(sql).toMatch(/to_char\(date_trunc\('day', created_at\), '.*'\)/);
    });

    test('handles timezone formatting correctly', () => {
      const sql = getDateSQL('created_at', 'day', 'UTC');
      expect(sql).toMatch(/to_char\(date_trunc\('day', created_at.*\), '.*'\)/);
    });
  });

  describe('Edge cases', () => {
    test('handles whitespace in parameters', () => {
      const sql = getDateSQL('  created_at  ', '  day  ', '  UTC  ');
      expect(sql).toContain('created_at');
      expect(sql).toContain('day');
    });

    test('handles case sensitivity in units', () => {
      const sql = getDateSQL('created_at', 'DAY');
      expect(sql).toContain('day'); // Should be normalized to lowercase
    });

    test('rejects non-string parameters', () => {
      expect(() => getDateSQL(123, 'day')).toThrow();
      expect(() => getDateSQL('created_at', 123)).toThrow();
      expect(() => getDateSQL('created_at', 'day', 123)).toThrow();
    });
  });
});

console.log('Security test suite completed. All functions should be protected against SQL injection.');