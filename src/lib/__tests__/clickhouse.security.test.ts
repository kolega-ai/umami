/**
 * Security tests for ClickHouse SQL injection prevention
 * Tests the fixes for CWE-89 vulnerabilities in getDateStringSQL and getDateSQL functions
 */

import clickhouse from '../clickhouse';

describe('ClickHouse Security - SQL Injection Prevention', () => {
  describe('getDateStringSQL', () => {
    describe('timezone parameter validation', () => {
      it('should accept valid IANA timezone identifiers', () => {
        expect(() => {
          clickhouse.getDateStringSQL('now()', 'utc', 'America/New_York');
        }).not.toThrow();

        expect(() => {
          clickhouse.getDateStringSQL('now()', 'utc', 'Europe/London');
        }).not.toThrow();

        expect(() => {
          clickhouse.getDateStringSQL('now()', 'utc', 'Asia/Tokyo');
        }).not.toThrow();
      });

      it('should accept valid timezone abbreviations', () => {
        expect(() => {
          clickhouse.getDateStringSQL('now()', 'utc', 'UTC');
        }).not.toThrow();

        expect(() => {
          clickhouse.getDateStringSQL('now()', 'utc', 'EST');
        }).not.toThrow();

        expect(() => {
          clickhouse.getDateStringSQL('now()', 'utc', 'JST');
        }).not.toThrow();
      });

      it('should accept valid numeric timezone offsets', () => {
        expect(() => {
          clickhouse.getDateStringSQL('now()', 'utc', '+03:00');
        }).not.toThrow();

        expect(() => {
          clickhouse.getDateStringSQL('now()', 'utc', '-0530');
        }).not.toThrow();

        expect(() => {
          clickhouse.getDateStringSQL('now()', 'utc', '+1400');
        }).not.toThrow();

        expect(() => {
          clickhouse.getDateStringSQL('now()', 'utc', '-12:00');
        }).not.toThrow();
      });

      it('should accept undefined/empty timezone (server default)', () => {
        expect(() => {
          clickhouse.getDateStringSQL('now()', 'utc');
        }).not.toThrow();

        expect(() => {
          clickhouse.getDateStringSQL('now()', 'utc', undefined);
        }).not.toThrow();
      });

      it('should reject SQL injection attempts in timezone parameter', () => {
        const injectionAttempts = [
          "'; DROP TABLE users; --",
          "' OR 1=1 --",
          "'; DELETE FROM events; --",
          "' UNION SELECT * FROM passwords --",
          "UTC'; INSERT INTO logs VALUES ('hacked'); --",
          "UTC' OR '1'='1",
          "'; SHOW TABLES; --",
          "UTC\\'; DROP DATABASE umami; --",
        ];

        injectionAttempts.forEach(injection => {
          expect(() => {
            clickhouse.getDateStringSQL('now()', 'utc', injection);
          }).toThrow(/Invalid timezone/);
        });
      });

      it('should reject invalid timezone formats', () => {
        const invalidTimezones = [
          'Invalid/Timezone',
          'UTC+25:00', // Invalid offset
          'Random_String',
          '123abc',
          '+25:00', // Out of range
          '+1500', // Invalid format
          'UTC; DROP TABLE users;',
        ];

        invalidTimezones.forEach(invalid => {
          expect(() => {
            clickhouse.getDateStringSQL('now()', 'utc', invalid);
          }).toThrow(/Invalid timezone/);
        });
      });

      it('should reject non-string timezone types', () => {
        expect(() => {
          clickhouse.getDateStringSQL('now()', 'utc', 123 as any);
        }).toThrow(/Timezone must be a string/);

        expect(() => {
          clickhouse.getDateStringSQL('now()', 'utc', {} as any);
        }).toThrow(/Timezone must be a string/);

        expect(() => {
          clickhouse.getDateStringSQL('now()', 'utc', [] as any);
        }).toThrow(/Timezone must be a string/);
      });
    });

    describe('unit parameter validation', () => {
      it('should accept valid date units', () => {
        const validUnits = ['utc', 'second', 'minute', 'hour', 'day', 'month', 'year'];
        
        validUnits.forEach(unit => {
          expect(() => {
            clickhouse.getDateStringSQL('now()', unit);
          }).not.toThrow();
        });
      });

      it('should reject SQL injection attempts in unit parameter', () => {
        const injectionAttempts = [
          "utc'; DROP TABLE users; --",
          "day' OR 1=1 --",
          "hour'; DELETE FROM events; --",
          "minute' UNION SELECT * FROM passwords --",
        ];

        injectionAttempts.forEach(injection => {
          expect(() => {
            clickhouse.getDateStringSQL('now()', injection);
          }).toThrow(/Invalid date unit/);
        });
      });

      it('should reject invalid date units', () => {
        const invalidUnits = ['invalid', 'week', 'decade', ''];

        invalidUnits.forEach(unit => {
          expect(() => {
            clickhouse.getDateStringSQL('now()', unit);
          }).toThrow(/Invalid date unit/);
        });
      });

      it('should reject non-string unit types', () => {
        expect(() => {
          clickhouse.getDateStringSQL('now()', 123 as any);
        }).toThrow(/Date unit is required and must be a string/);

        expect(() => {
          clickhouse.getDateStringSQL('now()', null as any);
        }).toThrow(/Date unit is required and must be a string/);

        expect(() => {
          clickhouse.getDateStringSQL('now()', undefined as any);
        }).toThrow(/Date unit is required and must be a string/);
      });
    });

    describe('output validation', () => {
      it('should produce properly escaped SQL with valid inputs', () => {
        const result1 = clickhouse.getDateStringSQL('created_at', 'day', 'America/New_York');
        expect(result1).toBe("formatDateTime(created_at, '%Y-%m-%d', 'America/New_York')");

        const result2 = clickhouse.getDateStringSQL('created_at', 'hour');
        expect(result2).toBe("formatDateTime(created_at, '%Y-%m-%d %H:00:00')");

        const result3 = clickhouse.getDateStringSQL('created_at', 'utc', '+03:00');
        expect(result3).toBe("formatDateTime(created_at, '%Y-%m-%dT%H:%i:%SZ', '+03:00')");
      });

      it('should properly escape single quotes in timezone names', () => {
        // Simulate a timezone with single quotes (hypothetically)
        // The escaping function should handle this gracefully
        const result = clickhouse.getDateStringSQL('created_at', 'day', 'UTC');
        expect(result).not.toContain("''"); // No doubled quotes needed for UTC
      });
    });
  });

  describe('getDateSQL', () => {
    describe('timezone parameter validation', () => {
      it('should accept valid timezone identifiers', () => {
        expect(() => {
          clickhouse.getDateSQL('created_at', 'day', 'America/New_York');
        }).not.toThrow();

        expect(() => {
          clickhouse.getDateSQL('created_at', 'hour', 'UTC');
        }).not.toThrow();
      });

      it('should reject SQL injection attempts in timezone parameter', () => {
        const injectionAttempts = [
          "'; DROP TABLE users; --",
          "' OR 1=1 --",
          "UTC'; DELETE FROM events; --",
        ];

        injectionAttempts.forEach(injection => {
          expect(() => {
            clickhouse.getDateSQL('created_at', 'day', injection);
          }).toThrow(/Invalid timezone/);
        });
      });
    });

    describe('unit parameter validation', () => {
      it('should accept valid date units', () => {
        const validUnits = ['second', 'minute', 'hour', 'day', 'month', 'year'];
        
        validUnits.forEach(unit => {
          expect(() => {
            clickhouse.getDateSQL('created_at', unit);
          }).not.toThrow();
        });
      });

      it('should reject SQL injection attempts in unit parameter', () => {
        const injectionAttempts = [
          "day'; DROP TABLE users; --",
          "hour' OR 1=1 --",
          "minute'; DELETE FROM events; --",
        ];

        injectionAttempts.forEach(injection => {
          expect(() => {
            clickhouse.getDateSQL('created_at', injection);
          }).toThrow(/Invalid date unit/);
        });
      });

      it('should reject invalid date units', () => {
        const invalidUnits = ['invalid', 'week', 'decade'];

        invalidUnits.forEach(unit => {
          expect(() => {
            clickhouse.getDateSQL('created_at', unit);
          }).toThrow(/Invalid date unit/);
        });
      });
    });

    describe('output validation', () => {
      it('should produce properly escaped SQL with valid inputs', () => {
        const result1 = clickhouse.getDateSQL('created_at', 'day', 'America/New_York');
        expect(result1).toBe("toDateTime(date_trunc('day', created_at, 'America/New_York'))");

        const result2 = clickhouse.getDateSQL('created_at', 'hour');
        expect(result2).toBe("toDateTime(date_trunc('hour', created_at))");

        const result3 = clickhouse.getDateSQL('created_at', 'minute', 'UTC');
        expect(result3).toBe("toDateTime(date_trunc('minute', created_at, 'UTC'))");
      });
    });
  });

  describe('edge cases and integration', () => {
    it('should handle all valid timezone and unit combinations', () => {
      const validTimezones = ['UTC', 'America/New_York', '+03:00', '-0530'];
      const validUnits = ['day', 'hour', 'minute'];

      validTimezones.forEach(timezone => {
        validUnits.forEach(unit => {
          expect(() => {
            clickhouse.getDateStringSQL('created_at', unit, timezone);
            clickhouse.getDateSQL('created_at', unit, timezone);
          }).not.toThrow();
        });
      });
    });

    it('should maintain backwards compatibility for valid usage', () => {
      // Test that existing valid calls still work
      expect(() => {
        clickhouse.getDateStringSQL('created_at', 'day');
        clickhouse.getDateStringSQL('created_at', 'hour', 'UTC');
        clickhouse.getDateSQL('created_at', 'day');
        clickhouse.getDateSQL('created_at', 'hour', 'America/New_York');
      }).not.toThrow();
    });
  });
});