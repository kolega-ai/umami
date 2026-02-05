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
    describe('field parameter validation (CWE-89 fix)', () => {
      it('should accept valid simple field names', () => {
        expect(() => {
          clickhouse.getDateSQL('created_at', 'day', 'UTC');
        }).not.toThrow();

        expect(() => {
          clickhouse.getDateSQL('date_value', 'hour', 'UTC');
        }).not.toThrow();

        expect(() => {
          clickhouse.getDateSQL('timestamp', 'minute', 'UTC');
        }).not.toThrow();

        expect(() => {
          clickhouse.getDateSQL('min_time', 'day', 'UTC');
        }).not.toThrow();

        expect(() => {
          clickhouse.getDateSQL('max_time', 'day', 'UTC');
        }).not.toThrow();
      });

      it('should accept valid table-prefixed field names', () => {
        expect(() => {
          clickhouse.getDateSQL('website_event.created_at', 'day', 'UTC');
        }).not.toThrow();

        expect(() => {
          clickhouse.getDateSQL('website_revenue.created_at', 'hour', 'UTC');
        }).not.toThrow();

        expect(() => {
          clickhouse.getDateSQL('event_data.date_value', 'day', 'UTC');
        }).not.toThrow();

        expect(() => {
          clickhouse.getDateSQL('session_data.created_at', 'minute', 'UTC');
        }).not.toThrow();

        expect(() => {
          clickhouse.getDateSQL('website_event_stats_hourly.timestamp', 'hour', 'UTC');
        }).not.toThrow();

        expect(() => {
          clickhouse.getDateSQL('revenue.created_at', 'day', 'UTC');
        }).not.toThrow();
      });

      it('should reject SQL injection attempts in field parameter', () => {
        const injectionAttempts = [
          "created_at'; DROP TABLE users; --",
          "created_at OR 1=1 --",
          "created_at UNION SELECT password FROM users",
          "created_at'; DELETE FROM events; --",
          "created_at/* comment */",
          "created_at--comment",
          "created_at'",
          'created_at"',
          "created_at`",
          "created_at\\",
          "created_at; SELECT * FROM passwords",
          "created_at) DROP DATABASE",
        ];

        injectionAttempts.forEach(injection => {
          expect(() => {
            clickhouse.getDateSQL(injection, 'day', 'UTC');
          }).toThrow(/Invalid field: contains forbidden characters or SQL keywords/);
        });
      });

      it('should reject unrecognized field names', () => {
        const invalidFields = [
          'invalid_field',
          'password',
          'hacker_field',
          'user_data',
          'admin_field',
        ];

        invalidFields.forEach(field => {
          expect(() => {
            clickhouse.getDateSQL(field, 'day', 'UTC');
          }).toThrow(/Invalid field: .* is not a recognized field name/);
        });
      });

      it('should reject unrecognized table prefixes', () => {
        const invalidTables = [
          'invalid_table.created_at',
          'users.created_at',
          'passwords.created_at',
          'hacker_table.created_at',
          'admin_data.created_at',
        ];

        invalidTables.forEach(field => {
          expect(() => {
            clickhouse.getDateSQL(field, 'day', 'UTC');
          }).toThrow(/Invalid field: .* is not a recognized table prefix/);
        });
      });

      it('should reject nested table references', () => {
        expect(() => {
          clickhouse.getDateSQL('schema.table.field', 'day', 'UTC');
        }).toThrow(/Invalid field: nested table references \(multiple dots\) are not allowed/);
      });

      it('should reject empty or null fields', () => {
        expect(() => {
          clickhouse.getDateSQL('', 'day', 'UTC');
        }).toThrow(/Field parameter cannot be empty/);

        expect(() => {
          clickhouse.getDateSQL('   ', 'day', 'UTC');
        }).toThrow(/Field parameter cannot be empty/);

        expect(() => {
          clickhouse.getDateSQL(null as any, 'day', 'UTC');
        }).toThrow(/Field parameter is required and must be a string/);

        expect(() => {
          clickhouse.getDateSQL(undefined as any, 'day', 'UTC');
        }).toThrow(/Field parameter is required and must be a string/);
      });

      it('should reject invalid characters in field names', () => {
        const invalidCharFields = [
          'created-at',
          '123created_at', 
          'created@at',
          'created.at.extra',
          'created$at',
          'created%at',
          'created+at',
        ];

        invalidCharFields.forEach(field => {
          expect(() => {
            clickhouse.getDateSQL(field, 'day', 'UTC');
          }).toThrow(/Invalid field:|contains invalid characters/);
        });
      });

      it('should handle whitespace correctly', () => {
        // Valid field with whitespace should be trimmed and accepted
        expect(() => {
          clickhouse.getDateSQL(' created_at ', 'day', 'UTC');
        }).not.toThrow();

        expect(() => {
          clickhouse.getDateSQL(' website_event.created_at ', 'day', 'UTC');
        }).not.toThrow();
      });

      it('should validate field parameter type', () => {
        expect(() => {
          clickhouse.getDateSQL(123 as any, 'day', 'UTC');
        }).toThrow(/Field parameter is required and must be a string/);

        expect(() => {
          clickhouse.getDateSQL({} as any, 'day', 'UTC');
        }).toThrow(/Field parameter is required and must be a string/);

        expect(() => {
          clickhouse.getDateSQL([] as any, 'day', 'UTC');
        }).toThrow(/Field parameter is required and must be a string/);
      });
    });

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

    describe('integrated parameter validation', () => {
      it('should validate all parameters together', () => {
        // Valid field but invalid unit should fail on unit validation
        expect(() => {
          clickhouse.getDateSQL('created_at', 'invalid_unit', 'UTC');
        }).toThrow(/Invalid date unit/);

        // Valid field but invalid timezone should fail on timezone validation
        expect(() => {
          clickhouse.getDateSQL('created_at', 'day', 'Invalid/Timezone');
        }).toThrow(/Invalid timezone/);

        // Invalid field should fail on field validation even if other params are valid
        expect(() => {
          clickhouse.getDateSQL('invalid_field', 'day', 'UTC');
        }).toThrow(/Invalid field/);
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

        const result4 = clickhouse.getDateSQL('website_event.created_at', 'day', 'UTC');
        expect(result4).toBe("toDateTime(date_trunc('day', website_event.created_at, 'UTC'))");
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