import prisma from '../prisma';

describe('Prisma Security Tests', () => {
  describe('getDateSQL Security', () => {
    it('should handle valid timezones', () => {
      expect(() => prisma.getDateSQL('created_at', 'day', 'America/New_York')).not.toThrow();
      expect(() => prisma.getDateSQL('created_at', 'day', 'UTC')).not.toThrow();
      expect(() => prisma.getDateSQL('created_at', 'day', '+05:30')).not.toThrow();
      expect(() => prisma.getDateSQL('created_at', 'day', '-08:00')).not.toThrow();
    });

    it('should reject SQL injection attempts in timezone', () => {
      expect(() => 
        prisma.getDateSQL('created_at', 'day', "UTC'; DROP TABLE users; --")
      ).toThrow('Invalid timezone provided');
      
      expect(() => 
        prisma.getDateSQL('created_at', 'day', "UTC' OR '1'='1")
      ).toThrow('Invalid timezone provided');
      
      expect(() => 
        prisma.getDateSQL('created_at', 'day', 'UTC" UNION SELECT * FROM users')
      ).toThrow('Invalid timezone provided');
    });

    it('should reject SQL injection attempts in field name', () => {
      expect(() => 
        prisma.getDateSQL("created_at; DELETE FROM users", 'day', 'UTC')
      ).toThrow('Invalid field name');
      
      expect(() => 
        prisma.getDateSQL("created_at' OR 1=1", 'day', 'UTC')
      ).toThrow('Invalid field name');
    });

    it('should reject SQL injection attempts in date unit', () => {
      expect(() => 
        prisma.getDateSQL('created_at', "day'; DROP TABLE users; --", 'UTC')
      ).toThrow('Invalid date unit');
      
      expect(() => 
        prisma.getDateSQL('created_at', "day' OR 1=1", 'UTC')
      ).toThrow('Invalid date unit');
    });

    it('should handle invalid timezones gracefully', () => {
      // Invalid timezone should default to UTC behavior
      const result = prisma.getDateSQL('created_at', 'day', 'InvalidTimezone');
      expect(result).toContain('to_char(date_trunc(');
      expect(result).toContain('YYYY-MM-DD"T"HH24:00:00"Z"'); // UTC format
    });

    it('should generate correct SQL for valid inputs', () => {
      const result1 = prisma.getDateSQL('created_at', 'day', 'America/New_York');
      expect(result1).toBe("to_char(date_trunc('day', created_at at time zone 'America/New_York'), 'YYYY-MM-DD HH24:00:00')");
      
      const result2 = prisma.getDateSQL('created_at', 'hour', 'UTC');
      expect(result2).toBe("to_char(date_trunc('hour', created_at), 'YYYY-MM-DD\"T\"HH24:00:00\"Z\"')");
    });
  });

  describe('getDateWeeklySQL Security', () => {
    it('should handle valid inputs', () => {
      expect(() => prisma.getDateWeeklySQL('created_at', 'UTC')).not.toThrow();
      expect(() => prisma.getDateWeeklySQL('created_at', 'America/New_York')).not.toThrow();
    });

    it('should reject SQL injection attempts', () => {
      expect(() => 
        prisma.getDateWeeklySQL('created_at', "UTC'; DROP TABLE users; --")
      ).toThrow('Invalid timezone provided');
      
      expect(() => 
        prisma.getDateWeeklySQL("created_at; DELETE FROM users", 'UTC')
      ).toThrow('Invalid field name');
    });

    it('should default to UTC for invalid timezone', () => {
      const result = prisma.getDateWeeklySQL('created_at', 'InvalidTimezone');
      expect(result).toContain("at time zone 'UTC'");
    });

    it('should generate correct SQL for valid inputs', () => {
      const result = prisma.getDateWeeklySQL('created_at', 'America/New_York');
      expect(result).toBe("concat(extract(dow from (created_at at time zone 'America/New_York')), ':', to_char((created_at at time zone 'America/New_York'), 'HH24'))");
    });
  });

  describe('Other SQL Functions Security', () => {
    it('should validate field names in getTimestampSQL', () => {
      expect(() => prisma.getTimestampSQL('created_at')).not.toThrow();
      expect(() => prisma.getTimestampSQL("created_at; DROP TABLE users")).toThrow('Invalid field name');
    });

    it('should validate field names in getDayDiffQuery', () => {
      expect(() => prisma.getDayDiffQuery('start_date', 'end_date')).not.toThrow();
      expect(() => prisma.getDayDiffQuery("start_date; DROP TABLE users", 'end_date')).toThrow('Invalid field name');
      expect(() => prisma.getDayDiffQuery('start_date', "end_date' OR 1=1")).toThrow('Invalid field name');
    });

    it('should validate inputs in getCastColumnQuery', () => {
      expect(() => prisma.getCastColumnQuery('value', 'integer')).not.toThrow();
      expect(() => prisma.getCastColumnQuery('value', 'varchar')).not.toThrow();
      expect(() => prisma.getCastColumnQuery("value; DROP TABLE users", 'integer')).toThrow('Invalid field name');
      expect(() => prisma.getCastColumnQuery('value', 'invalid_type')).toThrow('Invalid PostgreSQL data type');
    });

    it('should validate inputs in getAddIntervalQuery', () => {
      expect(() => prisma.getAddIntervalQuery('created_at', '1 day')).not.toThrow();
      expect(() => prisma.getAddIntervalQuery('created_at', '30 minutes')).not.toThrow();
      expect(() => prisma.getAddIntervalQuery("created_at; DROP TABLE users", '1 day')).toThrow('Invalid field name');
      expect(() => prisma.getAddIntervalQuery('created_at', "1 day'; DROP TABLE users; --")).toThrow('Invalid interval format');
    });

    it('should validate inputs in getSearchSQL', () => {
      expect(() => prisma.getSearchSQL('name', 'search')).not.toThrow();
      expect(() => prisma.getSearchSQL("name; DROP TABLE users", 'search')).toThrow('Invalid column name');
      expect(() => prisma.getSearchSQL('name', "search'; DROP TABLE users; --")).toThrow('Invalid parameter name');
    });
  });

  describe('Edge Cases', () => {
    it('should handle null and undefined inputs gracefully', () => {
      expect(() => prisma.getDateSQL('created_at', 'day', undefined)).not.toThrow();
      expect(() => prisma.getDateSQL('created_at', 'day', null as any)).not.toThrow();
      expect(() => prisma.getDateWeeklySQL('created_at', undefined)).not.toThrow();
      expect(() => prisma.getDateWeeklySQL('created_at', null as any)).not.toThrow();
    });

    it('should handle empty strings', () => {
      expect(() => prisma.getDateSQL('created_at', 'day', '')).not.toThrow();
      expect(() => prisma.getDateWeeklySQL('created_at', '')).not.toThrow();
    });

    it('should handle table.column format in field names', () => {
      expect(() => prisma.getDateSQL('website_event.created_at', 'day', 'UTC')).not.toThrow();
      expect(() => prisma.getTimestampSQL('session.created_at')).not.toThrow();
    });
  });
});