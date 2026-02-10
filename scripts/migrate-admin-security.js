#!/usr/bin/env node

/* eslint-disable no-console */
import 'dotenv/config';
import { PrismaPg } from '@prisma/adapter-pg';
import { PrismaClient } from '../generated/prisma/client.js';
import { ROLES } from '../src/lib/constants.ts';

const url = new URL(process.env.DATABASE_URL);
const adapter = new PrismaPg(
  { connectionString: url.toString() },
  { schema: url.searchParams.get('schema') },
);
const prisma = new PrismaClient({ adapter });

// The known vulnerable admin user ID from the migration
const VULNERABLE_ADMIN_ID = '41e2b680-648e-4b09-bcd7-3e2b10c06264';
const VULNERABLE_ADMIN_USERNAME = 'admin';

async function migrateAdminSecurity() {
  console.log('🔒 Umami Security Migration');
  console.log('===========================\n');
  console.log('Checking for vulnerable default admin user...\n');

  try {
    // Check for the specific vulnerable admin user
    const vulnerableAdmin = await prisma.user.findFirst({
      where: {
        OR: [
          { id: VULNERABLE_ADMIN_ID },
          { 
            username: VULNERABLE_ADMIN_USERNAME,
            role: ROLES.admin,
            // Also check for the specific bcrypt hash if needed
          }
        ]
      },
    });

    if (!vulnerableAdmin) {
      console.log('✅ No vulnerable default admin user found.');
      console.log('Your installation appears to be secure.\n');
      return;
    }

    console.log('⚠️  SECURITY ALERT: Vulnerable default admin user detected!');
    console.log(`   User ID: ${vulnerableAdmin.id}`);
    console.log(`   Username: ${vulnerableAdmin.username}`);
    console.log(`   This user has known default credentials and poses a security risk.\n`);

    // Disable the vulnerable admin user
    const timestamp = new Date();
    const randomSuffix = Math.random().toString(36).substring(7);
    
    await prisma.user.update({
      where: { id: vulnerableAdmin.id },
      data: {
        username: `disabled_admin_${randomSuffix}`,
        password: 'DISABLED_' + timestamp.getTime(), // Invalid bcrypt hash
        updatedAt: timestamp,
      },
    });

    console.log('🔒 Vulnerable admin user has been disabled.');
    console.log('   - Username changed to prevent login attempts');
    console.log('   - Password invalidated');
    console.log('   - Account effectively disabled\n');

    // Check if there are other admin users
    const otherAdmins = await prisma.user.findMany({
      where: {
        role: ROLES.admin,
        id: { not: vulnerableAdmin.id },
        deletedAt: null,
      },
      select: {
        username: true,
        createdAt: true,
      },
    });

    if (otherAdmins.length > 0) {
      console.log('✅ Other admin users found:');
      otherAdmins.forEach(admin => {
        console.log(`   - ${admin.username} (created: ${admin.createdAt.toISOString().split('T')[0]})`);
      });
      console.log('\nYou can continue using these admin accounts.\n');
    } else {
      console.log('⚠️  No other admin users found.');
      console.log('You should create a new admin user immediately:');
      console.log('   npm run setup-admin\n');
    }

    console.log('🔐 IMPORTANT NEXT STEPS:');
    console.log('1. Create a new admin user with: npm run setup-admin');
    console.log('2. Review all user accounts for suspicious activity');
    console.log('3. Consider rotating any sensitive data that may have been accessed');
    console.log('4. Update to the latest version if not already done');
    console.log('5. Monitor logs for any unauthorized access attempts\n');

  } catch (error) {
    console.error('❌ Error during security migration:', error.message);
    process.exit(1);
  } finally {
    await prisma.$disconnect();
  }
}

// Run the migration if this script is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  migrateAdminSecurity();
}

export { migrateAdminSecurity };