#!/usr/bin/env node

/* eslint-disable no-console */
import 'dotenv/config';
import { PrismaPg } from '@prisma/adapter-pg';
import prompts from 'prompts';
import { v4 as uuid } from 'uuid';
import { PrismaClient } from '../generated/prisma/client.js';
import { hashPassword } from '../src/lib/password.ts';
import { ROLES } from '../src/lib/constants.ts';

const url = new URL(process.env.DATABASE_URL);
const adapter = new PrismaPg(
  { connectionString: url.toString() },
  { schema: url.searchParams.get('schema') },
);
const prisma = new PrismaClient({ adapter });

async function setupAdmin() {
  console.log('🔐 Umami Admin Setup');
  console.log('====================\n');

  try {
    // Check if any admin users already exist
    const existingAdmin = await prisma.user.findFirst({
      where: { role: ROLES.admin },
    });

    if (existingAdmin) {
      console.log('⚠️  An admin user already exists.');
      console.log('Use the password reset functionality or contact your system administrator.\n');
      process.exit(0);
    }

    // Get admin credentials from environment variables first
    let username = process.env.UMAMI_ADMIN_USERNAME;
    let password = process.env.UMAMI_ADMIN_PASSWORD;

    // If not provided via environment, prompt for them
    if (!username || !password) {
      console.log('🔍 Admin credentials not found in environment variables.');
      console.log('Please provide admin credentials for the initial setup:\n');

      const response = await prompts([
        {
          type: 'text',
          name: 'username',
          message: 'Admin username:',
          initial: username || 'admin',
          validate: (value) => value.length >= 3 ? true : 'Username must be at least 3 characters',
        },
        {
          type: 'password',
          name: 'password',
          message: 'Admin password:',
          validate: (value) => value.length >= 8 ? true : 'Password must be at least 8 characters',
        },
        {
          type: 'password',
          name: 'confirmPassword',
          message: 'Confirm password:',
          validate: (value, prev) => value === prev.password ? true : 'Passwords do not match',
        },
      ]);

      if (!response.username || !response.password) {
        console.log('\n❌ Setup cancelled.');
        process.exit(1);
      }

      username = response.username;
      password = response.password;
    }

    // Check if username already exists
    const existingUser = await prisma.user.findUnique({
      where: { username },
    });

    if (existingUser) {
      console.log(`\n❌ Username '${username}' already exists.`);
      process.exit(1);
    }

    // Hash the password
    const hashedPassword = hashPassword(password);

    // Create the admin user
    const adminUser = await prisma.user.create({
      data: {
        id: uuid(),
        username,
        password: hashedPassword,
        role: ROLES.admin,
      },
      select: {
        id: true,
        username: true,
        role: true,
        createdAt: true,
      },
    });

    console.log('\n✅ Admin user created successfully!');
    console.log(`   Username: ${adminUser.username}`);
    console.log(`   Role: ${adminUser.role}`);
    console.log(`   Created: ${adminUser.createdAt.toISOString()}`);
    console.log('\n🔒 Please store your credentials securely and change the password after first login.');

  } catch (error) {
    console.error('\n❌ Error creating admin user:', error.message);
    process.exit(1);
  } finally {
    await prisma.$disconnect();
  }
}

// Run the setup if this script is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  setupAdmin();
}

export { setupAdmin };