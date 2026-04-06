/**
 * Database Seed Script
 * Creates test users on first run
 */
// NOTE: Script utility: one-off or startup helper tasks for local/dev operations.

const mongoose = require('mongoose');
const bcryptjs = require('bcryptjs');
const User = require('../models/User');

const testUsers = [
    {
        email: 'admin@test.com',
        password: 'Admin123456',
        fullName: 'Admin User',
        role: 'Admin',
        department: 'Management',
    },
];

async function seedDatabase() {
    try {
        // Seed users if database is empty.
        const existingUsers = await User.countDocuments();
        if (existingUsers === 0) {
            for (const userData of testUsers) {
                const user = new User(userData);
                await user.save();
                console.log(`✓ Created test user: ${userData.email}`);
            }
            console.log('✓ User seed completed');
        } else {
            console.log('✓ Users already seeded, skipping user seed');
        }

        // NOTE: Threat data is now sourced from NIST threat intelligence service
        // and live CVE analysis. No local seed data is required for threat types.
        // See: backend/services/nistThreatIntelService.js
        console.log('✓ Threat data: Using NIST intelligence service');
        console.log('✓ Database seeded successfully');
    } catch (error) {
        console.error('✗ Seed error:', error.message);
        // Don't throw - let server continue even if seed fails
    }
}

module.exports = { seedDatabase };
