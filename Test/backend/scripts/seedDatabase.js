/**
 * Database Seed Script
 * Creates test users on first run
 */

const mongoose = require('mongoose');
const bcryptjs = require('bcryptjs');
const User = require('../models/User');

const testUsers = [
    {
        email: 'admin@test.com',
        password: 'Admin123456',
        fullName: 'Admin User',
        role: 'Admin',
    },
    {
        email: 'staff@test.com',
        password: 'Staff123456',
        fullName: 'Staff User',
        role: 'Staff',
    },
];

async function seedDatabase() {
    try {
        // Check if users already exist
        const existingUsers = await User.countDocuments();
        
        if (existingUsers > 0) {
            console.log('✓ Database already seeded, skipping');
            return;
        }

        // Create test users
        for (const userData of testUsers) {
            const user = new User(userData);
            await user.save();
            console.log(`✓ Created test user: ${userData.email}`);
        }

        console.log('✓ Database seeded successfully');
    } catch (error) {
        console.error('✗ Seed error:', error.message);
        // Don't throw - let server continue even if seed fails
    }
}

module.exports = { seedDatabase };
