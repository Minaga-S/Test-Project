/**
 * Database Seed Script
 * Creates test users on first run
 */

const mongoose = require('mongoose');
const bcryptjs = require('bcryptjs');
const User = require('../models/User');
const ThreatKnowledgeBase = require('../models/ThreatKnowledgeBase');
const { THREAT_KNOWLEDGE_BASE } = require('../utils/constants');

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

        // Upsert threat knowledge base entries.
        for (const entry of THREAT_KNOWLEDGE_BASE) {
            await ThreatKnowledgeBase.findOneAndUpdate(
                { threatType: entry.threatType },
                {
                    ...entry,
                    updatedAt: new Date(),
                },
                { upsert: true, new: true, setDefaultsOnInsert: true }
            );
        }

        console.log('✓ Threat knowledge base seed completed');
        console.log('✓ Database seeded successfully');
    } catch (error) {
        console.error('✗ Seed error:', error.message);
        // Don't throw - let server continue even if seed fails
    }
}

module.exports = { seedDatabase };
