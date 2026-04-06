/**
 * Reset local test database to the admin-only baseline.
 */

require('dotenv').config();

const mongoose = require('mongoose');
const { connectDatabase, closeDatabase } = require('../config/database');
const { seedDatabase } = require('./seedDatabase');

async function resetDatabase() {
    await connectDatabase();

    try {
        await mongoose.connection.db.dropDatabase();
        console.log('✓ Database cleared');

        await seedDatabase();
    } finally {
        await closeDatabase();
        await mongoose.disconnect();
    }
}

resetDatabase().catch((error) => {
    console.error('Reset failed:', error.message);
    process.exitCode = 1;
});