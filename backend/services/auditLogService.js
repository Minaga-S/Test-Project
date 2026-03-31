// NOTE: Service layer: contains core business logic used by controllers.

const AuditLog = require('../models/AuditLog');
const logger = require('../utils/logger');

class AuditLogService {
    async record(entry) {
        try {
            await AuditLog.create(entry);
        } catch (error) {
            logger.error(`Audit log failure: ${error.message}`);
        }
    }
}

module.exports = new AuditLogService();

