const mongoose = require('mongoose');

const ThreatKnowledgeBaseSchema = new mongoose.Schema({
	threatType: {
		type: String,
		required: true,
		unique: true,
	},
	threatCategory: {
		type: String,
		required: true,
	},
	affectedAssetTypes: [String],
	nistFunctions: [String],
	nistControls: [String],
	mitigationSteps: [String],
	createdAt: {
		type: Date,
		default: Date.now,
	},
	updatedAt: {
		type: Date,
		default: Date.now,
	},
});

module.exports = mongoose.model('ThreatKnowledgeBase', ThreatKnowledgeBaseSchema);
