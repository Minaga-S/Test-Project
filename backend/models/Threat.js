const mongoose = require('mongoose');

const ThreatSchema = new mongoose.Schema({
	threatType: {
		type: String,
		required: true,
	},
	threatCategory: {
		type: String,
		default: 'Other',
	},
	affectedAsset: {
		type: String,
		default: 'General',
	},
	confidence: {
		type: Number,
		min: 0,
		max: 100,
		default: 0,
	},
	likelihood: {
		type: Number,
		min: 1,
		max: 4,
		default: 2,
	},
	impact: {
		type: Number,
		min: 1,
		max: 4,
		default: 2,
	},
	mitigationSteps: [String],
	nistFunctions: [String],
	nistControls: [String],
	sourceDescription: {
		type: String,
		default: '',
	},
	userId: {
		type: mongoose.Schema.Types.ObjectId,
		ref: 'User',
		required: true,
	},
	createdAt: {
		type: Date,
		default: Date.now,
	},
});

module.exports = mongoose.model('Threat', ThreatSchema);
