// NOTE: Data model: defines how records are stored and validated in MongoDB.

const mongoose = require('mongoose');

const RiskAssessmentSchema = new mongoose.Schema({
	incidentId: {
		type: mongoose.Schema.Types.ObjectId,
		ref: 'Incident',
		required: false,
	},
	likelihood: {
		type: Number,
		min: 1,
		max: 4,
		required: true,
	},
	impact: {
		type: Number,
		min: 1,
		max: 4,
		required: true,
	},
	riskScore: {
		type: Number,
		required: true,
	},
	riskLevel: {
		type: String,
		enum: ['Low', 'Medium', 'High', 'Critical'],
		required: true,
	},
	recommendation: {
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
	updatedAt: {
		type: Date,
		default: Date.now,
	},
});

module.exports = mongoose.model('RiskAssessment', RiskAssessmentSchema);

