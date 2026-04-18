// NOTE: Data model: defines how records are stored and validated in MongoDB.

const mongoose = require('mongoose');
const bcryptjs = require('bcryptjs');
const { DEPARTMENTS } = require('../utils/constants');

const USER_PERMISSIONS = ['asset:read', 'asset:write', 'incident:read', 'incident:write', 'dashboard:read'];

const SecurityQuestionSchema = new mongoose.Schema({
    question: {
        type: String,
        required: true,
        trim: true,
    },
    answerHash: {
        type: String,
        required: true,
    },
}, { _id: false });

const UserSchema = new mongoose.Schema({
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true,
    },
    password: {
        type: String,
        required: true,
        minlength: 8,
    },
    fullName: {
        type: String,
        required: true,
        trim: true,
    },
    role: {
        type: String,
        enum: ['User'],
        default: 'User',
    },
    roles: {
        type: [String],
        default: ['User'],
    },
    permissions: {
        type: [String],
        default: USER_PERMISSIONS,
    },
    department: {
        type: String,
        enum: [...DEPARTMENTS, ''],
        default: '',
        trim: true,
    },
    isActive: {
        type: Boolean,
        default: true,
    },
    twoFactorEnabled: {
        type: Boolean,
        default: false,
    },
    twoFactorSecret: {
        type: String,
        default: '',
    },
    twoFactorTempSecret: {
        type: String,
        default: '',
    },
    recoveryCodeHashes: {
        type: [String],
        default: [],
    },
    sessionVersion: {
        type: Number,
        default: 0,
    },
    refreshTokenVersion: {
        type: Number,
        default: 0,
    },
    securityQuestions: {
        type: [SecurityQuestionSchema],
        default: [],
    },
    loginFailedAttempts: {
        type: Number,
        default: 0,
    },
    loginLockUntil: {
        type: Date,
        default: null,
    },
    lastLoginAt: {
        type: Date,
        default: null,
    },
    lastLoginIp: {
        type: String,
        default: '',
        trim: true,
    },
    lastFailedLoginAt: {
        type: Date,
        default: null,
    },
    lastFailedLoginIp: {
        type: String,
        default: '',
        trim: true,
    },
    passwordResetFailedAttempts: {
        type: Number,
        default: 0,
    },
    passwordResetLockUntil: {
        type: Date,
        default: null,
    },
    passwordChangedAt: {
        type: Date,
        default: Date.now,
    },
    hasLoggedInOnce: {
        type: Boolean,
        default: false,
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

UserSchema.index({ email: 1 }, { unique: true });

UserSchema.pre('validate', function(next) {
    this.role = 'User';
    this.roles = ['User'];
    this.permissions = USER_PERMISSIONS;
    next();
});

// Hash password before saving
UserSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();

    try {
        const salt = await bcryptjs.genSalt(10);
        this.password = await bcryptjs.hash(this.password, salt);
        this.passwordChangedAt = new Date();
        next();
    } catch (error) {
        next(error);
    }
});

// Compare password method
UserSchema.methods.comparePassword = async function(password) {
    return bcryptjs.compare(password, this.password);
};

// Remove password from response
UserSchema.methods.toJSON = function() {
    const user = this.toObject();
    delete user.password;
    delete user.twoFactorSecret;
    delete user.twoFactorTempSecret;
    delete user.recoveryCodeHashes;
    delete user.sessionVersion;
    delete user.refreshTokenVersion;
    delete user.loginFailedAttempts;
    delete user.loginLockUntil;
    delete user.lastLoginAt;
    delete user.lastLoginIp;
    delete user.lastFailedLoginAt;
    delete user.lastFailedLoginIp;
    delete user.passwordResetFailedAttempts;
    delete user.passwordResetLockUntil;
    user.securityQuestions = Array.isArray(user.securityQuestions)
        ? user.securityQuestions.map((item) => ({ question: item.question }))
        : [];
    return user;
};

module.exports = mongoose.model('User', UserSchema);
