// NOTE: Data model: defines how records are stored and validated in MongoDB.

const mongoose = require('mongoose');
const bcryptjs = require('bcryptjs');

const ROLE_PERMISSIONS = {
    Admin: ['asset:read', 'asset:write', 'incident:read', 'incident:write', 'user:manage', 'dashboard:read'],
    Staff: ['asset:read', 'asset:write', 'incident:read', 'incident:write', 'dashboard:read'],
};

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
        enum: ['Admin', 'Staff'],
        default: 'Staff',
    },
    roles: {
        type: [String],
        default: ['Staff'],
    },
    permissions: {
        type: [String],
        default: ROLE_PERMISSIONS.Staff,
    },
    department: {
        type: String,
        default: '',
        trim: true,
    },
    isActive: {
        type: Boolean,
        default: true,
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
    const normalizedRole = this.role || 'Staff';
    this.roles = [normalizedRole];
    this.permissions = ROLE_PERMISSIONS[normalizedRole] || ROLE_PERMISSIONS.Staff;
    next();
});

// Hash password before saving
UserSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();

    try {
        const salt = await bcryptjs.genSalt(10);
        this.password = await bcryptjs.hash(this.password, salt);
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
    return user;
};

module.exports = mongoose.model('User', UserSchema);

