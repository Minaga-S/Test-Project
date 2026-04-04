const User = require('./User');

describe('User model', () => {
    it('should default new users to the User role', async () => {
        const user = new User({
            email: 'guest@example.com',
            password: 'Password123!',
            fullName: 'Guest User',
        });

        await user.validate();

        expect(user.toObject()).toMatchObject({
            role: 'User',
            roles: ['User'],
        });
    });

    it('should keep admin permissions for admin users', async () => {
        const user = new User({
            email: 'admin@example.com',
            password: 'Password123!',
            fullName: 'Admin User',
            role: 'Admin',
        });

        await user.validate();

        expect(user.toObject()).toMatchObject({
            role: 'Admin',
            permissions: ['asset:read', 'asset:write', 'incident:read', 'incident:write', 'user:manage', 'dashboard:read'],
        });
    });

    it('should reject a department outside the allowed list', async () => {
        const user = new User({
            email: 'invalid-department@example.com',
            password: 'Password123!',
            fullName: 'Invalid Department',
            department: 'Unknown Department',
        });

        await expect(user.validate()).rejects.toThrow();
    });
});
