#!/usr/bin/python3

# Driver code to run Simple Role Based Access Control.

from rbac.acl import Registry

# constants
# Access levels for different roles.
ACCESS_LEVELS = {
    'super-admin': ['READ', 'WRITE', 'DELETE'],
    'admin': ['READ', 'WRITE'],
    'normal-user': ['READ']
}

# Resources, Assumption: 'file' is a resource
RESOURCES = ['file']


class RoleBasedAccessControl:
    """
    Implements Role Based Access Control.
    System should be able to assign a role to user and remove
    a user from the role.
    """

    def __init__(self):
        #  Create a Access Control List
        self.acl = Registry()

    def add_role(self):
        """Adds roles available in ACCESS_LEVELS.
        """
        # Assumption: admin user having access level(READ and WRITE)
        # Syntax: acl.addRole(role, [access-levels])
        for role, access_levels in ACCESS_LEVELS.items():
            self.acl.addRole(role, access_levels)

    def add_resource(self):
        """Adds Resources available in RESOURCES.
        """
        # Assumption: 'file' is a resource
        # Syntax: acl.addResource(resource-name)
        for resource in RESOURCES:
            self.acl.addResource(resource)

    def allow_rule(self):
        """Implements allow rules.
        """
        for role, access_levels in ACCESS_LEVELS.items():
            for acl in access_levels:
                # Add allow Rules
                # Syntax: acl.allow(role, access-level, [Resources])
                self.acl.allow(role, acl, RESOURCES)

    def deny_rule(self):
        """Implements Deny rules.
        """
        for role, access_levels in ACCESS_LEVELS.items():
            # take all access levels from super-admin role
            for acl in ACCESS_LEVELS['super-admin']:
                if acl not in access_levels:
                    # Add deny Rules
                    # Syntax: acl.deny(role, access-level, [Resources])
                    self.acl.deny(role, acl, RESOURCES)

    def add_users(self):
        """Add users with roles.
        """
        # Syntax: acl.addUser(user, [roles])
        self.acl.addUser('User-1', ['normal-user', 'admin'])
        self.acl.addUser('user-1', ['super-admin'])

    def perform_operations(self):
        """
        Given a user, action type and resource system should be able
        to tell whether user has access or not.
        """

        # Before deleting role
        self.acl.isAllowed('User-1', 'READ', 'file')
        self.acl.isAllowed('User-1', 'WRITE', 'file')

        # Delete role
        self.acl.deleteRole('User-1', 'admin')
		
		# After deleting role
        self.acl.isAllowed('User-1', 'READ', 'file')
        self.acl.isAllowed('User-1', 'WRITE', 'file')


if __name__ == "__main__":
    rbac = RoleBasedAccessControl()
    rbac.add_role()
    rbac.add_resource()
    rbac.allow_rule()
    rbac.deny_rule()
    rbac.add_users()
    rbac.perform_operations()
