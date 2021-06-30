# AccessControlSystem

Implementation of a role based auth system.
System should be able to assign a role to user and remove a user from the role.
Entities are USER, ACTION TYPE, RESOURCE, ROLES
ACTION TYPE defines the access level(Ex: READ, WRITE, DELETE)
Access to resources for users are controlled strictly by the role.
One user can have multiple roles.
Given a user, action type and resource system should be able to tell whether user has access or not.

Assumptions:
Only one system resource 'file'
Roles:
1. normal-user having READ access
2. admin having read and write access
3. super-admin having read, write and delete access
In-memory database for storing users, roles, resources, allowed and denied.
How to run:
$ python AccessControl.py
