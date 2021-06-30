#!/usr/bin/python3

# Entity Resource.


class Resources:
    """
    Implements addResource to add the resources.
    """

    def __init__(self):
        # Initialize resources
        self.resources = {}

    def addResource(self, resource, parents=[]):
        """
        Add a resource or append resource.
        """
        self.resources.setdefault(resource, set())
        self.resources[resource].update(parents)
