#!/usr/bin/python
#
# An ansible module for manipulating projects using
# [Packet's API](https://www.packet.net/resources/docs/)
#
# Copyright (c) 2015 Niels Grewe
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

DOCUMENTATION = '''
---
module: packet_project
short_description: Create/delete a project in Packet
description:
    - Create or delete a project in Packet's bare metal cloud.
notes:
    - check_mode is supported.
version_added: "2.1"
author: "Niels Grewe, @ngrewe"
requirements:
    - Requires the packet-python library
options:
    name:
        description:
            - The name of the project to manipulate
        required: true
        default: null
    auth_token:
        description:
            - Your authentication token for API access
        required: true
        default: null
        aliases: [ 'api_token' ]
    state:
        description:
            - Determines whether the project should or should not exist
        default: 'present'
        choices: [ 'present', 'absent' ]

'''

EXAMPLES = '''
- packet_project:
    name: foo
    state: present
    auth_token: XYZ
'''

RETURN = '''
id:
    description: The UUID identifying the project
    returned: when the project exists
    type: string
    sample: "e22ee691-9c3e-4b71-a45c-07a3c3190f96"
name:
    description: The name of the project
    returned: when the project exists
    type: string
    sample: "foo"
created_at:
    description: Timestamp when the project was created
    returned: when the project exists
    type: string
    sample: "2016-06-01T12:00:00Z"
updated_at:
    description: Timestamp when the project was last changed
    returned: when the project exists
    type: string
    sample: "2016-06-01T12:00:00Z"
'''

# Begin common code applying to all modules
from ansible.module_utils.basic import AnsibleModule
try:
    import packet
    HAS_PACKET = True
except ImportError:
    HAS_PACKET = False


class PacketModule(AnsibleModule):

    PROJECT_PROPERTIES = (
        'id',
        'name',
        'created_at',
        'updated_at'
    )

    def __init__(self, *args, **kwargs):
        spec = kwargs.get('argument_spec')
        if spec is None:
            spec = dict()
        spec.update(auth_token=dict(required=True, aliases=['api_token'],
                                    no_log=True))
        super(PacketModule, self).__init__(*args, **kwargs)
        self._manager = None

    @property
    def manager(self):
        """The object responsible for all comms with Packet"""
        if self._manager is None:
            self._manager = packet.Manager(
                auth_token=self.params['auth_token']
            )
        return self._manager

    @staticmethod
    def is_packet_supported():
        return HAS_PACKET

# End common code applying to all modules


class Creation(object):

    def __init__(self, manager, name):
        self._manager = manager
        self._name = name

    def apply(self):
        return self._manager.create_project(self._name)


class Deletion(object):

    def __init__(self, project):
        self._project = project

    def apply(self):
        self._project.delete()


def project_as_result(obj):
        if obj is None:
            return dict()
        return dict((name, getattr(obj, name))
                    for name in dir(obj)
                    if name in PacketModule.PROJECT_PROPERTIES)


def main():
    module = PacketModule(
        argument_spec=dict(
            name=dict(required=True),
            state=dict(default='present', choices=['present', 'absent']),
        ),
        supports_check_mode=True
    )

    if not module.is_packet_supported():
        module.fail_json(msg="packet-python not installed")

    projects = module.manager.list_projects()
    match = [x for x in projects if x.name == module.params['name']]
    if not match:
        result = dict()
    else:
        result = project_as_result(match[0])
    changed = False
    action = None
    if (module.params['state'] == 'present' and not result):
        changed = True
        action = Creation(module.manager, module.params['name'])
    elif (module.params['state'] == 'absent' and result):
        changed = True
        action = Deletion(match[0])

    if module.check_mode or not changed:
        module.exit_json(changed=changed, **result)

    result = project_as_result(action.apply())
    module.exit_json(changed=True, **result)


if __name__ == '__main__':
    main()
