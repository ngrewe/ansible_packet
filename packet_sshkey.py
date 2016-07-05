#!/usr/bin/python
#
# An ansible module for manipulating ssh keys using
# [Packet's API](https://www.packet.net/resources/docs/)
#
# Copyright (c) 2016 Niels Grewe
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
#
# At your discretion, you may also use this module under the terms of the MIT
# license.

DOCUMENTATION = '''
---
module: packet_sshkey
short_description: Create/delete a SSH key in Packet
description:
    - Create or delete a SSH key for the current user in Packet
notes:
    - check_mode is supported.
version_added: "2.2"
author: "Niels Grewe, @ngrewe"
requirements:
    - Requires the packet-python library
    - If sshpubkeys is installed, it will be used to validate the keys prior
      to sending them to the other end.
options:
    label:
        description:
            - The label of the key to manipulate
        required: true
        default: null
        aliases: [ 'name' ]
    ssh_pub_key:
        description:
            - The public SSH key you want to add/remove for the user
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
            - Determines whether the key should be present or removed
        default: 'present'
        choices: [ 'present', 'absent' ]
'''

EXAMPLES = '''
- packet_sshkey:
    label: my_key
    ssh_pub_key: 'ssh-rsa DEADBEEF...'
    state: present
    auth_token: XYZ
'''

RETURN = '''
id:
    description: The UUID identifying the ssh key
    returned: when the key exists
    type: string
    sample: "e22ee691-9c3e-4b71-a45c-07a3c3190f96"
label:
    description: The label assigned to the key
    returned: when the key exists
    type: string
    sample: "foo"
created_at:
    description: Timestamp when the key was created
    returned: when the key exists
    type: string
    sample: "2016-06-01T12:00:00Z"
updated_at:
    description: Timestamp when the key was last changed
    returned: when the key exists
    type: string
    sample: "2016-06-01T12:00:00Z"
fingerprint:
    description: The fingerprint of the key
    returned: when the key exists
    type: string
    sample: "74:f6:47:91:78:a2:c7:1e:ef:73:c9:b3:17:ab:ec:c9"
'''

# Begin common code applying to all modules
from ansible.module_utils.basic import AnsibleModule
from operator import attrgetter
try:
    import packet
    HAS_PACKET = True
except ImportError:
    HAS_PACKET = False


class PacketProperties(object):
    if HAS_PACKET:
        mapping = {
            packet.Project.Project: (
                'id',
                'name',
                'created_at',
                'updated_at'),
            packet.SSHKey.SSHKey: (
                'id',
                'label',
                'created_at',
                'updated_at',
                'key',
                'fingerprint'),
            packet.Device.Device: (
                'id',
                'hostname',
                'user_data',
                'locked',
                'tags',
                'created_at',
                'updated_at',
                'state',
                'ip_addresses',
                'operating_system',
                'plan'),
            packet.OperatingSystem.OperatingSystem: (
                'slug',
                'name',
                'distro',
                'version')}
    else:
        mapping = dict()

    @classmethod
    def to_ansible(self, obj, inner=False):
        """Convert an packet API object into a dictionary presentation"""
        if (inner and not isinstance(obj, packet.baseapi.BaseAPI) and
                not isinstance(obj, packet.OperatingSystem.OperatingSystem)):
            return obj
        try:
            properties = self.mapping[type(obj)]
        except KeyError:
            properties = dict()
        return dict((name, self.to_ansible(getattr(obj, name), inner=True))
                    for name in dir(obj)
                    if name in properties)


class PacketAction(object):

    def apply(self):
        """Apply the action to the API endpoint, returning the result

        Subclasses need to override this method.
        """
        raise NotImplementedError


class PacketByIdLookup(AnsibleModule):
    """Allow API entities to be loaded by ID

    This mixin allows classes to declare that they support loading and
    manipulating objects by ID. The id argument is automatically added, but the
    subclass still needs to implement entity_by_id and set the required_one_of
    kwarg as needed.
    """
    def __init__(self, *args, **kwargs):
        spec = kwargs.get('argument_spec')
        if spec is None:
            spec = dict()
            kwargs['argument_spec'] = spec
        if 'id' not in spec:
            spec.update(id=dict())
        super(PacketByIdLookup, self).__init__(*args, **kwargs)

    def entity_by_id(self):
        """Return the entity mentiond in id using the packet API

        Subclasses must override this method.
        """
        raise NotImplementedError


class PacketModule(AnsibleModule):

    def __init__(self, *args, **kwargs):
        spec = kwargs.get('argument_spec')
        if spec is None:
            spec = dict()
            kwargs['argument_spec'] = spec
        spec.update(auth_token=dict(required=True, aliases=['api_token'],
                                    no_log=True))
        super(PacketModule, self).__init__(*args, **kwargs)
        self._manager = None

    @property
    def manager(self):
        """The object responsible for all comms with Packet"""
        if self._manager is None:
            # Note: Lazy initialisation of the manager object isn't thread-safe
            # but the same module object shouldn't be used in multiple threads
            # simultaneously.
            self._manager = packet.Manager(
                auth_token=self.params['auth_token']
            )
        return self._manager

    @staticmethod
    def is_packet_supported():
        return HAS_PACKET

    def list_entities(self):
        """Return the list of entities using the packet API

        Subclasses must override this method.
        """
        raise NotImplementedError

    def matched_entities(self, entities):
        """Extracts the entity to work on from the list of entities returned

        Subclasses must override this method.
        """
        raise NotImplementedError

    def action_for_entity(self, entity):
        """Returns an action object used for state synchronisation

        Used to sync state with packet. Returns None if the state is already
        synchronised, otherwise the returned instances should be of
        :class:`PacketAction`.

        Subclasses must override this method.
        """
        raise NotImplementedError

    def execute_module(self):
        """Execute the module

        This method relies on the abstract methods in the class to implement
        the default update process:

        1. List the entities
        2. Find the one matching the module invocation
        3. Generate required state changes
        4. Apply
        """

        if not self.is_packet_supported():
            self.fail_json(msg="packet-python not installed")

        matched = None
        if (isinstance(self, PacketByIdLookup) and 'id' in self.params
                and self.params['id']):
            try:
                matched = self.entity_by_id()
            except packet.baseapi.Error as e:
                # we need to convert a 404
                if (attrgetter('cause.response.status_code')(e) == 404):
                    matched = None
                else:
                    self.fail_json(msg=str(e))
        else:
            try:
                entities = self.list_entities()
            except packet.baseapi.Error as e:
                self.fail_json(msg=str(e))

            matches = self.matched_entities(entities)
            if (len(matches) > 1):
                self.fail_json(msg="Named entity not unique", choices=matches)
            elif not matches:
                matched = None
            else:
                matched = matches[0]

        result = PacketProperties.to_ansible(matched)
        action = self.action_for_entity(matched)

        if self.check_mode or not action:
            self.exit_json(changed=(action is not None), **result)
        try:
            result = PacketProperties.to_ansible(action.apply())
        except packet.baseapi.Error as e:
            self.fail_json(msg=str(e))

        self.exit_json(changed=True, **result)

# End common code applying to all modules


class Creation(PacketAction):

    def __init__(self, manager, label, key):
        self._manager = manager
        self._label = label
        self._key = key
        super(Creation, self).__init__()

    def apply(self):
        return self._manager.create_ssh_key(self._label, self._key)


class Update(PacketAction):

    def __init__(self, key, label):
        self._key = key
        self._label = label
        super(Update, self).__init__()

    def apply(self):
        self._key.label = self._label
        self._key.update()
        return self._key


class Deletion(PacketAction):

    def __init__(self, key):
        self._key = key
        super(Deletion, self).__init__()

    def apply(self):
        self._key.delete()


class PacketSSHKeyModule(PacketModule):
    def __init__(self, *args, **kwargs):
        spec = kwargs.get('argument_spec')
        if spec is None:
            spec = dict()
        spec.update(label=dict(required=True, aliases=['name']),
                    ssh_pub_key=dict(required=True),
                    state=dict(default='present',
                    choices=['present', 'absent']),
                    )
        kwargs['supports_check_mode'] = True
        kwargs['argument_spec'] = spec
        super(PacketSSHKeyModule, self).__init__(*args, **kwargs)

    def list_entities(self):
        return self.manager.list_ssh_keys()

    def matched_entities(self, entities):
        return [x for x in entities if x.key == self.params['ssh_pub_key']]

    def action_for_entity(self, entity):
        if (self.params['state'] == 'present' and not entity):
            return Creation(self.manager, self.params['label'],
                            self.params['ssh_pub_key'])
        elif (self.params['state'] == 'present'
              and entity.label != self.params['label']):
            return Update(entity, self.params['label'])
        elif (self.params['state'] == 'absent' and entity):
            return Deletion(entity)
        return None


def main():
    PacketSSHKeyModule().execute_module()


if __name__ == '__main__':
    main()
