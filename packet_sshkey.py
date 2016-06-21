#!/usr/bin/python
#
# An ansible module for manipulating ssh keys using
# [Packet's API](https://www.packet.net/resources/docs/)
#
# Copyright (c) 2016 Niels Grewe
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
module: packet_sshkey
short_description: Create/delete a SSH key in Packet
description:
    - Create or delete a SSH key for the current user in Packet
notes:
    - check_mode is supported.
version_added: "2.1"
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
                'updated_at'
                ),
            packet.SSHKey.SSHKey: (
                'id',
                'label',
                'created_at',
                'updated_at',
                'key',
                'fingerprint'
                )
            }
    else:
        mapping = dict()

    @classmethod
    def to_ansible(self, obj):
        """Convert an packet API object into a dictionary presentation"""
        try:
            properties = self.mapping[type(obj)]
        except KeyError:
            properties = dict()
        return dict((name, getattr(obj, name))
                    for name in dir(obj)
                    if name in properties)


class PacketAction(object):

    def apply(self):
        """Apply the action to the API endpoint, returning the result

        Subclasses need to override this method.
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

        try:
            entities = self.list_entities()
        except packet.baseapi.Error as e:
            self.fail_json(msg=str(e))

        matches = self.matched_entities(entities)
        if (len(matches) > 1):
            self.fail_json(msg="Named entity not unique", choices=matches)
        elif not matches:
            matched = None
            result = dict()
        else:
            matched = matches[0]
            result = PacketProperties.to_ansible(matches[0])
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