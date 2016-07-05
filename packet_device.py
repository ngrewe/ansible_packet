#!/usr/bin/python
#
# An ansible module for provisioning compute resources using
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

DOCUMENTATION = '''
---
module: packet_device
short_description: Provision devices in Packet
description:
    - Create or remove a device in Packet's bare metal cloud.
notes:
    - check_mode is supported.
version_added: "2.2"
author: "Niels Grewe, @ngrewe"
requirements:
    - Requires the packet-python library
options:
    project_id:
        description:
          - The ID of the project that the device should be assigned to
          - either project_id or project_name are required.
    project_name:
        description:
          - The ID name the project that the device should be assigned to
          - either project_id or project_name are required.

    id:
        description:
            - >
                The UUID of the device. If this property is used to identify
                the device, the module cannot automatically create it
        required: false
    hostname:
        description:
            - Hostname of the device
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
            - Determines whether the device should be available.
            - The 'rebooted' state can be used to force a reboot.
        default: 'present'
        choices: [ 'present', 'absent', 'rebooted' ]
    plan:
        description:
            - The plan (type of device) that should be used
            - >
                Valid values seem to include 'baremetal_0', 'baremetal_1',
                'baremetal_3', but there is no enforcement in the module. Check
                with Packet for currently valid values
        required: true
    billing_cycle:
        description: Billing cycle for the machine
        default: 'hourly'
    facility:
        description:
            - The location where the machine should be provisioned.
            - >
                Valid values seem to include 'ewr1', 'sjc1',
                'ams1', but there is no enforcement in the module. Check
                with Packet for currently valid values

        aliases: [ 'region_name' ]
        required: true
    operating_system:
        description:
            - The operating system to provision the device with
            - >
                Valid values seem to include 'centos_7', 'coreos_stable',
                'debian_8', or 'ubuntu_14_04', but there is no enforcement in
                the module. Check with Packet for currently valid values.
        required: true
    locked:
        description: boolean, set locked status
        required: false
        default: 'no'
        choices: [ 'yes', 'no' ]
    user_data:
        description: Userdata you want to process during provisioning
    wait_for:
        description:
            - >
                integer, if set to a positive, non-zero value, the number of
                seconds to wait the device to be successfully provisioned.
        default: 0
        required: false
'''

EXAMPLES = '''
- packet_device:
    project_id: 97c4a82f-d7f3-415d-a8a2-6f791dd724a9
    hostname: host.example.com
    plan: baremetal_0
    facility: ewr1
    operating_system: coreos_stable
    state: present
    auth_token: XYZ
'''

RETURN = '''
'''

# Begin common code applying to all modules
from ansible.module_utils.basic import AnsibleModule
from operator import attrgetter
from sched import scheduler
import time

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


class WaitExceededError(Exception):
    """This error is raised if the device wasn't provisioned in time"""

    def __init__(self, wait, device):
        super(WaitExceededError, self).__init__()
        self.device = device
        self.wait = wait

    def __str__(self):
        if not self.device:
            return "device did not become active " \
                   "within %d seconds" % (self.wait,)
        return "device '%s' did not become active " \
               "within %d seconds" % (self.device, self.wait)

    def __repr__(self):
        if not self.device:
            return "WaitExceeded(None > %ds)" % (self.wait,)
        return "WaitExceeded('%s' > %ds)" % (self.device, self.wait)


class WaitOnDeviceAction(PacketAction):
    """Superclass of actions that may require waiting on the device state"""

    def __init__(self, manager, wait_for=0):
        self._wait_seconds = wait_for
        self._poll = 10  # default to polling every 10 seconds
        self._manager = manager
        self._device = None
        super(WaitOnDeviceAction, self).__init__()

    @property
    def manager(self):
        return self._manager

    @property
    def device(self):
        return self._device

    @device.setter
    def device(self, value):
        self._device = value

    def should_wait(self, from_time):
        return not self.device or (self.device.state != 'active'
                                   and (time.time() - from_time
                                        < self._wait_seconds))

    def perform_inner(self):
        raise NotImplementedError

    def update_device(self):
        newDevice = self.manager.get_device(self.device.id)
        if newDevice:
            self.device = newDevice

    def wait_on_active(self):
        s = scheduler(time.time, time.sleep)
        started_at = time.time()
        while self.should_wait(started_at):
            d = max(0, min(self._poll,
                           self._wait_seconds - (time.time() - started_at)))
            s.enter(d, 0, lambda that: that.update_device(), (self,))
            s.run()
        if (not self.device or self.device.state != 'active'):
            raise WaitExceededError(self._wait_seconds, self.device)

    def apply(self):
        self.device = self.perform_inner()
        if self._wait_seconds > 0 and (not self.device
                                       or self.device.state != 'active'):
            self.wait_on_active()
        return self.device


class Creation(WaitOnDeviceAction):

    def __init__(self, module):
        super(Creation, self).__init__(module.manager,
                                       module.params['wait_for'])
        self._project_id = module.project_id
        self._hostname = module.params['hostname']
        self._plan = module.params['plan']
        self._facility = module.params['facility']
        self._operating_system = module.params['operating_system']
        self._billing_cycle = module.params['billing_cycle']
        self._userdata = module.params['user_data']
        self._locked = module.params['locked']

    def perform_inner(self):
        return self.manager.create_device(self._project_id,
                                          self._hostname, self._plan,
                                          self._facility,
                                          self._operating_system,
                                          self._billing_cycle,
                                          self._userdata,
                                          self._locked)


class Deletion(PacketAction):

    def __init__(self, device):
        super(Deletion, self).__init__()
        self._device = device

    def apply(self):
        self._device.delete()


class Update(PacketAction):

    def __init__(self, device, name, locked):
        super(Update, self).__init__()
        self._device = device
        self._name = name
        self._locked = locked

    def apply(self):
        self._device.name = self._name
        self._device.locked = self._locked
        self._device.update()
        return self._device


class Reboot(WaitOnDeviceAction):

    def __init__(self, manager, device, wait_for=0):
        super(Reboot, self).__init__(manager, wait_for)
        self.device = device

    def perform_inner(self):
        self.device.reboot()
        return self.device


class JustWait(WaitOnDeviceAction):

    def __init__(self, manager, device, wait_for=0):
        super(JustWait, self).__init__(manager, wait_for)
        self.device = device

    def perform_inner(self):
        return self.device


class ActionList(PacketAction):

    def __init(self, *actions):
        self._actions = list(actions)
        super(ActionList, self).__init__()

    def apply(self):
        res = None
        for action in self._actions:
            r = action.apply()
            if r:
                res = r
        return res


class PacketDeviceModule(PacketModule, PacketByIdLookup):

    REQUIRED_IF_PRESENT = ['operating_system', 'facility', 'plan']

    def __init__(self, *args, **kwargs):
        spec = kwargs.get('argument_spec')
        if spec is None:
            spec = dict()
        spec.update(hostname=dict(),
                    state=dict(default='present',
                    choices=['present', 'absent', 'rebooted']),
                    locked=dict(type='bool', default=False),
                    user_data=dict(default=''),
                    billing_cycle=dict(default='hourly'),
                    facility=dict(aliases=['region_name']),
                    operating_system=dict(),
                    plan=dict(),
                    project_id=dict(),
                    project_name=dict(),
                    wait_for=dict(type='int', default=0)
                    )
        kwargs['supports_check_mode'] = True
        kwargs['argument_spec'] = spec
        kwargs['required_one_of'] = [['project_id', 'project_name'],
                                     ['hostname', 'id']]
        kwargs['required_if'] = [['state', 'present',
                                  self.REQUIRED_IF_PRESENT],
                                 ['state', 'rebooted',
                                  self.REQUIRED_IF_PRESENT]]

        super(PacketDeviceModule, self).__init__(*args, **kwargs)
        self._project_id = None

    @property
    def project_id(self):
        """Return the project ID for the device.

        This is either set based on the module parameter, or matched up by name
        from the list of projects.
        """
        if self._project_id:
            return self._project_id
        if self.params['project_id']:
            self._project_id = self.params['project_id']
            return self._project_id
        try:
            proj_list = self.manager.list_projects()
        except packet.baseapi.Error as e:
            self.fail_json(msg=str(e))
        matches = [x for x in proj_list
                   if x.name == self.params['project_name']]
        if matches:
            self._project_id = matches[0].id
            return self._project_id
        else:
            self.fail_json(msg='Project does not exist')

    def entity_by_id(self):
        return self.manager.get_device(self.params['id'])

    def list_entities(self):
        return self.manager.list_devices(self.project_id)

    def matched_entities(self, entities):
        return [x for x in entities if x.hostname == self.params['hostname']]

    def action_for_entity(self, entity):
        actions = list()
        if (self.params['state'] in ['present', 'rebooted'] and not entity):
            if self.params['id']:
                self.fail_json(msg='Unable to create project with explicit ID')
            return Creation(self)
        elif (self.params['state'] == 'present' and entity and
              self.params['wait_for'] > 0 and entity.state != 'active'):
            return JustWait(self.manager, entity, self.params['wait_for'])
        elif (self.params['state'] == 'absent' and entity):
            return Deletion(entity)
        elif (self.params['state'] in ['present', 'rebooted']
              and (entity.hostname != self.params['hostname']
              or entity.locked != self.params['locked'])):
            actions.append(Update(entity, self.params['hostname'],
                                  self.params['locked']))
        if self.params['state'] == 'rebooted':
            actions.append(Reboot(self.manager, entity,
                                  self.params['wait_for']))

        if actions:
            return ActionList(actions)
        return None


def main():
    module = PacketDeviceModule()
    try:
        module.execute_module()
    except WaitExceededError as e:
        #  WaitExceededError is raised if we were asked to wait for the device
        #  to become active, but it didn't get provisioned/rebooted in time
        module.fail_json(msg=str(e),
                         device=PacketProperties.to_ansible(e.device))


if __name__ == '__main__':
    main()
