Ansible Modules for the Packet Bare Metal Cloud
===============================================

This project provides a few basic modules for managing bare metal servers on
[Packet's](https://www.packet.net) cloud solution. It requires the
[packet-python](https://github.com/packethost/packet-python) library, currently
you need a set of patches from the [ansible branch in my fork of the project](https://github.com/ngrewe/packet-python/tree/ansible)

Available modules
-----------------
Documentation for the modules is present in the `DOCUMENTATION` variable at the top of each module file, but as a quick reference, these are the basic operations available:

### packet_project
Simply creates or deletes projects:

```YAML
- packet_project:
    name: foo
    state: present
    auth_token: XYZ
```

### packet_sshkey
Allows you to add/remove SSH keys from your account:

```YAML
- packet_sshkey:
    label: my_key
    ssh_pub_key: 'ssh-rsa DEADBEEF...'
    state: present
    auth_token: XYZ
```

### packet_device
Allows you to manage devices in a project:

```YAML
- packet_device:
    project_id: 97c4a82f-d7f3-415d-a8a2-6f791dd724a9
    hostname: host.example.com
    plan: baremetal_0
    facility: ewr1
    operating_system: coreos_stable
    state: present
    auth_token: XYZ
```

It is also possible to reference the project by name using the `project_name` parameter. Other useful options for this module are the `rebooted` value for the `state` parameter, which allows you to reboot the instance, and the `wait_for` parameter which allows you to specify the number of seconds to wait while a provisioning operation completes.

Known issues
------------
* Paginated API responses are currently not treated appropriately, so if you have `n>10` entities of any sort and try to reference them by name, you might get false negatives about their existence.

License
-------
This software is released under the MIT license.

Copyright (c) 2016 Niels Grewe

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
