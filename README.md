Ansible Modules for the Packet Bare Metal Cloud
===============================================

This project provides a few basic modules for managing bare metal servers on
[Packet's](https://www.packet.net) cloud solution. It requires the
[packet-python](https://github.com/packethost/packet-python) library, currently
with a small patch so that it doesn't produce output that upsets ansible.

The first available module simply creates or deletes projects:

```
- packet_project:
    name: foo
    state: present
    auth_token: XYZ
```

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
