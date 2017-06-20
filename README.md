# credstash_credential

An Ansible role that provides the ability to generate secrets/credentials and store them
in CredStash. Also provides a lookup that allows the easy retrieval of the credentials


## Requirements

Requires the `credstash` python module to be installed.

Run `pip install credstash` to install the dependency.


## Role Variables

There are none for the role as the role provides a module and lookup, both of the
name `credstash_credential`.

To use either the module or lookup the role must be referenced first.

```
-  hosts: localhost
   roles:
     - role: credstash_credential
```


## credstash_credential module

The `credstash_credential` module allows you to create and delete CredStash secrets
from within Ansible Playbooks.

### Module Variables


### Module Examples




## credstash_credential lookup

The `credstash_credential` lookup is just a minor variation on the `credstash` lookup
that has a different default for `region` and provides a new parameter of `stack` so
as to compliment the `credsrash_credential` module.

### Lookup Variables

### Lookup Examples


## License
Apache
