from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from ansible.errors import AnsibleError
from ansible.plugins.lookup import LookupBase

CREDSTASH_INSTALLED = False

try:
    import credstash
    CREDSTASH_INSTALLED = True
except ImportError:
    CREDSTASH_INSTALLED = False


class LookupModule(LookupBase):
    def run(self, terms, variables, **kwargs):

        if not CREDSTASH_INSTALLED:
            raise AnsibleError('The credstash_credential lookup plugin requires CredStash to be installed.')

        ret = []
        for term in terms:
            try:
                version = kwargs.pop('version', '')
                region = kwargs.pop('region', 'eu-west-2')
                table = kwargs.pop('table', 'credential-store')
                stack = kwargs.pop('stack', None)

                if stack is not None:
                    key = term + "." + stack
                else:
                    key = term

                val = credstash.getSecret(key, version, region, table, context=kwargs)
            except credstash.ItemNotFound:
                raise AnsibleError('Key {0} not found'.format(term))
            except Exception as e:
                raise AnsibleError('Encountered exception while fetching {0}: {1}'.format(term, e.message))
            ret.append(val)

        return ret
