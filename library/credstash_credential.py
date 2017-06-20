#!/usr/bin/python

#TODO Add documentation
#TODO Add support for context when storing

CREDSTASH_INSTALLED = False
try:
    import credstash
    CREDSTASH_INSTALLED = True
except ImportError:
    CREDSTASH_INSTALLED = False

import os
import string
import random
import sys
from cStringIO import StringIO


class Capture(list):
    def __enter__(self):
        self._stdout = sys.stdout
        sys.stdout = self._stringio = StringIO()
        return self

    def __exit__(self, *args):
        self.extend(self._stringio.getvalue().splitlines())
        del self._stringio
        sys.stdout = self._stdout


def _is_missing_error(ex):
    return "couldn't be found" in ex.message

def _version_provided(version):
    return version is not None and version

def _generate_result(key, changed=False, version=None):
    result = {'changed': changed, 'key': key}

    if version is not None:
        result['version'] = version

    return result

def _pad_version(version):
    my_val = ''

    if _version_provided(version):
        my_val = str(version)
        my_val = my_val.zfill(19)

    return my_val;

def rotate_credential(key, value, region, table, version=''):
    if not _version_provided(version):
        version = int(credstash.getHighestVersion(key, region=region, table=table)) + 1
        version = _pad_version(version)
    # return {'version': version}
    credstash.putSecret(key, value, version, region=region, table=table)
    return _generate_result(key, changed=True, version=version)


def store_credential(key, value, region, table, version=''):
    credstash.putSecret(key, value, version, region=region, table=table)
    result = _generate_result(key, changed=True, version=version)
    return result


def delete_credential(key, region, table):
    changed = False

    if _credential_exists(key, region, table):
        with Capture() as output:
            # credstash library writes to stdout on deletes
            credstash.deleteSecrets(key, region=region, table=table)
        changed = True

    return _generate_result(key, changed)


def get_credential(key, region, table, version=''):
    return credstash.getSecret(key, version, region, table)

def _credential_exists(key, region, table, version=''):
    result = False
    try:
        existing = get_credential(key, region, table, _pad_version(version))
        result = True
    except Exception as e:
        if _is_missing_error(e):
            # Ignore a this error
            result = False
        else:
            raise e
    return result

def _generate_secret_value(value, create_password, password_length, password_type):
    val = None

    if value is None:
        if create_password:
            val = _generate_password(password_length, password_type)
        else:
            raise Exception('A secret must be provided or dynamic creation activated when storing a credential')
    else:
        val = value

    return val

def _random_password(length=20, chars=['ascii_letters', 'digits']):
    '''Return a random password string of length containing only chars

    :kwarg length: The number of characters in the new password.  Defaults to 20.
    :kwarg chars: The characters to choose from.  The default is all ascii
        letters, ascii digits, and these symbols ``.,:-_``
    '''
    assert isinstance(chars, text_type), '%s (%s) is not a text_type' % (chars, type(chars))

    random_generator = random.SystemRandom()

    password = []
    while len(password) < length:
        new_char = random_generator.choice(chars)
        password.append(new_char)

    return u''.join(password)


def _gen_candidate_chars(characters):
    '''Generate a string containing all valid chars as defined by ``characters``

    :arg characters: A list of character specs. The character specs are
        shorthand names for sets of characters like 'digits', 'ascii_letters',
        or 'punctuation' or a string to be included verbatim.

    The values of each char spec can be:

    * a name of an attribute in the 'strings' module ('digits' for example).
      The value of the attribute will be added to the candidate chars.
    * a string of characters. If the string isn't an attribute in 'string'
      module, the string will be directly added to the candidate chars.

    For example::

        characters=['digits', '?|']``

    will match ``string.digits`` and add all ascii digits.  ``'?|'`` will add
    the question mark and pipe characters directly. Return will be the string::

        u'0123456789?|'
    '''
    chars = []
    for chars_spec in characters:
        # getattr from string expands things like "ascii_letters" and "digits"
        # into a set of characters.
        chars.append(to_text(getattr(string, to_native(chars_spec), chars_spec),
                            errors='strict'))
    chars = u''.join(chars).replace(u'"', u'').replace(u"'", u'')
    return chars


def _get_characters_from_type(type):
    options = {
        'letters': ['ascii_letters'],
        'letters_and_numbers': ['ascii_letters', 'digits'],
        'complex': ['ascii_letters', 'digits', '".,:-_"']
    }
    return options.get(type)


def _generate_password(length, type):
    valid_chars = _get_characters_from_type(type)
    candidate_characters = _gen_candidate_chars(valid_chars)

    return _random_password(length=length, chars=candidate_characters)


def main():
    module = AnsibleModule(
        argument_spec = dict(
            state=dict(default='present', choices=['present', 'absent'], type='str'),
            version=dict(default='', type='str'),
            #TODO make all regions we need available -- load from Amazon constants?
            region=dict(default='eu-west-2', choices=['eu-west-1', 'eu-west-2', 'us-east-1', 'us-west-1'], type='str'),
            table=dict(default='credential-store', type='str'),
            stack=dict(default=None, type='str'),
            name=dict(required=True, type='str'),

            secret=dict(default=None, type='str'),
            create_if_missing=dict(default=False, type='bool'),
            rotate=dict(default=False, type='bool'),

            secret_chars=dict(default='letters_and_numbers', choices=['letters', 'letters_and_numbers', 'complex'], type='str'),
            secret_length=dict(default=12, type='int')
        )
    )

    if not CREDSTASH_INSTALLED:
        module.fail_json(msg='CredStash is not installed')

    name = module.params.get('name')
    stack = module.params.get('stack')

    if stack is not None:
        key = name + "." + stack
    else:
        key = name

    table = module.params.get('table')
    state = module.params.get('state')
    region = module.params.get('region')
    version = module.params.get('version')

    try:
        if state == 'present':
            value = module.params.get('secret')
            rotate = module.params.get('rotate')

            create_password = module.params.get('create_if_missing')
            password_length=module.params.get('secret_length')
            password_type=module.params.get('secret_chars')

            exists = _credential_exists(key, region, table, version)

            if exists:
                if rotate:
                    if not _version_provided(version):
                        secret = _generate_secret_value(value, create_password, password_length, password_type)
                        result = rotate_credential(key, secret, region, table)
                    else:
                        module.fail_json(msg='Cannot rotate a credential when specifying a version that already exists for key')
                else:
                    result = _generate_result(key)
            else:
                secret = _generate_secret_value(value, create_password, password_length, password_type)
                result = store_credential(key, secret, region, table, _pad_version(version))
        else:
            result = delete_credential(key, region, table)

    except Exception as e:
        module.fail_json(msg=str(e))

    module.exit_json(**result)


from ansible.module_utils.basic import *

if __name__ == '__main__':
    main()
