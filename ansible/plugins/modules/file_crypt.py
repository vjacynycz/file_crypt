#!/usr/bin/python

'''
'''

from ansible.module_utils.basic import AnsibleModule
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import base64
import os
import tarfile

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'stratio'
}

class FileCryptException(Exception):
    """docstring for FileCryptException"""

    def __init__(self, msg, exception_type):
        super(FileCryptException, self).__init__()
        self.msg = msg
        self.exception_type = exception_type

DOCUMENTATION = '''
---
module: file_cript

short_description: Encrypts or decrypts a file

version_added: "2.8"

description:
    - "This module allows users encrypt or decrypt a file using RSA key files"

options:
    src:
        description:
            - Source file to encrypt or decrypt
        required: true
    dest:
        description:
            - Optional destination path. Default is source path with a '.crypt' preffix.
        required: false
    op:
        description:
            - "encrypt" / "decrypt".
        required: true
    rm_src:
        description:
            - If true, this module will delete the source file once the operation is finished. Default is false
        required: false
    rsa_key_raw:
        description:
            - Raw public/private key to encrypt/decrypt the file.
        required: true
    rsa_key_path:
        description:
            - Path to the public/private key to encrypt/decrypt the file.
        required: true
author:
    - Viktor Jacynycz (vjacynycz@stratio.com)
'''

EXAMPLES = '''
file_crypt:
  src: /workspace/my_big_file.data
  op: cypher
  rm_src: no
  rsa_key_raw: "{{ lookup('file', key_dir + '/public_key.pem') }}"

file_crypt:
  src: /workspace/my_big_file.data
  dest: /workspace/filencrypted.crypt
  op: cypher
  rm_src: yes
  rsa_key_path: "/tmp/rsa_keys/public_key.pem"

file_crypt:
  src: /workspace/my_big_file.data.crypt
  op: decypher
  rsa_key: "{{ lookup('file', key_dir + '/private_key.pem') }}"
'''

RETURN = '''
cryptlog:
    description: Log text about the operation
    type: str
    returned: always
'''

def run_module():
    '''Main module'''
    module_args = dict(
        src=dict(type='str', required=True),
        dest=dict(type='str', required=False, default=''),
        op=dict(type='str', required=True),
        rm_src=dict(type='bool', required=False, default=False),
        rsa_key_raw=dict(type='str', required=False, default=''),
        rsa_key_path=dict(type='str', required=False, default='')
    )

    result = dict(
        changed=False,
        log=[]
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    error = dict(
        msg='',
        error_type=''
    )

    if module.check_mode:
        module.exit_json(**result)

    _src = module.params['src']
    _dest = module.params['dest']
    _op = module.params['op']
    _rm_src = module.params['rm_src']
    _rsa_key_raw = module.params['rsa_key_raw']
    _rsa_key_path = module.params['rsa_key_path']
    log = []
    try:
        key = load_key(_rsa_key_raw, _rsa_key_path, _op)
        if _op == 'encrypt':
            encrypt_operation(key, _src, _dest, _rm_src, log)
        elif _op == 'decrypt':
            decrypt_operation(key, _src, _dest, _rm_src, log)
        else:
            raise FileCryptException("Parameter 'op' must be ['encrypt','decrypt']",
                                "Wrong operation")
    except FileCryptException as snake_case_error:
        error['msg'] = snake_case_error.msg
        error['error_type'] = snake_case_error.exception_type
        module.fail_json(**error)

    result['log'] = log
    module.exit_json(**result)

def load_key(rsa_key_raw, rsa_key_path, _op):
    try:
        # Try to load raw RSA key
        if rsa_key_raw == '':
            with open(rsa_key_path,'r') as rsa_public_file:
                rsa_key_data = RSA.importKey(rsa_public_file.read())
        else:
            rsa_key_data = RSA.importKey(rsa_key_raw)
        
        if _op == 'encrypt':
            return PKCS1_OAEP.new(rsa_key_data.publickey())
        else: 
            return PKCS1_OAEP.new(rsa_key_data)
    except Exception as other_error:
        raise FileCryptException("Key file could not be loaded. "+str(other_error),
                                "Keyfile error")

def encrypt_operation(key, src, dest, rm_src, log):
    log.append('Encrypting file '+src)
    
    # Generate a new random AES key
    aeskey = Random.new().read(32)
    if dest == '':
        dest = src + ".crypt"
    encrypt_file(src, aeskey, dest)

    # Encrypt the key using RSA
    dest_dirname = os.path.dirname(dest)
    ciphertext = key.encrypt(aeskey)
    with open(dest_dirname + '/aes_key.crypt','wb') as rsafile:
        rsafile.write(base64.b64encode(ciphertext))
    log.append('Encrypting complete')

    # Generate a tar containing the file encrypted and the key
    log.append('Generating tar file')
    with tarfile.open(dest + '.tgz', "w:gz") as tar:
        tar.add(dest_dirname + '/aes_key.crypt', arcname='aes_key.crypt')
        tar.add(dest, arcname=os.path.basename(dest) )
    os.remove(dest_dirname + '/aes_key.crypt')
    log.append('Tar file generated: ' + dest + '.tgz')

    # Remove src file if rm_src is true
    if rm_src:
        os.remove(src)
        log.append('Removed source file')

def decrypt_operation(key, src, dest, rm_src, log):
    log.append('Decrypting file '+src)
    # Extract tar file
    with tarfile.open(src, 'r:gz') as tgz:
        tgz.extractall(path=os.path.dirname(src))

    # Get files
    cryptfile = src[:-4]
    aes_key_path = os.path.dirname(src) + '/aes_key.crypt'

    if dest == '':
        if cryptfile.endswith('.crypt'):
            dest = cryptfile[:-6]
        else:
            dest = src + ".crypt"
    
    with open(aes_key_path, 'rb') as encrypted_key:
        # Decrypt the key file using RSA
        aes_key = key.decrypt(base64.b64decode(encrypted_key.read()))

        # Decrypt the file using the decrypted key
        decrypt_file(cryptfile, aes_key, dest)
        log.append('Decrypted file '+ dest)
    
    os.remove(cryptfile)
    os.remove(aes_key_path)

    # Remove src file if rm_src is true
    if rm_src:
        os.remove(src)
        log.append('Removed source file')

def encrypt(message, key):
    message = pad(message,AES.block_size)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(message)

def decrypt(ciphertext, key):
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext[AES.block_size:])
    return unpad(plaintext,AES.block_size)

def encrypt_file(file_name, key, dest):
    with open(file_name, 'rb') as fo:
        plaintext = fo.read()
    enc = encrypt(plaintext, key)
    with open(dest, 'wb') as fo:
        fo.write(enc)

def decrypt_file(file_name, key, dest):
    if dest == '':
        dest = file_name + ".decrypt"
    with open(file_name, 'rb') as fo:
        ciphertext = fo.read()
    dec = decrypt(ciphertext, key)
    with open(dest, 'wb') as fo:
        fo.write(dec)

def main():
    '''Main function'''
    run_module()

if __name__ == '__main__':
    main()
