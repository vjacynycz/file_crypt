# file_crypt module for Ansible
Ansibe module to encrypt a file using AES and RSA

# How to use
Download or clone this repository and copy the module in `ansible/plugins/modules` under your ansible's module directory.

Once copied, you can use this module in you plays like this:

```yml
- name: Encrypt file
  file_crypt:
    src: "{{ file_to_encrypt }}"
    op: encrypt
    rsa_key_raw: "{{ lookup('file', rsa_keys_dir + '/public_key.pem') }}"
```


## Module options
- `src`:
    description:
        - Source file to encrypt or decrypt
    required: true
- `dest`:
    description:
        - Optional destination path. Default is source path with a '.crypt' preffix.
    required: false
- `op`:
    description:
        - "encrypt" / "decrypt".
    required: true
- `rm_src`:
    description:
        - If true, this module will delete the source file once the operation is finished. Default is false
    required: false
- `rsa_key_raw`:
    description:
        - Raw public/private key to encrypt/decrypt the file.
    required: true
- `rsa_key_path`:
    description:
        - Path to the public/private key to encrypt/decrypt the file.
    required: true

## How it works
This module works following this steps. To `encrypt` a file:
1. Loads an RSA key via path or raw.
2. Generates a random AES key .
3. Encrypts the file using AES algorithm.
4. Encrypts AES key using RSA public key.
5. Packs both the file encrypted and the key into a `tgz` file.
6. If rm_src option is `True`, this module removes the original file.

To `decrypt` a file:
1. Unpacks the `tgz` file.
2. Decrypts the AES key file using RSA private key.
3. Decrypts the file using AES algorithm.
4. If rm_src option is `True`, this module removes the packed `tgz` file.

## Requirements

This module requires `pycryptodome` installed to encrypt/decrypt.