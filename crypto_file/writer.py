import hashlib
import base64

from Crypto.Cipher import AES
from Crypto import Random

from crypto_file import CryptoHandler


class Writer(CryptoHandler):

    def __init__(self, fname, password=None, key=None, saveKey_file=None):
        super(Writer, self).__init__(fname, password, key, 'wb')

        # Write the key to the specified file
        if saveKey_file is not None:
            open(saveKey_file, 'wb').write(self.key)

        # Verify the file object is in write mode
        self.check_mode('w')

        self.get_salt()
        self.gen_iv()

        # Initiate the encryptor
        self.cipher = AES.new(self.key, AES.MODE_CBC, self.iv)

    def gen_key(self):
        should_create_new_key = (self.key is None and
                                 self.password is None)
        if should_create_new_key:
            self.key = hashlib.sha256(Random.new().read(32)).digest()
            print('Encryption Key: {}\n'.format(base64.b64encode(self.key)))
            # Have to create a new password from the key to use in IV
            # - allows for message recovery using key file without password
            self.password = base64.b64encode(self.key)
        else:
            super(Writer, self).gen_key()

    # Create the salt for the cipher
    def get_salt(self):
        # If it is a writable file need to
        # save the salt value to the start of the file
        self.salt = Random.new().read(self.bs - len('Salted__'))
        self.fObj.write('Salted__' + self.salt)

    def write(self, s):
        self.stream += s
        self.check_write_buffer()

    # Check if enough data is available to write an encrypted chunk
    def check_write_buffer(self):
        # - retain partial chunks and only pad if the file is being closed
        while len(self.stream) >= 1024 * self.bs:
            chunk = self.stream[:1024*self.bs]
            self.fObj.write(self.cipher.encrypt(chunk))
            self.stream = self.stream[1024*self.bs:]

    def close(self):
        if self.fObj.closed:
            return

        # Check for a partial string and pad if necessary
        if len(self.stream) == 0 or len(self.stream) % self.bs != 0:
            padding_length = (self.bs - len(self.stream) % self.bs) or self.bs
            self.stream += padding_length * chr(padding_length)
        else:
            self.fObj.write(self.cipher.encrypt(self.stream))
            self.stream = self.bs * chr(self.bs)

        self.fObj.write(self.cipher.encrypt(self.stream))
        super(Writer, self).close()
