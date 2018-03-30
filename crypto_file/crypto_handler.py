import hashlib
import base64

from Crypto.Cipher import AES

#  AES encrypted file-like object
#  - Support for Reader and Writer objects


class CryptoHandler:
    def __init__(self, fname, password=None, key=None, mode=None):

        # Create a file handler
        if isinstance(fname, str):
            self.fObj = open(fname, mode)
        elif isinstance(fname, file):  # noqa: F821
            curr_mode = fname.mode
            if 'b' in curr_mode:
                self.fObj = fname
            else:
                curr_mode += 'b'
                tempName = fname.name
                fname.close()
                self.fObj = open(tempName, curr_mode)
        else:
            raise IOError("fname must be a string or file")

        self.mode = self.fObj.mode

        self.password = password
        self.key = key
        self.bs = AES.block_size

        # Generate the key
        self.gen_key()

        # Setup the object's stream [used as a read buffer or write buffer]
        self.stream = ''
        self.fileOpen = True

    # Create the hashed password and initiation vector for the cipher
    def gen_key(self):

        # Support a pre-hashed key either saved in a file or passed as a string
        if isinstance(self.key, str):
            decoded_key = base64.b64decode(self.key)
            if self.key.endswith('.key'):
                self.key = open(self.key, 'rb').read()
            elif len(decoded_key) == 32:
                self.key = decoded_key
            else:
                raise NotImplementedError("Key not supported.")
        # Also support a password hashed into a key
        elif isinstance(self.password, str):
            self.key = hashlib.sha256(self.password).digest()
        else:
            raise ValueError("Key or password is invalid.")

        # Have to create a new password from the key to use in IV
        # - allows for message recovery using key file without password
        self.password = base64.b64encode(self.key)

    def gen_iv(self):
        iv = ''
        d_i = ''
        while len(iv) < self.bs:
            d_i = hashlib.sha256(d_i + self.password + self.salt).digest()
            iv += d_i
        self.iv = iv[:self.bs]

    def check_mode(self, mType):
        if not self.mode.startswith(mType):
            print('Requested operation not compatible with current file mode')
            raise IOError

    # Allow use in a with statement
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.fObj.close()

    # Add a weak method to ensure open encryption streams are closed properly
    def __del__(self):
        self.fObj.close()
