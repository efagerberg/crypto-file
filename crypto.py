from Crypto.Cipher import AES
from Crypto import Random
import hashlib
import base64


#  AES encrypted file-like object
#  - Support for Reader and Writer objects


class cryptoClass:
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
            raise IOError

        self.mode = self.fObj.mode

        self.passwrd = password
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
        if isinstance(self.key, str) and self.key.endswith('.key'):
            self.key = open(self.key, 'rb').read()
        elif isinstance(self.key, str):
            if len(base64.b64decode(self.key)) == 32:
                self.key = base64.b64decode(self.key)

            if len(self.key) != 32:
                raise NotImplementedError

        # Also support a password hashed into a key
        elif isinstance(self.passwrd, str):
            self.key = hashlib.sha256(self.passwrd).digest()

        # Create a new key if the Writer object is being used
        should_create_new_key = (self.__class__.__name__ == 'Writer' and
                                 self.key is None and
                                 self.passwrd is None)
        if should_create_new_key:
            self.key = hashlib.sha256(Random.new().read(32)).digest()
            print('Encryption Key: {}\n'.format(base64.b64encode(self.key)))

        # Have to create a new password from the key to use in IV
        # - allows for message recovery using key file without password
        self.passwrd = base64.b64encode(self.key)

    def gen_iv(self):
        iv = ''
        d_i = ''
        while len(iv) < self.bs:
            d_i = hashlib.sha256(d_i + self.passwrd + self.salt).digest()
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
        self.close()

    # Add a weak method to ensure open encryption streams are closed properly
    def __del__(self):
        self.close()


class Reader(cryptoClass):

    def __init__(self, fname, password=None, key=None, enableSeek=True):

        # Check for a key or password
        if key is None and password is None:
            print('Need either a password or a key (file) for decryption')
            raise NotImplementedError

        cryptoClass.__init__(self, fname, password, key, 'rb')

        # Verify the file object is in read mode
        self.check_mode('r')

        # Need to retrieve the salt from the file
        self.get_salt()
        self.gen_iv()

        # Initiate the decryptor
        self.cipher = AES.new(self.key, AES.MODE_CBC, self.iv)

        # Setup the object's stream [used as a read buffer or write buffer]
        self.streamLines = 0
        self.chunk_unprocessed = ''
        self.enableSeek = enableSeek

        # Allow for seek function; need to store previous values
        self.prev_stream = ''

    # Retrieve or Create the salt for the cipher
    def get_salt(self):
        self.salt = self.fObj.read(self.bs)[len('Salted__'):]

    # Method to read the next line
    # + decrypt enough to cover the next line
    def readline(self):
        while self.streamLines == 0 and self.fileOpen:
            self.decrypt_chunk()

        currLine, lineSuff, self.stream = self.stream.partition('\n')
        currChunk = currLine + lineSuff
        self.streamLines -= 1

        if self.enableSeek:
            self.prev_stream += currChunk

        return currChunk

    def read(self, size=None):
        while (len(self.stream) < size or size is None) and self.fileOpen:
            self.decrypt_chunk()
        if size is None:
            size = len(self.stream)
            currChunk, self.stream = self.stream, ''
        else:
            size = min(size, len(self.stream))
            currChunk = self.stream[:size]
            self.stream = self.stream[size:]

        if self.enableSeek:
            self.prev_stream += currChunk

        return currChunk

    def seek(self, pos, mode=0):
        if not self.enableSeek:
            print('seek disabled for this object')
            raise NotImplementedError

        # - Absolute position: from the start of the file
        # + equivalent to a relative position plus the
        #  length of the previous stream
        if mode == 0:
            pos -= len(self.prev_stream)

        # - Relative position: from the current position
        if mode == 0 or mode == 1:
            if pos < 0:
                self.stream = self.prev_stream[pos:] + self.stream
                self.prev_stream = self.prev_stream[:pos]
            else:
                self.read(pos)

        elif mode == 2:
            print('Seek from EOF is not implemented')
            raise IOError
        else:
            print('Unknown mode requested for seek')
            raise IOError

    def decrypt_chunk(self):
        self.chunk_processed = self.chunk_unprocessed
        crypted = self.fObj.read(1024 * self.bs)
        self.chunk_unprocessed = self.cipher.decrypt(crypted)
        if len(self.chunk_unprocessed) == 0:
            padding_length = ord(self.chunk_processed[-1])
            self.chunk_processed = self.chunk_processed[:-padding_length]
            self.fileOpen = False
        self.stream += self.chunk_processed
        self.streamLines += self.chunk_processed.count('\n')
        return 1

    def close(self):
        if not self.fObj.closed:
            self.fObj.close()


class Writer(cryptoClass):

    def __init__(self, fname, password=None, key=None, saveKey_file=None):
        cryptoClass.__init__(self, fname, password, key, 'wb')

        # Write the key to the specified file
        if saveKey_file is not None:
            open(saveKey_file, 'wb').write(self.key)

        # Verify the file object is in write mode
        self.check_mode('w')

        self.get_salt()
        self.gen_iv()

        # Initiate the encryptor
        self.cipher = AES.new(self.key, AES.MODE_CBC, self.iv)

    # Create the salt for the cipher
    def get_salt(self):
        # If it is a writable file need to
        # save the salt value to the start of the file
        self.salt = Random.new().read(self.bs - len('Salted__'))
        self.fObj.write('Salted__' + self.salt)

    def write(self, str):
        self.stream += str
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
        self.fObj.close()
