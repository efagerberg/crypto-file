from Crypto.Cipher import AES

from crypto_file import CryptoHandler


class Reader(CryptoHandler):

    def __init__(self, fname, password=None, key=None, enableSeek=True):

        # Check for a key or password
        if key is None and password is None:
            msg = 'Need either a password or a key (file) for decryption'
            raise ValueError(msg)

        super(Reader, self).__init__(fname, password, key, 'rb')

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
            raise NotImplementedError('seek disabled for this object')

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
            raise IOError('Seek from EOF is not implemented')
        else:
            raise IOError('Unknown mode requested for seek')

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
