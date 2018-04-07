import mock
import pytest

from crypto_file.reader import Reader


@pytest.fixture()
def mock_open():
    with mock.patch('__builtin__.open') as m:
        yield m


@pytest.fixture()
def reader(mock_open):
    mock_open.return_value.read.return_value = 'Salted__asdfghj\n'
    reader = Reader(fname='foo.txt',
                    password='foo')
    mock_open.reset_mock()
    yield reader


def test_init_errors_without_password_or_key():
    with pytest.raises(ValueError):
        Reader(fname='foo')


def test_init_generates_expected_attributes(reader):
    assert reader.salt is not None
    assert reader.iv is not None
    assert reader.cipher is not None
    assert reader.streamLines == 0
    assert reader.chunk_unprocessed == ''
    assert reader.enableSeek is True
    assert reader.prev_stream == ''


def test_get_salt_makes_salt_from_fObj(reader):
    expected_salt = 'asdfghj\n'
    reader = Reader(fname='foo.txt',
                    password='foo')
    reader.get_salt()

    assert reader.salt == expected_salt


def test_readline_returns_chunk_when_file_is_closed(reader):
    reader.fileOpen = False
    reader.stream = "FooBar\nBaz"
    chunk = reader.readline() 

    assert chunk == 'FooBar\n'
    assert reader.streamLines == -1
    assert reader.prev_stream == chunk


def test_readline_decrypts_returns_chunk(reader, mock_open):
    reader.chunk_unprocessed = 'Something'
    reader.fObj.read.return_value = ''
    reader.stream = "FooBar\nBaz"
    chunk = reader.readline()

    assert chunk == 'FooBar\n'
    assert reader.streamLines == -1
    assert reader.prev_stream == chunk


def test_readline_does_not_set_prev_stream(reader, mock_open):
    reader.chunk_unprocessed = 'Something'
    reader.fObj.read.return_value = ''
    reader.stream = "FooBar\nBaz"
    reader.enableSeek = False
    chunk = reader.readline()

    assert chunk == 'FooBar\n'
    assert reader.streamLines == -1
    assert reader.prev_stream == ''


def test_read_returns_chunk_when_file_is_closed(reader):
    reader.fileOpen = False
    reader.stream = "FooBar\nBaz"
    chunk = reader.read(2)

    assert chunk == "Fo"
    assert reader.streamLines == 0
    assert reader.prev_stream == chunk


def test_read_decrypts_returns_chunk(reader, mock_open):
    reader.stream = "FooBar\nBaz"
    chunk = reader.read(2)

    assert chunk == 'Fo'
    assert reader.streamLines == 0
    assert reader.prev_stream == chunk


def test_read_does_not_set_prev_stream(reader, mock_open):
    reader.stream = "FooBar\nBaz"
    reader.enableSeek = False
    chunk = reader.read(2)

    assert chunk == 'Fo'
    assert reader.streamLines == 0
    assert reader.prev_stream == ''


def test_read_decrypts_chunk_when_size_larger_than_stream(reader, mock_open):
    expected_chunk = "FooBar\nBaz"
    reader.stream = expected_chunk
    chunk = reader.read(len(reader.stream) + 1)

    assert chunk == expected_chunk + '\x03'
    assert reader.streamLines == 0
    assert reader.prev_stream == expected_chunk + '\x03'


def test_read_with_no_size_gets_whole_stream(reader, mock_open):
    reader.chunk_unprocessed = ''
    expected_chunk = 'FooBar\nBaz\x03\x85\xd3\xf4'
    reader.fObj.read.side_effect = ('Salted__asdfghj\n', '')
    reader.stream = "FooBar\nBaz"
    chunk = reader.read()

    assert chunk == expected_chunk
    assert reader.streamLines == 0
    assert reader.prev_stream == expected_chunk


def test_seek_raises_error_when_enableSeek_False(reader):
    reader.enableSeek = False
    with pytest.raises(NotImplementedError):
        reader.seek(1)


def test_seek_eof_raises_error(reader):
    with pytest.raises(IOError):
        reader.seek(1, mode=2)


def test_seek_with_unknown_mode_raises_error(reader):
    with pytest.raises(IOError):
        reader.seek(1, mode=34)


def test_seek_with_mode_zero_reads_position_in_stream(reader):
    reader.prev_stream = "Foo"
    reader.seek(1)

    assert reader.stream == 'oo'
    assert reader.prev_stream == 'F'


def test_seek_with_mode_one_reads_stream(reader):
    reader.prev_stream = "Foo"
    reader.seek(1, mode=1)

    assert reader.stream != ''
    assert reader.prev_stream == 'Foo\x03'


def test_decrypt_chunk_appends_steam_one_line(reader):
    expected_stream = 'Bar'
    reader.chunk_unprocessed = expected_stream
    reader.fObj.read.return_value = '1' * 16
    reader.decrypt_chunk()

    assert reader.stream == expected_stream
    assert reader.streamLines == 0
    assert reader.fileOpen


def test_decrypt_chunk_appends_steam_two_line(reader):
    expected_stream = 'Bar\nBaz'
    reader.chunk_unprocessed = expected_stream
    reader.fObj.read.return_value = '1' * 16
    reader.decrypt_chunk()

    assert reader.stream == expected_stream
    assert reader.streamLines == 1
    assert reader.fileOpen


def test_decrypt_chunk_processes_chunk_when_no_cipher_left(reader):
    expected_stream = '1' * 128
    reader.chunk_unprocessed = expected_stream
    reader.fObj.read.return_value = ''
    reader.decrypt_chunk()

    assert reader.stream == expected_stream[:-49]
    assert reader.streamLines == 0
    assert not reader.fileOpen
