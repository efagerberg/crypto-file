import base64

import mock
import pytest

from crypto_file.reader import Reader


@pytest.fixture()
def mock_open():
    with mock.patch('__builtin__.open') as m:
        yield m


@pytest.fixture()
def reader(mock_open):
    mock_open.return_value.read.return_value = 'Salted__foooo'
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
    expected_salt = 'foooo'
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
    mock_open.return_value.read.return_value = 'Salted__asdfghj\n'
    reader.stream = "FooBar\nBaz"
    chunk = reader.readline()

    assert chunk == 'FooBar\n'
    assert reader.streamLines == 0
    assert reader.prev_stream == chunk


def test_readline_does_not_set_prev_stream(reader, mock_open):
    mock_open.return_value.read.return_value = 'Salted__asdfghj\n'
    reader.stream = "FooBar\nBaz"
    reader.enableSeek = False
    chunk = reader.readline()

    assert chunk == 'FooBar\n'
    assert reader.streamLines == 0
    assert reader.prev_stream == ''


def test_read_returns_chunk_when_file_is_closed(reader):
    reader.fileOpen = False
    reader.stream = "FooBar\nBaz"
    chunk = reader.read(2)

    assert chunk == "Fo"
    assert reader.streamLines == 0
    assert reader.prev_stream == chunk


def test_read_decrypts_returns_chunk(reader, mock_open):
    mock_open.return_value.read.return_value = 'Salted__asdfghj\n'
    reader.stream = "FooBar\nBaz"
    chunk = reader.read(2)

    assert chunk == 'Fo'
    assert reader.streamLines == 0
    assert reader.prev_stream == chunk


def test_read_does_not_set_prev_stream(reader, mock_open):
    mock_open.return_value.read.return_value = 'Salted__asdfghj\n'
    reader.stream = "FooBar\nBaz"
    reader.enableSeek = False
    chunk = reader.read(2)

    assert chunk == 'Fo'
    assert reader.streamLines == 0
    assert reader.prev_stream == ''


def test_read_decrypts_chunk_when_size_larger_than_stream(reader, mock_open):
    mock_open.return_value.read.return_value = 'Salted__asdfghj\n'
    expected_chunk = "FooBar\nBaz"
    reader.stream = expected_chunk
    chunk = reader.read(len(reader.stream) + 1)

    assert chunk == expected_chunk + '4'
    assert reader.streamLines == 1
    assert reader.prev_stream == expected_chunk + '4'


# def test_read_with_no_size_gets_whole_stream(reader, mock_open):
#     expected_chunk = "FooBar\nBaz"
#     mock_open.return_value.read.return_value = 'Salted__asdfghj\n'
#     reader.stream = expected_chunk
#     chunk = reader.read()

#     assert chunk == reader.stream
#     assert reader.streamLines == 1
#     assert reader.prev_stream == ''
