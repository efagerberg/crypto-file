import base64

import mock
import pytest

from crypto_file.writer import Writer


@pytest.fixture()
def mock_open():
    with mock.patch('__builtin__.open') as m:
        yield m


@pytest.fixture()
def writer(mock_open):
    writer = Writer(fname='foo.txt',
                    password='foo')
    mock_open.reset_mock()
    yield writer


def test_init_generates_expected_attributes(writer, mock_open):
    assert writer.salt is not None
    assert writer.iv is not None
    assert writer.cipher is not None


def test_init_creates_savekey_file(writer, mock_open):
    expected_file = 'foo.key'
    writer.__init__(fname='foo.txt', password='foo',
                    saveKey_file=expected_file)

    last_open_call = mock_open.call_args_list[-1]
    assert last_open_call == mock.call(expected_file, 'wb')


def test_gen_key_generates_key_w_no_initial_key_and_pass(writer, mock_open):
    writer.key = None
    writer.password = None
    writer.gen_key()

    assert writer.key is not None
    assert writer.password == base64.b64encode(writer.key)


def test_gen_key_generates_key_without_initial_key_only(writer, mock_open):
    writer.key = None
    writer.gen_key()

    assert writer.key is not None
    assert writer.password == base64.b64encode(writer.key)


def test_get_salt_generates_salt(writer, mock_open):
    writer.salt = None
    writer.get_salt()

    assert writer.salt is not None


def test_write_adds_input_to_steam_and_checks_buffer(writer):
    path = 'crypto_file.writer.Writer.check_write_buffer'
    with mock.patch(path) as m:
        writer.write("Foo")

    m.assert_called_once()
    assert writer.stream == "Foo"


def test_check_write_buffer_with_large_enough_stream(writer):
    writer.fObj = mock.Mock(spec=file)
    writer.stream = '1' * 1024 * writer.bs
    writer.check_write_buffer()

    writer.fObj.write.assert_called_once()
    assert writer.stream == ''


def test_close_does_nothing_when_file_already_closed(writer):
    writer.fObj = mock.Mock(spec=file)
    writer.fObj.closed = True
    writer.close()

    assert not writer.fObj.write.called
    assert not writer.stream


def test_close_handles_partial_stream(writer):
    writer.fObj = mock.Mock(spec=file)
    writer.fObj.closed = False
    # A partial stream
    writer.stream = '1' * (writer.bs + 1)
    writer.close()

    writer.fObj.write.assert_called_once()
    writer.fObj.close.assert_called_once()
    assert writer.stream != writer.bs * chr(writer.bs)


def test_close_with_no_partial_stream_writes_to_file(writer):
    writer.fObj = mock.Mock(spec=file)
    writer.fObj.closed = False
    writer.close()

    writer.fObj.write.assert_called_once()
    writer.fObj.close.assert_called_once()
    assert writer.stream == writer.bs * chr(writer.bs)
