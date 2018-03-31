import base64

import mock
import pytest

from Crypto.Cipher import AES

from crypto_file.crypto_handler import CryptoHandler


BASE_MOCK_PATH = 'crypto_file.crypto_handler'


@pytest.fixture()
def mock_open():
    with mock.patch('{}.open'.format(BASE_MOCK_PATH)) as m:
        yield m


@pytest.fixture()
def handler(mock_open):
    handler = CryptoHandler(fname='foo.txt',
                            mode='rb',
                            password='foo')
    mock_open.reset_mock()
    yield handler


@pytest.fixture()
def mock_b64():
    with mock.patch('{}.base64'.format(BASE_MOCK_PATH), autospec=True) as m:
        m.b64decode.return_value = '1' * 32
        yield m


@pytest.fixture()
def mock_sha256():
    path = '{}.hashlib.sha256'.format(BASE_MOCK_PATH)
    with mock.patch(path, autospec=True) as m:
        yield m


def asset_good_handler(handler, mock_open, expected_fname, expected_mode):
    assert handler.mode == expected_mode
    assert handler.fileOpen is True
    assert handler.stream == ''
    assert handler.key is not None
    assert handler.password == base64.b64encode(handler.key)

    if isinstance(expected_fname, str):
        mock_open.assert_called_once_with(expected_fname, expected_mode)


def test_handler_constructor_handles_string_fname(mock_open):
    expected_fname = 'test.csv'
    mock_open.return_value.mode = expected_mode = 'r'
    handler = CryptoHandler(fname=expected_fname,
                            mode=expected_mode,
                            password='foo')

    asset_good_handler(handler, mock_open, expected_fname, expected_mode)


def test_handler_constructor_handles_file_fname_with_b(mock_open):
    mock_file = mock.Mock(spec=file)
    mock_file.mode = expected_mode = 'rb'
    handler = CryptoHandler(fname=mock_file,
                            mode=expected_mode,
                            password='foo')

    asset_good_handler(handler, mock_open, mock_file, expected_mode)


def test_handler_constructor_handles_file_fname_without_b(mock_open):
    mock_file = mock.Mock(spec=file)
    mock_file.mode = 'r'
    expected_mode = 'rb'
    mock_open.return_value.mode = expected_mode
    handler = CryptoHandler(fname=mock_file,
                            mode=expected_mode,
                            password='foo')

    asset_good_handler(handler, mock_open, mock_file, expected_mode)


def test_raises_io_error_without_correct_fname():
    with pytest.raises(IOError):
        CryptoHandler(fname=1)


def test_gen_key_handles_key_as_keyfile_sets_pw(handler, mock_open, mock_b64):
    handler.key = 'keyfile.key'
    handler.gen_key()

    assert handler.key == mock_open.return_value.read.return_value
    assert handler.password == mock_b64.b64encode.return_value
    mock_b64.b64encode.assert_called_once_with(handler.key)
    mock_open.assert_called_once_with('keyfile.key', 'rb')


def test_gen_key_handles_key_str(handler, mock_open, mock_b64):
    handler.key = 'foo'
    handler.gen_key()

    assert handler.key == mock_b64.b64decode.return_value
    assert handler.password == mock_b64.b64encode.return_value
    mock_b64.b64encode.assert_called_once_with(handler.key)
    assert not mock_open.called


def test_gen_key_errors_with_non_32_len_key(handler, mock_open, mock_b64):
    handler.key = '1'
    mock_b64.b64decode.return_value = 'NotLongEnough'
    with pytest.raises(NotImplementedError):
        handler.gen_key()

    assert not mock_b64.b64encode.called
    assert not mock_open.called


def test_gen_key_generates_key_from_password(handler, mock_b64):
    handler.gen_key()

    mock_b64.b64encode.assert_called_once_with(handler.key)
    assert handler.password == mock_b64.b64encode.return_value


def test_gen_key_errors_with_invalid_password(handler, mock_b64):
    handler.password = 1234
    handler.key = None
    with pytest.raises(ValueError):
        handler.gen_key()


def test_gen_iv_sets_iv(handler, mock_sha256):
    handler.salt = 'salty'
    mock_sha256.return_value.digest.return_value = b'1'
    handler.gen_iv()

    assert handler.iv == b'1' * AES.block_size


def test_check_mode_passes_if_mode_matches(handler):
    handler.mode = 'rb'

    handler.check_mode('r')
    handler.check_mode('rb')


def test_check_mode_errors_if_mode_does_not_match(handler):
    handler.mode = 'wb'

    with pytest.raises(IOError):
        handler.check_mode('r')


def test_close_closes_file(handler):
    handler.fObj = mock.Mock(spec=file)
    handler.close()

    assert handler.fObj.closed


def test__enter__returns_handler(handler):
    assert handler.__enter__() == handler


def test__exit__closes_file(handler):
    handler.fObj = mock.Mock(spec=file)
    handler.__exit__('foo', 'bar', 'traceback')

    assert handler.fObj.closed


def test__del__closes_file(handler):
    handler.fObj = fObj = mock.Mock(spec=file)
    del handler

    assert fObj.closed
