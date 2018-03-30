import base64

import mock
import pytest

from crypto_file.crypto_handler import CryptoHandler


@pytest.fixture()
def mock_open():
    with mock.patch('crypto_file.crypto_handler.open') as m:
        yield m


def asset_good_handler(handler, mock_open, expected_fname, expected_mode):
    assert handler.mode == expected_mode
    assert handler.fileOpen is True
    assert handler.stream == ''
    assert handler.key is not None
    assert handler.passwrd == base64.b64encode(handler.key)

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


@pytest.fixture()
def handler(mock_open):
    yield CryptoHandler(fname='foo.txt',
                        mode='rb',
                        password='foo')


@pytest.fixture()
def mock_b64():
    with mock.patch('crypto_file.crypto_handler.base64', autospec=True) as m:
        yield m


def test_gen_key_with_provided_keyfile_no_new_key(handler, mock_open, mock_b64):
    handler.key = 'keyfile.key'
    handler.gen_key()

    assert handler.key == mock_open.return_value.read.return_value
    assert handler.passwrd == mock_b64.b64encode.return_value
    mock_b64.b64encode.assert_called_once_with(handler.key)
    expected_calls = [mock.call('foo.txt', 'rb'),
                      mock.call('keyfile.key', 'rb')]
    mock_open.assert_has_calls(expected_calls)
