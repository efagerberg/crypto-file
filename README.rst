A file handlers that read and write encryptes files.


.. image:: https://secure.travis-ci.org/efagerberg/crypto-file.png
    :target: https://secure.travis-ci.org/efagerberg/crypto-file/


Requirements
============

- Python 2.7

Usage
=====

Reading
-------

.. code-block:: python

    from crypto_file import Reader
    with Reader(fname='file.txt', password='Foo') as f:
        f.read()

Writing
-------

.. code-block:: python

    from crypto_file import Writer
    with Writer(fname='file.txt', password='Foo') as f:
        f.write("Some secret stuff")