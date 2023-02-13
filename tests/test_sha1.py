"""
:Authors: cykooz
:Date: 11.02.2023
"""
import hashlib
import random

import pytest

from cykooz.rehash import Sha1


@pytest.mark.parametrize(
    ['data', 'digest'],
    [
        (b'The quick brown fox jumps over the lazy dog',
         '2fd4e1c67a2d28fced849ee1bb76e7391b93eb12'),
        (b'The quick brown fox jumps over the lazy cog',
         'de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3'),
        (b'', 'da39a3ee5e6b4b0d3255bfef95601890afd80709'),
        (b'testing\n', '9801739daae44ec5293d4e1f53d3f4d2d426d91c'),
        (b'x' * 57, '025ecbd5d70f8fb3c5457cd96bab13fda305dc59'),
        (b'x' * 119, '4300320394f7ee239bcdce7d3b8bcee173a0cd5c'),
        (b'x' * 55, 'cef734ba81a024479e09eb5a75b6ddae62e6abf1'),
    ]
)
def test_simple(data, digest):
    hasher = Sha1()
    hasher.update(data)
    assert hasher.hexdigest() == digest


def test_multiple_updates():
    hasher = Sha1()
    hasher.update(b'The quick brown ')
    hasher.update(b'fox jumps over ')
    hasher.update(b'the lazy dog')
    digest = hasher.hexdigest()
    assert digest == '2fd4e1c67a2d28fced849ee1bb76e7391b93eb12'


def test_sha1_loop():
    hasher = Sha1()
    for _ in range(3):
        hasher.reset()
        for _ in range(1000):
            hasher.update(b'The quick brown fox jumps over the lazy dog.')
        assert hasher.hexdigest() == '7ca27655f67fceaa78ed2e645a81c7f1d6e249d2'


def test_spray_and_pray():
    hasher = Sha1()
    for _ in range(20):
        std_hasher = hashlib.sha1()
        hasher.reset()
        for _ in range(50):
            buf_size = random.randint(0, 512)
            buf = b''.join(
                random.randint(0, 255).to_bytes(1, 'little')
                for _ in range(buf_size)
            )
            hasher.update(buf)
            std_hasher.update(buf)
        assert hasher.digest() == std_hasher.digest()


def test_serialize_deserialize_hash():
    hasher = Sha1()
    hasher.update(b'x' * 78)
    state = hasher.serialize()
    assert len(state) == 94

    new_hasher = Sha1.deserialize(state)
    new_hasher.update(b'x' * 41)
    digest = new_hasher.hexdigest()
    assert digest == '4300320394f7ee239bcdce7d3b8bcee173a0cd5c'


def test_deserialize_from_invalid_state():
    assert Sha1.deserialize(b'') is None
    assert Sha1.deserialize(b'x' * 94) is None
    assert Sha1.deserialize(b'\0x01' + b'0xff' * 100) is None
