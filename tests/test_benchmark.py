"""
:Authors: cykooz
:Date: 11.02.2023
"""
import hashlib

import pytest
from pytest_benchmark.stats import Metadata

from cykooz.rehash import Sha1
from utils import BenchResults


@pytest.fixture(name='results', scope='session')
def results_fixture():
    results = BenchResults()
    yield results
    print()
    results.print_table()


def update_hasher(hasher, data: bytes):
    for _ in range(100):
        hasher.update(data)


@pytest.mark.parametrize(
    ['hasher_cls', 'name'],
    [
        (Sha1, 'rehash'),
        (hashlib.sha1, 'std'),
    ],
    ids=['rehash', 'std']
)
def test_bench(benchmark, hasher_cls, name, results: BenchResults):
    data = b'*' * (256 * 1024)

    def setup():
        return (hasher_cls(), data), {}

    benchmark.pedantic(update_hasher, setup=setup, rounds=20, warmup_rounds=3)

    stats: Metadata = benchmark.stats
    value = stats.stats.mean * 1000
    results.add(f'{name} sha1', 'time (ms)', f'{value:.2f}')
