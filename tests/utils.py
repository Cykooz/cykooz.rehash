"""
:Authors: cykooz
:Date: 12.08.2021
"""
from collections import defaultdict

from tabulate import tabulate


class BenchResults:

    def __init__(self):
        self.columns = []
        self.rows = defaultdict(dict)

    def add(self, row_name, column_name, value):
        self.rows[row_name][column_name] = value
        if column_name not in self.columns:
            self.columns.append(column_name)

    def print_table(self):
        headers = ['Hasher'] + self.columns
        table = []
        for row_name, columns in self.rows.items():
            row = [row_name]
            for c_name in self.columns:
                row.append(columns.get(c_name, ''))
            table.append(row)
        print(tabulate(
            table,
            headers=headers,
            tablefmt='pipe',
            disable_numparse=True,
            colalign=['left'] + ['right'] * len(self.columns),
        ))
