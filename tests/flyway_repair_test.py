#!/usr/bin/env python3
"""Ensure schema comparison ignores dump randomness without hiding real drift."""
import runpy
import unittest
from pathlib import Path

NORMALIZE = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'scripts/repair-local-flyway.py'))[
    'normalize_dump']


class SchemaComparisonTest(unittest.TestCase):
    def test_pg_dump_random_tokens_do_not_look_like_schema_drift(self):
        first = '\\restrict first\n-- Dumped by pg_dump version 17.12\nCREATE TABLE example (id integer);\n\\unrestrict first\n'
        second = '\\restrict second\n-- Dumped by pg_dump version 17.12\nCREATE TABLE example (id integer);\n\\unrestrict second\n'
        self.assertEqual(NORMALIZE(first), NORMALIZE(second))

    def test_changed_columns_constraints_or_functions_remain_visible(self):
        for definition in ['CREATE TABLE example (id bigint);',
                           'ALTER TABLE example ADD CONSTRAINT required CHECK (id > 0);',
                           'CREATE FUNCTION policy() RETURNS int LANGUAGE sql AS $$ SELECT 2 $$;']:
            self.assertNotEqual(NORMALIZE('CREATE TABLE example (id integer);'), NORMALIZE(definition))


if __name__ == '__main__': unittest.main()
