import unittest

from src.normalizer import normalize_cellblock


class CellblockNormalizationTest(unittest.TestCase):
    def test_dict_column_range(self):
        cb = normalize_cellblock({"startColumn": 3, "endColumn": 5})
        self.assertEqual(cb["columns"], [3, 4, 5])
        self.assertFalse(cb["invalid"])

    def test_list_form(self):
        cb = normalize_cellblock([{"startColumn": 3}, {"endColumn": 3}])
        self.assertEqual(cb["columns"], [3])
        self.assertFalse(cb["invalid"])

    def test_case_and_spacing_variants(self):
        cb = normalize_cellblock({"START_COLUMN": 3, "End Column": 4})
        self.assertEqual(cb["columns"], [3, 4])
        self.assertFalse(cb["invalid"])

    def test_numeric_field_keys(self):
        cb = normalize_cellblock({"3": 3, "4": 4})
        self.assertEqual(cb["columns"], [3, 4])
        self.assertFalse(cb["invalid"])

    def test_row_only_cellblock_is_valid(self):
        # Byte-table reads address rows, not columns (core/5.3.2.3 Table 168).
        cb = normalize_cellblock({"startRow": 0, "endRow": 511})
        self.assertFalse(cb["invalid"])
        self.assertEqual(cb["columns"], [])
        cb = normalize_cellblock({"1": 0, "2": 511})
        self.assertFalse(cb["invalid"])

    def test_junk_cellblock_invalid(self):
        self.assertTrue(normalize_cellblock({"bogus": 1})["invalid"])
        self.assertTrue(normalize_cellblock("junk")["invalid"])

    def test_none_cellblock(self):
        cb = normalize_cellblock(None)
        self.assertFalse(cb["invalid"])
        self.assertEqual(cb["columns"], [])


if __name__ == "__main__":
    unittest.main()
