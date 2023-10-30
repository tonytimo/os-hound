import pytest
import unittest
from os_hound.db_parser import DbParser


class TestDbParser(unittest.TestCase):
    def test_parse_db(self):
        # Act
        parser = DbParser()
        res = parser.parse_db()
        print(res)

        # Assert
        assert res is not None
        assert res[0] == {
            'SEQ': {'SP': '0-5', 'GCD': '51E80C|A3D018|F5B824|147A030|199883C', 'ISR': 'C8-D2', 'TI': 'I|RD', 'CI': 'I', 'II': 'RI', 'SS': 'S', 'TS': 'U'},
            'OPS': {'O1': 'M5B4', 'O2': 'M5B4', 'O3': 'M5B4', 'O4': 'M5B4', 'O5': 'M5B4', 'O6': 'M5B4'},
            'WIN': {'W1': '8000', 'W2': '8000', 'W3': '8000', 'W4': '8000', 'W5': '8000', 'W6': '8000'},
            'ECN': {'R': 'Y', 'DF': 'N', 'T': 'FA-104', 'TG': 'FF', 'W': '8000', 'O': 'M5B4', 'CC': 'N', 'Q': ''},
            'T1': {'R': 'Y', 'DF': 'N', 'T': 'FA-104', 'TG': 'FF', 'S': 'O', 'A': 'S+', 'F': 'AS', 'RD': '0', 'Q': ''}, 'T2': {'R': 'N'},
            'T3': {'R': 'Y', 'DF': 'N', 'T': 'FA-104', 'TG': 'FF', 'W': '8000', 'S': 'O', 'A': 'S+', 'F': 'AS', 'O': 'M5B4', 'RD': '0', 'Q': ''},
            'T4': {'R': 'Y', 'DF': 'N', 'T': 'FA-104', 'TG': 'FF', 'W': '8000', 'S': 'A+', 'A': 'S', 'F': 'AR', 'O': '', 'RD': '0', 'Q': ''},
            'T5': {'R': 'Y', 'DF': 'N', 'T': 'FA-104', 'TG': 'FF', 'W': '8000', 'S': 'A', 'A': 'S+', 'F': 'AR', 'O': '', 'RD': '0', 'Q': ''},
            'T6': {'R': 'Y', 'DF': 'N', 'T': 'FA-104', 'TG': 'FF', 'W': '8000', 'S': 'A', 'A': 'S', 'F': 'AR', 'O': '', 'RD': '0', 'Q': ''},
            'T7': {'R': 'Y', 'DF': 'N', 'T': 'FA-104', 'TG': 'FF', 'W': '8000', 'S': 'A', 'A': 'S+', 'F': 'AR', 'O': '', 'RD': '0', 'Q': ''},
            'U1': {'DF': 'N', 'T': 'FA-104', 'TG': 'FF', 'IPL': '38', 'UN': '0', 'RIPL': 'G', 'RID': 'G', 'RIPCK': 'G', 'RUCK': 'G', 'RUD': 'G'},
            'IE': {'DFI': 'S', 'T': 'FA-104', 'TG': 'FF', 'CD': 'S'},
            'os_title': ' Fingerprint 2N Helios IP VoIP doorbell Class 2N | embedded || specialized CPE cpe:/h:2n:helios'}
        assert res[3] == {'SEQ': {'SP': '5A-A0', 'GCD': '1-6', 'ISR': '98-A9', 'TI': 'I', 'TS': 'A'},
                          'OPS': {'O1': 'M5B4NNSW0NNNT11', 'O2': 'M578NNSW0NNNT11', 'O3': 'M280W0NNNT11', 'O4': 'M218NNSW0NNNT11', 'O5': 'M218NNSW0NNNT11',
                                  'O6': 'M109NNSNNT11'}, 'WIN': {'W1': '8000', 'W2': '8000', 'W3': '8000', 'W4': '8000', 'W5': '8000', 'W6': '8000'},
                          'ECN': {'R': 'Y', 'DF': 'Y', 'T': 'FA-104', 'TG': 'FF', 'W': '8000', 'O': 'M5B4NNSW0N', 'CC': 'N', 'Q': ''},
                          'T1': {'R': 'Y', 'DF': 'Y', 'T': 'FA-104', 'TG': 'FF', 'S': 'O', 'A': 'S+', 'F': 'AS', 'RD': '0', 'Q': ''}, 'T2': {'R': 'N'},
                          'T3': {'R': 'N'},
                          'T4': {'R': 'Y', 'DF': 'Y', 'T': 'FA-104', 'TG': 'FF', 'W': '0', 'S': 'A', 'A': 'Z', 'F': 'R', 'O': '', 'RD': 'E44A4E43', 'Q': ''},
                          'T5': {'R': 'Y', 'DF': 'Y', 'T': 'FA-104', 'TG': 'FF', 'W': '0', 'S': 'Z', 'A': 'S+', 'F': 'AR', 'O': '', 'RD': 'BD1AB510', 'Q': ''},
                          'T6': {'R': 'Y', 'DF': 'Y', 'T': 'FA-104', 'TG': 'FF', 'W': '0', 'S': 'A', 'A': 'Z', 'F': 'R', 'O': '', 'RD': 'EA6C967D', 'Q': ''},
                          'T7': {'R': 'N'},
                          'U1': {'DF': 'Y', 'T': 'FA-104', 'TG': 'FF', 'IPL': '70', 'UN': '0', 'RIPL': 'G', 'RID': 'G', 'RIPCK': 'G', 'RUCK': 'G', 'RUD': 'G'},
                          'IE': {'R': 'N'},
                          'os_title': ' Fingerprint 2Wire 1701HG, 2700HG, 2700HG-B, 2701HG-B, RG2701HG, or 3800HGV-B wireless ADSL modem Class 2Wire | embedded || WAP CPE cpe:/h:2wire:1701hg CPE cpe:/h:2wire:2700hg CPE cpe:/h:2wire:2700hg-b CPE cpe:/h:2wire:2701hg-b CPE cpe:/h:2wire:rg2701hg CPE cpe:/h:2wire:3800hgv-b'}


if __name__ == '__main__':
    pytest.main()
