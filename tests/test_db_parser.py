import pytest
import unittest
from os_hound.db_parser import DbParser


class TestDbParser(unittest.TestCase):
    def test_parse_db(self):
        # Act
        parser = DbParser()
        res = parser.parse_db()

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
            'IE': {'DFI': 'S', 'T': 'FA-104', 'TG': 'FF', 'CD': 'S'}, 'os_title': 'Fingerprint 2N Helios IP VoIP doorbell',
            'os_info': 'Class 2N | embedded || specialized', 'os_cpe': ' CPE cpe:/h:2n:helios', 'os_description': '', 'description': ['# 2N VOIP doorbell']}
        assert res[3]["SEQ"]["SP"] == '5A-A0'
        assert res[3]["ECN"]["O"] == 'M5B4NNSW0N'


if __name__ == '__main__':
    pytest.main()
