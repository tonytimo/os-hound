import pytest
import unittest
from os_hound.scoring import Scoring


class TestScoring(unittest.TestCase):

    def test_scoring(self):
        # Arrange
        profile_os = {'SEQ': {'SP': 160, 'GCD': 1, 'ISR': 159, 'TI': 'I', 'CI': 'I', 'TS': '1'},
                           'OPS': {'O1': 'Mffd7NW8ST11', 'O2': 'Mffd7NW8ST11', 'O3': 'Mffd7NW8NNT11', 'O4': 'Mffd7NW8ST11', 'O5': 'Mffd7NW8ST11',
                                   'O6': 'Mffd7ST11'},
                           'WIN': {'W1': 65535, 'W2': 65535, 'W3': 65535, 'W4': 65535, 'W5': 65535, 'W6': 65500},
                           'ECN': {'R': 'Y', 'DF': 'Y', 'T': 192, 'TG': 128, 'W': 65535, 'O': "M0xNW8NNSb''", 'CC': 'N', 'Q': ''},
                           'T1': {'R': 'Y', 'DF': 'Y', 'T': 192, 'TG': 128, 'S': 'O', 'A': 'O', 'F': 'AS', 'RD': 0, 'Q': ''},
                           'T2': {'R': 'Y', 'DF': 'Y', 'T': 192, 'TG': 128, 'W': 0, 'S': 'Z', 'F': 'AR', 'RD': 0, 'Q': ''},
                           'T3': {'R': 'Y', 'DF': 'Y', 'T': 192, 'TG': 128, 'W': 0, 'S': 'Z', 'F': 'AR', 'RD': 0, 'Q': ''},
                           'T4': {'R': 'Y', 'DF': 'Y', 'T': 192, 'TG': 128, 'W': 0, 'S': 'Z', 'F': 'R', 'RD': 0, 'Q': ''},
                           'T5': {'R': 'Y', 'DF': 'N', 'T': 192, 'TG': 128, 'W': 65535, 'S': 'Z', 'F': 'AS', 'RD': 0, 'Q': ''},
                           'T6': {'R': 'Y', 'DF': 'Y', 'T': 192, 'TG': 128, 'W': 0, 'S': 'Z', 'F': 'R', 'RD': 0, 'Q': ''},
                           'T7': {'R': 'Y', 'DF': 'Y', 'T': 192, 'TG': 128, 'W': 0, 'S': 'Z', 'F': 'AR', 'RD': 0, 'Q': ''},
                           'U1': {'R': 'Y', 'DF': 'N', 'T': 192, 'TG': 128, 'IPL': 56, 'UN': None, 'RIPL': 'G', 'RID': 'G', 'RIPCK': 'G', 'RUCK': '0xa278',
                                  'RUD': 'G'},
                           'IE': {'R': 'Y', 'DFI': 'N', 'T': 192, 'TG': 128, 'CD': 'Z'}}
        os_dicts = [
            {'SEQ': {'SP': '0-5', 'GCD': '51E80C|A3D018|F5B824|147A030|199883C', 'ISR': 'C8-D2', 'TI': 'I|RD', 'CI': 'I', 'II': 'RI', 'SS': 'S', 'TS': 'U'},
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
             'os_title': ' Fingerprint 2N Helios IP VoIP doorbell Class 2N | embedded || specialized CPE cpe:/h:2n:helios'},
            {'SEQ': {'SP': '6A-BE', 'GCD': '1-6', 'ISR': '96-A0', 'TI': 'I', 'CI': 'I', 'II': 'I', 'SS': 'S', 'TS': 'A'},
             'OPS': {'O1': 'M5B4NNSW0NNNT11', 'O2': 'M578NNSW0NNNT11', 'O3': 'M280W0NNNT11', 'O4': 'M218NNSW0NNNT11', 'O5': 'M218NNSW0NNNT11',
                     'O6': 'M109NNSNNT11'}, 'WIN': {'W1': '8000', 'W2': '8000', 'W3': '8000', 'W4': '8000', 'W5': '8000', 'W6': '8000'},
             'ECN': {'R': 'Y', 'DF': 'Y', 'T': 'FA-104', 'TG': 'FF', 'W': '8000', 'O': 'M5B4NNSW0N', 'CC': 'N', 'Q': ''},
             'T1': {'R': 'Y', 'DF': 'Y', 'T': 'FA-104', 'TG': 'FF', 'S': 'O', 'A': 'S+', 'F': 'AS', 'RD': '0', 'Q': ''}, 'T2': {'R': 'N'}, 'T3': {'R': 'N'},
             'T4': {'R': 'Y', 'DF': 'Y', 'T': 'FA-104', 'TG': 'FF', 'W': '0', 'S': 'A', 'A': 'Z', 'F': 'R', 'O': '', 'RD': 'E44A4E43', 'Q': ''},
             'T5': {'R': 'Y', 'DF': 'Y', 'T': 'FA-104', 'TG': 'FF', 'W': '0', 'S': 'Z', 'A': 'S+', 'F': 'AR', 'O': '', 'RD': '1F59B3D4', 'Q': ''},
             'T6': {'R': 'Y', 'DF': 'Y', 'T': 'FA-104', 'TG': 'FF', 'W': '0', 'S': 'A', 'A': 'Z', 'F': 'R', 'O': '', 'RD': '1F59B3D4', 'Q': ''},
             'T7': {'R': 'N'},
             'U1': {'DF': 'Y', 'T': 'FA-104', 'TG': 'FF', 'IPL': '70', 'UN': '0', 'RIPL': 'G', 'RID': 'G', 'RIPCK': 'G', 'RUCK': 'G', 'RUD': 'G'},
             'IE': {'DFI': 'Y', 'T': 'FA-104', 'TG': 'FF', 'CD': 'S'},
             'os_title': ' Fingerprint 2Wire BT2700HG-V ADSL modem Class 2Wire | embedded || broadband router CPE cpe:/h:2wire:bt2700hg-v'}
        ]

        instance = Scoring()

        # Act
        result = instance.score(profile_os, os_dicts)

        # Assert
        assert (result[0][0]['os_title'], ' Fingerprint 2N Helios IP VoIP doorbell Class 2N | embedded || specialized CPE cpe:/h:2n:helios')


if __name__ == "__main__":
    pytest.main()
