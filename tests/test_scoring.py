import pytest
import unittest
from os_hound.scoring import Scoring


class TestScoring(unittest.TestCase):

    def test_scoring(self):
        # Arrange
        profile_os = {'SEQ': {'SP': 273, 'GCD': 1, 'ISR': 266, 'TI': 'I', 'CI': 'I', 'II': 'I', 'SS': 'S', 'TS': 10},
                      'OPS': {'O1': 'MFFD7NW8ST11', 'O2': 'MFFD7NW8ST11', 'O3': 'MFFD7NW8NNT11', 'O4': 'MFFD7NW8ST11', 'O5': 'MFFD7NW8ST11', 'O6': 'MFFD7ST11'},
                      'WIN': {'W1': 65535, 'W2': 65535, 'W3': 65535, 'W4': 65535, 'W5': 65535, 'W6': 65500},
                      'ECN': {'R': 'Y', 'DF': 'Y', 'T': 128, 'TG': 128, 'W': 65535, 'O': 'MFFD7NW8NNS', 'CC': 'N', 'Q': ''},
                      'T1': {'R': 'Y', 'DF': 'Y', 'T': 128, 'TG': 128, 'S': 'O', 'A': 'S+', 'F': 'AS', 'RD': 0, 'Q': ''},
                      'T2': {'R': 'Y', 'DF': 'Y', 'T': 128, 'TG': 128, 'W': 0, 'S': 'Z', 'A': 'Z', 'F': 'AR', 'RD': 0, 'Q': ''},
                      'T3': {'R': 'Y', 'DF': 'Y', 'T': 128, 'TG': 128, 'W': 0, 'S': 'Z', 'A': 'O', 'F': 'AR', 'RD': 0, 'Q': ''},
                      'T4': {'R': 'Y', 'DF': 'Y', 'T': 128, 'TG': 128, 'W': 0, 'S': 'Z', 'A': 'Z', 'F': 'R', 'RD': 0, 'Q': ''},
                      'T5': {'R': 'Y', 'DF': 'Y', 'T': 128, 'TG': 128, 'W': 0, 'S': 'Z', 'A': 'S+', 'F': 'AR', 'RD': 0, 'Q': ''},
                      'T6': {'R': 'Y', 'DF': 'Y', 'T': 128, 'TG': 128, 'W': 0, 'S': 'Z', 'A': 'Z', 'F': 'R', 'RD': 0, 'Q': ''},
                      'T7': {'R': 'Y', 'DF': 'Y', 'T': 128, 'TG': 128, 'W': 0, 'S': 'Z', 'A': 'S+', 'F': 'AR', 'RD': 0, 'Q': ''},
                      'U1': {'R': 'Y', 'DF': 'N', 'T': 128, 'TG': 128, 'IPL': 356, 'UN': 0, 'RIPL': 'G', 'RID': 'G', 'RIPCK': 'G', 'RUCK': 'G', 'RUD': 'G'},
                      'IE': {'R': 'Y', 'DFI': 'N', 'T': 128, 'TG': 128, 'CD': 'Z'}}

        os_dicts = [
            {'SEQ': {'SP': 'FE-108', 'GCD': '1-6', 'ISR': '102-10C', 'TI': 'I', 'CI': 'I', 'II': 'I', 'SS': 'S', 'TS': 'A'},
             'OPS': {'O1': 'M5B4ST11', 'O2': 'M5B4ST11', 'O3': 'M5B4NNT11', 'O4': 'M5B4ST11', 'O5': 'M5B4ST11', 'O6': 'M5B4ST11'},
             'WIN': {'W1': 'FE88', 'W2': 'FED4', 'W3': 'FF20', 'W4': 'FFDC', 'W5': 'FFDC', 'W6': 'FFDC'},
             'ECN': {'R': 'Y', 'DF': 'Y', 'T': '7B-85', 'TG': '80', 'W': 'FAF0', 'O': 'M5B4NNS', 'CC': 'N', 'Q': ''},
             'T1': {'R': 'Y', 'DF': 'Y', 'T': '7B-85', 'TG': '80', 'S': 'O', 'A': 'S+', 'F': 'AS', 'RD': '0', 'Q': ''},
             'T2': {'R': 'Y', 'DF': 'Y', 'T': '7B-85', 'TG': '80', 'W': '0', 'S': 'Z', 'A': 'S', 'F': 'AR', 'O': '', 'RD': '0', 'Q': ''},
             'T3': {'R': 'Y', 'DF': 'Y', 'T': '7B-85', 'TG': '80', 'W': '0', 'S': 'Z', 'A': 'O', 'F': 'AR', 'O': '', 'RD': '0', 'Q': ''},
             'T4': {'R': 'Y', 'DF': 'Y', 'T': '7B-85', 'TG': '80', 'W': '0', 'S': 'A', 'A': 'O', 'F': 'R', 'O': '', 'RD': '0', 'Q': ''},
             'T5': {'R': 'Y', 'DF': 'Y', 'T': '7B-85', 'TG': '80', 'W': '0', 'S': 'Z', 'A': 'S+', 'F': 'AR', 'O': '', 'RD': '0', 'Q': ''},
             'T6': {'R': 'Y', 'DF': 'Y', 'T': '7B-85', 'TG': '80', 'W': '0', 'S': 'A', 'A': 'O', 'F': 'R', 'O': '', 'RD': '0', 'Q': ''},
             'T7': {'R': 'Y', 'DF': 'Y', 'T': '7B-85', 'TG': '80', 'W': '0', 'S': 'Z', 'A': 'S+', 'F': 'AR', 'O': '', 'RD': '0', 'Q': ''},
             'U1': {'DF': 'N', 'T': '7B-85', 'TG': '80', 'IPL': '164', 'UN': '0', 'RIPL': 'G', 'RID': 'G', 'RIPCK': 'G', 'RUCK': 'G', 'RUD': 'G'},
             'IE': {'DFI': 'N', 'T': '7B-85', 'TG': '80', 'CD': ''}, 'os_title': 'Fingerprint Microsoft Windows 11 21H2',
             'os_info': 'Class Microsoft | Windows | 11 | general purpose', 'os_cpe': '', 'os_description': '',
             'description': ['# Microsoft Windows Version 21H2 (OS Build 22000.434)']},
            {'SEQ': {'SP': 'FE-108', 'GCD': '1-6', 'ISR': '107-111', 'TI': 'I', 'II': 'I', 'SS': 'S', 'TS': 'A'},
             'OPS': {'O1': 'M5B4NW8ST11', 'O2': 'M5B4NW8ST11', 'O3': 'M5B4NW8NNT11', 'O4': 'M5B4NW8ST11', 'O5': 'M5B4NW8ST11', 'O6': 'M5B4ST11'},
             'WIN': {'W1': 'FFFF', 'W2': 'FFFF', 'W3': 'FFFF', 'W4': 'FFFF', 'W5': 'FFFF', 'W6': 'FFDC'},
             'ECN': {'R': 'Y', 'DF': 'Y', 'T': '7B-85', 'TG': '80', 'W': 'FFFF', 'O': 'M5B4NW8NNS', 'CC': 'N', 'Q': ''},
             'T1': {'R': 'Y', 'DF': 'Y', 'T': '7B-85', 'TG': '80', 'S': 'O', 'A': 'S+', 'F': 'AS', 'RD': '0', 'Q': ''}, 'T2': {'R': 'N'}, 'T3': {'R': 'N'},
             'T4': {'R': 'N'}, 'T5': {'R': 'Y', 'DF': 'Y', 'T': '7B-85', 'TG': '80', 'W': '0', 'S': 'Z', 'A': 'S+', 'F': 'AR', 'O': '', 'RD': '0', 'Q': ''},
             'T6': {'R': 'N'}, 'T7': {'R': 'N'},
             'U1': {'DF': 'N', 'T': '7B-85', 'TG': '80', 'IPL': '164', 'UN': '0', 'RIPL': 'G', 'RID': 'G', 'RIPCK': 'G', 'RUCK': 'G', 'RUD': 'G'},
             'IE': {'DFI': 'N', 'T': '7B-85', 'TG': '80', 'CD': 'Z'}, 'os_title': 'Fingerprint Microsoft Windows 11 21H2',
             'os_info': 'Class Microsoft | Windows | 11 | general purpose', 'os_cpe': '', 'os_description': '',
             'description': ['# Windows 11 Version 21H2 (OS Build 22000.708']},
            {'SEQ': {'SP': '100-10A', 'GCD': '1-6', 'ISR': '101-10B', 'TI': 'I', 'CI': 'I', 'II': 'I', 'SS': 'S', 'TS': 'A'},
             'OPS': {'O1': 'MFFD7ST11', 'O2': 'MFFD7ST11', 'O3': 'MFFD7NNT11', 'O4': 'MFFD7ST11', 'O5': 'MFFD7ST11', 'O6': 'MFFD7ST11'},
             'WIN': {'W1': 'FE88', 'W2': 'FED4', 'W3': 'FF20', 'W4': 'FFDC', 'W5': 'FFDC', 'W6': 'FFDC'},
             'ECN': {'R': 'Y', 'DF': 'Y', 'T': '7B-85', 'TG': '80', 'W': 'FAF0', 'O': 'MFFD7NNS', 'CC': 'N', 'Q': ''},
             'T1': {'R': 'Y', 'DF': 'Y', 'T': '7B-85', 'TG': '80', 'S': 'O', 'A': 'S+', 'F': 'AS', 'RD': '0', 'Q': ''},
             'T2': {'R': 'Y', 'DF': 'Y', 'T': '7B-85', 'TG': '80', 'W': '0', 'S': 'Z', 'A': 'S', 'F': 'AR', 'O': '', 'RD': '0', 'Q': ''},
             'T3': {'R': 'Y', 'DF': 'Y', 'T': '7B-85', 'TG': '80', 'W': '0', 'S': 'Z', 'A': 'O', 'F': 'AR', 'O': '', 'RD': '0', 'Q': ''},
             'T4': {'R': 'Y', 'DF': 'Y', 'T': '7B-85', 'TG': '80', 'W': '0', 'S': 'A', 'A': 'O', 'F': 'R', 'O': '', 'RD': '0', 'Q': ''},
             'T5': {'R': 'Y', 'DF': 'Y', 'T': '7B-85', 'TG': '80', 'W': '0', 'S': 'Z', 'A': 'S+', 'F': 'AR', 'O': '', 'RD': '0', 'Q': ''},
             'T6': {'R': 'Y', 'DF': 'Y', 'T': '7B-85', 'TG': '80', 'W': '0', 'S': 'A', 'A': 'O', 'F': 'R', 'O': '', 'RD': '0', 'Q': ''},
             'T7': {'R': 'Y', 'DF': 'Y', 'T': '7B-85', 'TG': '80', 'W': '0', 'S': 'Z', 'A': 'S+', 'F': 'AR', 'O': '', 'RD': '0', 'Q': ''},
             'U1': {'DF': 'N', 'T': '7B-85', 'TG': '80', 'IPL': '164', 'UN': '0', 'RIPL': 'G', 'RID': 'G', 'RIPCK': 'Z', 'RUCK': 'G', 'RUD': 'G'},
             'IE': {'DFI': 'N', 'T': '7B-85', 'TG': '80', 'CD': 'Z'}, 'os_title': 'Fingerprint Microsoft Windows 11 21H2',
             'os_info': 'Class Microsoft | Windows | 11 | general purpose', 'os_cpe': '', 'os_description': '', 'description': ['# Windows 11']},
            {'SEQ': {'SP': 'E8-F2', 'GCD': '1-6', 'ISR': '105-10F', 'TI': 'I', 'CI': 'I', 'II': 'I', 'SS': 'S', 'TS': 'U'},
             'OPS': {'O1': 'MFFD7NW8NNS', 'O2': 'MFFD7NW8NNS', 'O3': 'MFFD7NW8', 'O4': 'MFFD7NW8NNS', 'O5': 'MFFD7NW8NNS', 'O6': 'MFFD7NNS'},
             'WIN': {'W1': 'FFFF', 'W2': 'FFFF', 'W3': 'FFFF', 'W4': 'FFFF', 'W5': 'FFFF', 'W6': 'FF70'},
             'ECN': {'R': 'Y', 'DF': 'Y', 'T': '7B-85', 'TG': '80', 'W': 'FFFF', 'O': 'MFFD7NW8NNS', 'CC': 'N', 'Q': ''},
             'T1': {'R': 'Y', 'DF': 'Y', 'T': '7B-85', 'TG': '80', 'S': 'O', 'A': 'S+', 'F': 'AS', 'RD': '0', 'Q': ''},
             'T2': {'R': 'Y', 'DF': 'Y', 'T': '7B-85', 'TG': '80', 'W': '0', 'S': 'Z', 'A': 'S', 'F': 'AR', 'O': '', 'RD': '0', 'Q': ''},
             'T3': {'R': 'Y', 'DF': 'Y', 'T': '7B-85', 'TG': '80', 'W': '0', 'S': 'Z', 'A': 'O', 'F': 'AR', 'O': '', 'RD': '0', 'Q': ''},
             'T4': {'R': 'Y', 'DF': 'Y', 'T': '7B-85', 'TG': '80', 'W': '0', 'S': 'A', 'A': 'O', 'F': 'R', 'O': '', 'RD': '0', 'Q': ''},
             'T5': {'R': 'Y', 'DF': 'Y', 'T': '7B-85', 'TG': '80', 'W': '0', 'S': 'Z', 'A': 'S+', 'F': 'AR', 'O': '', 'RD': '0', 'Q': ''},
             'T6': {'R': 'Y', 'DF': 'Y', 'T': '7B-85', 'TG': '80', 'W': '0', 'S': 'A', 'A': 'O', 'F': 'R', 'O': '', 'RD': '0', 'Q': ''},
             'T7': {'R': 'Y', 'DF': 'Y', 'T': '7B-85', 'TG': '80', 'W': '0', 'S': 'Z', 'A': 'S+', 'F': 'AR', 'O': '', 'RD': '0', 'Q': ''},
             'U1': {'DF': 'N', 'T': '7B-85', 'TG': '80', 'IPL': '164', 'UN': '0', 'RIPL': 'G', 'RID': 'G', 'RIPCK': 'Z', 'RUCK': 'G', 'RUD': 'G'},
             'IE': {'DFI': 'N', 'T': '7B-85', 'TG': '80', 'CD': ''}, 'os_title': 'Fingerprint Microsoft Windows 11 21H2',
             'os_info': 'Class Microsoft | Windows | 11 | general purpose', 'os_cpe': '', 'os_description': '',
             'description': ['# Localhost: Windows 11, Version 21H2 (OS Build 22000.856)']}]

        instance = Scoring()

        # Act
        result = instance.score(profile_os, os_dicts)

        # Assert
        assert (result[0][0]['os_title'], 'Fingerprint Microsoft Windows 11 21H2')


if __name__ == "__main__":
    pytest.main()
