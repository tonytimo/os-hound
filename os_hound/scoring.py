class Scoring:
    """Class to score the profile against the database and return the most likely OS."""
    def __init__(self):
        self.scoring_dict = {
            'SEQ': {'SP': 25, 'GCD': 75, 'ISR': 25, 'TI': 100, 'CI': 50, 'II': 100, 'SS': 80, 'TS': 100},
            'OPS': {'O1': 20, 'O2': 20, 'O3': 20, 'O4': 20, 'O5': 20, 'O6': 20},
            'WIN': {'W1': 15, 'W2': 15, 'W3': 15, 'W4': 15, 'W5': 15, 'W6': 15},
            'ECN': {'R': 100, 'DF': 20, 'T': 15, 'TG': 15, 'W': 15, 'O': 15, 'CC': 100, 'Q': 20},
            'T1': {'R': 100, 'DF': 20, 'T': 15, 'TG': 15, 'S': 20, 'A': 20, 'F': 30, 'RD': 20, 'Q': 20},
            'T2': {'R': 80, 'DF': 20, 'T': 15, 'TG': 15, 'W': 25, 'S': 20, 'A': 20, 'F': 30, 'O': 10, 'RD': 0, 'Q': 20},
            'T3': {'R': 80, 'DF': 20, 'T': 15, 'TG': 15, 'W': 25, 'S': 20, 'A': 20, 'F': 30, 'O': 10, 'RD': 0, 'Q': 20},
            'T4': {'R': 100, 'DF': 20, 'T': 15, 'TG': 15, 'W': 25, 'S': 20, 'A': 20, 'F': 30, 'O': 10, 'RD': 0, 'Q': 20},
            'T5': {'R': 100, 'DF': 20, 'T': 15, 'TG': 15, 'W': 25, 'S': 20, 'A': 20, 'F': 30, 'O': 10, 'RD': 0, 'Q': 20},
            'T6': {'R': 100, 'DF': 20, 'T': 15, 'TG': 15, 'W': 25, 'S': 20, 'A': 20, 'F': 30, 'O': 10, 'RD': 0, 'Q': 20},
            'T7': {'R': 80, 'DF': 20, 'T': 15, 'TG': 15, 'W': 25, 'S': 20, 'A': 20, 'F': 30, 'O': 10, 'RD': 0, 'Q': 20},
            'U1': {'R': 50, 'DF': 20, 'T': 15, 'TG': 15, 'IPL': 100, 'UN': 100, 'RIPL': 100, 'RID': 100, 'RIPCK': 100, 'RUCK': 100, 'RUD': 100},
            'IE': {'R': 50, 'DFI': 40, 'T': 15, 'TG': 15, 'CD': 100}
        }

    def score(self, profile: dict, os_dicts: list[dict]):
        """
        Score the profile against the  all database and return the best match OS.
        :param profile: The profile OS to score against.
        :param os_dicts: The list of all OS dictionaries in the DataBase.
        :return: The best match OS.
        """
        filed_names = ["SEQ", "OPS", "WIN", "ECN", "T1", "T2", "T3", "T4", "T5", "T6", "T7", "U1", "IE"]
        best_matches = []
        # iterating through all OS dictionaries
        for os_dict in os_dicts:
            score = 0
            # iterating through all fields
            for field in filed_names:
                # checking if the current field is in the profile and the current OS dictionary
                if field in os_dict.keys() and field in profile.keys():
                    # iterating through all keys in the current field
                    for key in profile[field].keys():
                        # checking if the current key is in the profile and the current OS dictionary
                        if key in os_dict[field].keys():
                            # STRING
                            if isinstance(profile[field][key], str):
                                # Checking for symbols in the current value
                                if "|" in os_dict[field][key]:
                                    temp = os_dict[field][key].split("|")
                                    if profile[field][key] in temp:
                                        score += self.__check_score(field, key)
                                elif profile[field][key] == os_dict[field][key]:
                                    score += self.__check_score(field, key)
                            # INTEGER
                            elif isinstance(profile[field][key], int):
                                # Checking for symbols in the current value
                                if "|" in os_dict[field][key]:
                                    temp = os_dict[field][key].split("|")
                                    for t in temp:
                                        if "-" in t:
                                            temp_2 = t.split("-")
                                            if profile[field][key] in range(int(temp_2[0], 16), int(temp_2[1], 16)):
                                                score += self.__check_score(field, key)
                                                break
                                            continue
                                        elif ">" in t:
                                            temp_2 = t.strip(">")
                                            if profile[field][key] > int(temp_2, 16):
                                                score += self.__check_score(field, key)
                                                break
                                        elif profile[field][key] == int(t, 16):
                                            score += self.__check_score(field, key)
                                            break
                                elif "-" in os_dict[field][key]:
                                    temp = os_dict[field][key].split("-")
                                    if profile[field][key] in range(int(temp[0], 16), int(temp[1], 16)):
                                        score += self.__check_score(field, key)
                                elif ">" in os_dict[field][key]:
                                    temp = os_dict[field][key].lstrip(">")
                                    if profile[field][key] > int(temp[1], 16):
                                        score += self.__check_score(field, key)
                                elif "<" in os_dict[field][key]:
                                    temp = os_dict[field][key].lstrip("<")
                                    if profile[field][key] < int(temp[1], 16):
                                        score += self.__check_score(field, key)
                                elif profile[field][key] == int(os_dict[field][key], 16):
                                    score += self.__check_score(field, key)
                            else:
                                continue
            if not best_matches:
                best_matches.append((os_dict, score))
            else:
                if score == best_matches[0][1]:
                    best_matches.append((os_dict, score))
                elif score > best_matches[0][1]:
                    best_matches.clear()
                    best_matches.append((os_dict, score))

        return best_matches

    def __check_score(self, field: str, key: str):
        return self.scoring_dict[field][key]
