import re


class DbParser:
    def __init__(self):
        pass

    def parse_db(self):
        """
        Parse the database file and
        return a list of all dictionaries of OS fingerprints.
        :return: list of dictionaries
        """
        filed_names = ["SEQ", "OPS", "WIN", "ECN", "T1", "T2", "T3", "T4", "T5", "T6", "T7", "U1", "IE"]
        os_dicts = []
        # opening the database file
        db_file = open("../nmap-db.txt", encoding="utf8")
        # parsing the database file
        db_os_list = db_file.read().split("\n\n")
        db_os_list.pop(0)
        db_os_list.pop(0)
        for os in db_os_list:
            os_dict = {"SEQ": {}, "OPS": {}, "WIN": {}, "ECN": {}, "T1": {}, "T2": {}, "T3": {}, "T4": {}, "T5": {}, "T6": {}, "T7": {}, "U1": {}, "IE": {}, "os_title": "", "os_info": "", "os_cpe": "", "os_description": ""}
            temp = re.findall("([#].+)", os)
            os_dict["description"] = temp
            for t in temp:
                os = os.strip(t+"\n")
            os_lines = os.split("\n")
            os_dict["os_title"] = os_lines.pop(0)
            os_dict["os_info"] = os_lines.pop(0)
            new_os_lines = os_lines.copy()
            for line in os_lines:
                if "SEQ(" in line:
                    break
                os_dict["os_cpe"] += " " + line
                new_os_lines.remove(line)

            for i in range(0, len(new_os_lines)):
                p = re.search("(\w)+[(]", new_os_lines[i])
                new_os_lines[i] = new_os_lines[i].replace(p.group(0), "").replace(new_os_lines[i][-1], "")
                line_props = new_os_lines[i].split("%")
                for prop in line_props:
                    props = prop.split("=")
                    if len(props) == 1:
                        props.append("None")
                    os_dict[filed_names[i]][props[0]] = props[1]
            os_dicts.append(os_dict)
        db_file.close()

        return os_dicts
