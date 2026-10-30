import re

_ip_map = {}
_counter = 1


def anonymize_ip(ip):
    global _counter
    if ip not in _ip_map:
        _ip_map[ip] = f"ANON_HOST_{_counter:03d}"
        _counter += 1
    return _ip_map[ip]


def anonymize_log_file(input_path, output_path):
    with open(input_path, "r") as infile:
        content = infile.read()

    ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'

    def replace_ip(match):
        ip = match.group(0)
        return anonymize_ip(ip)

    anonymized_content = re.sub(ip_pattern, replace_ip, content)

    with open(output_path, "w") as outfile:
        outfile.write(anonymized_content)


def get_mapping():
    return _ip_map