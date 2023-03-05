"""
Nginx log analyzer.
Collect statisitcs from nginx logs ang generate html report.
"""
# !/usr/bin/env python
# -*- coding: utf-8 -*-


# log_format ui_short '$remote_addr  $remote_user $http_x_real_ip [$time_local] "$request" '
#                     '$status $body_bytes_sent "$http_referer" '
#                     '"$http_user_agent" "$http_x_forwarded_for" '
#                     '"$http_X_REQUEST_ID" "$http_X_RB_USER" '
#                     '$request_time';
import os
import re
import logging
import sys

config = {
    "REPORT_SIZE": 1000,
    "REPORT_DIR": "./reports",
    "LOG_DIR": "./log",
    "DEFAULT_CONFIG_PAH": "config.cfg",
}


def parse_config_file(config_file):
    """
    Parse conf file.
    :param config_file: conf file path
    :return: parsed conf dict
    """
    if not os.path.exists(config_file):
        raise Exception(f"Config file not found: {config_file}")

    try:
        with open(config_file, "r", encoding="UTF-8") as file:
            config_dict = {}
            for line in file:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                key, value = line.split("=")
                config_dict[key.strip()] = value.strip()
    except Exception as err:
        print(f"Config file cannot be parsed: {err}")

    return config_dict


def load_config(conf):
    """
    Load config from file and mix it with default config.
    """
    config_dict = {}
    if len(sys.argv) < 2:
        if not os.path.exists(conf["DEFAULT_CONFIG_PAH"]):
            raise FileNotFoundError(
                """File conf.cfg not found.
            Please check that file conf.cfg exist in this directory.
            Or provide path to conf.cfg file by --conf=file_path argument"""
            )
        config_dict = parse_config_file("./config.cfg")
    else:
        for arg in sys.argv:
            if arg.startswith("--conf="):
                config_file = arg.split("=")[1]
                config_dict = parse_config_file(config_file)

    config.update(config_dict)


def get_latest_log(conf):
    """
    Find the latest log file from LOG_DIR.
    Return latest log file name and zipped flag.
    :param conf: config dict
    :return: latest log path, the latest log date and zipped flag
    """
    log_regexp = re.compile(r"^(nginx-access-ui.log-)(\d{8})($|.gz$)")
    latest_log_date = 0
    latest_log_path = ""
    zipped = False

    for filename in os.listdir(conf["LOG_DIR"]):
        match = log_regexp.match(filename)
        if match and int(match.group(2)) > latest_log_date:
            latest_log_date = int(match.group(2))
            latest_log_path = f"{conf['LOG_DIR']}/{filename}"
            zipped = filename.endswith(".gz")
    return latest_log_path, latest_log_date, zipped


def main():
    """
    Main function.
    """
    load_config(config)
    logging.basicConfig(
        level=config["LOG_LEVEL"] if "LOG_LEVEL" in config else logging.INFO,
        format="[%(asctime)s] %(levelname).1s %(message)s",
        datefmt="%Y.%m.%d %H:%M:%S",
    )
    try:
        latest_log_path, latest_log_date, zipped = get_latest_log(config)
        logging.info("Latest log file: %s", latest_log_path)
        logging.info("Latest log date: %s", latest_log_date)
        logging.info("Zipped: %s", zipped)
    except Exception as err:
        logging.exception("Unexpected error: %s", err)


if __name__ == "__main__":
    main()
