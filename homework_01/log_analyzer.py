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
import gzip
import os
import re
import logging
import sys

config = {
    "REPORT_SIZE": 1000,
    "REPORT_DIR": "./reports",
    "LOG_DIR": "./log",
    "DEFAULT_CONFIG_PATH": "./config.cfg",
    "RE_NGINX_LOG_FORMAT": r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) (-|\w*)  (-|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,"
    r'3}) \[(.*)\] ".* (.*) .*" (\d*) (\d*) "(.*?)" "(.*?)" "(.*?)" "(.*?)" "(.*?)" (\d*.\d*)$',
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
        raise Exception(f"Config file cannot be parsed: {err}") from err

    return config_dict


def load_config(conf):
    """
    Load config from file and mix it with default config.
    """
    config_dict = {}
    if len(sys.argv) < 2:
        if not os.path.exists(conf["DEFAULT_CONFIG_PATH"]):
            raise FileNotFoundError(
                """File conf.cfg not found.
            Please check that file conf.cfg exist in this directory.
            Or provide path to conf.cfg file by --config=file_path argument"""
            )
        config_dict = parse_config_file("config.cfg")
    else:
        for arg in sys.argv:
            if arg.startswith("--config="):
                config_file = arg.split("=")[1]
                config_dict = parse_config_file(config_file)

    config.update(config_dict)


def get_latest_log(conf):
    """
    Find the latest log file from LOG_DIR.
    Return latest log file name and zipped flag.
    :param conf: config dict
    :return: latest log path, the latest log date
    """
    log_regexp = re.compile(r"^(nginx-access-ui.log-)(\d{8})($|.gz$)")
    latest_log_date = 0
    latest_log_path = ""

    for filename in os.listdir(conf["LOG_DIR"]):
        match = log_regexp.match(filename)
        if match and int(match.group(2)) > latest_log_date:
            latest_log_date = int(match.group(2))
            latest_log_path = f"{conf['LOG_DIR']}/{filename}"
    return latest_log_path, latest_log_date


def parse_line(line, regexp):
    """
    Parse log line.
    :param line: log line
    :param regexp: regexp for line format
    :return: parsed line
    """
    match = regexp.match(line)
    if not match:
        logging.debug("Can't parse line: %s", line[0:-2])
        return None
    return {
        "url": match.group(5),
        "request_time": match.group(13),
    }


def read_lines(file_path, regexp):
    """
    Read lines from log file.
    :param file_path: file path
    :param regexp: regexp for lines format
    :return: lines
    """
    if file_path.endswith(".gz"):
        log = gzip.open(file_path, "rt", encoding="UTF-8")
    else:
        log = open(file_path, "r", encoding="UTF-8")
    total = processed = 0
    for line in log:
        parsed_line = parse_line(line, regexp)
        total += 1
        if total == 1000000:
            break
        if total % 100000 == 0:
            logging.info("Processed %s lines", '{0:,}'.format(total).replace(',', ' '))
        if parsed_line:
            processed += 1
            yield parsed_line
    yield {"parsing_stats": {"total": total, "processed": processed}}
    log.close()


def parse_logfile(conf, log_path):
    """
    Read log file.
    :param conf: config dict
    :param log_path: path to log file
    :return: dict with log statistics
    """
    stats = {}
    logging.debug("Reading log file: %s", log_path)
    regexp = re.compile(conf["RE_NGINX_LOG_FORMAT"])
    stats = {}
    uniq_urls_count = 0
    all_req_time = 0
    for line in read_lines(log_path, regexp):
        if "parsing_stats" in line:
            stats["parsing_stats"] = line["parsing_stats"]
        elif line["url"] not in stats:
            stats[line["url"]] = {}
            stats[line["url"]]["url"] = line["url"]
            stats[line["url"]]["time_arr"] = []
            stats[line["url"]]["time_arr"].append(line["request_time"])
            uniq_urls_count += 1
            all_req_time += float(line["request_time"])
        else:
            stats[line["url"]]["time_arr"].append(line["request_time"])

    # for item in stats:
    #     print(stats[item])
    print(uniq_urls_count)
    print(all_req_time)


def main():
    """
    Main function.
    """
    load_config(config)
    logging.basicConfig(
        level=config["LOG_LEVEL"] if "LOG_LEVEL" in config else logging.INFO,
        format="[%(asctime)s] %(levelname).1s %(message)s",
        datefmt="%Y.%m.%d %H:%M:%S",
        filename=config["LOG_FILE"] if "LOG_FILE" in config else None,
    )
    try:
        logging.error("-" * 50)
        logging.error("Starting log analyzer...")
        latest_log_path, latest_log_date = get_latest_log(config)
        logging.info("Latest log file: %s", latest_log_path)
        logging.debug("Latest log date: %s", latest_log_date)
        parse_logfile(config, latest_log_path)
        logging.error("Log analyzer finished work. Have a nice day! :)")
    except Exception as err:
        logging.exception("Unexpected error: %s", err, exc_info=err)
    except KeyboardInterrupt:
        logging.error("User interrupted the program.")


if __name__ == "__main__":
    main()
