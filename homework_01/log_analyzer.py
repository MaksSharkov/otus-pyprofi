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
from string import Template
from statistics import mean, median

config = {
    "REPORT_SIZE": 1000,
    "REPORT_DIR": "./reports",
    "LOG_DIR": "./log",
    "DEFAULT_CONFIG_PATH": "./config.cfg",
    "RE_NGINX_LOG_FORMAT": r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) (-|\w*)  (-|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,"
    r'3}) \[(.*)\] ".* (.*) .*" (\d*) (\d*) "(.*?)" "(.*?)" "(.*?)" "(.*?)" "(.*?)" (\d*.\d*)$',
    "REPORT_FILE": "report-{yyyy}.{mm}.{dd}.html",
    "REPORT_TEMPLATE": "report.html",
    "REPORT_INSERT_POINT": "table_json",
    "RE_LOG_FILE": r"^(nginx-access-ui.log-)(\d{8})($|.gz$)",
    "MAX_PARSE_ERR_PERC": 5,
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
    log_regexp = re.compile(conf["RE_LOG_FILE"])
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
    total = processed = 0
    with gzip.open(file_path, "rt", encoding="UTF-8") if file_path.endswith(
        ".gz"
    ) else open(file_path, "r", encoding="UTF-8") as log:
        for line in log:
            parsed_line = parse_line(line, regexp)
            total += 1
            if total % 100000 == 0:
                logging.info(
                    "Processed %s lines", "{0:,}".format(total).replace(",", " ")
                )
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
    uniq_urls_count = 0
    all_req_time = 0
    for line in read_lines(log_path, regexp):
        if "parsing_stats" in line:
            stats["parsing_stats"] = line["parsing_stats"]
            stats["parsing_stats"]["uniq_urls_count"] = uniq_urls_count
            stats["parsing_stats"]["all_req_time"] = all_req_time
            break
        if line["url"] not in stats:
            stats[line["url"]] = {}
            stats[line["url"]]["url"] = line["url"]
            stats[line["url"]]["time_arr"] = []
            uniq_urls_count += 1
        stats[line["url"]]["time_arr"].append(float(line["request_time"]))
        all_req_time += float(line["request_time"])
    failed_lines_count = (
        stats["parsing_stats"]["total"] - stats["parsing_stats"]["processed"]
    )
    if failed_lines_count > float(stats["parsing_stats"]["total"]) / 100 * float(
        conf["MAX_PARSE_ERR_PERC"]
    ):
        raise Exception("Too many failed lines... Exiting")
    return stats


def actual_report_exists(conf, date):
    """
    Check if report exists.
    :param date: report date for check
    :param conf: config dict
    :return: True if report exists, False otherwise and report path
    """
    report_date = re.match(r"^(\d{4})(\d{2})(\d{2})$", str(date))
    report_file = conf["REPORT_FILE"].format(
        yyyy=report_date.group(1),
        yy=report_date.group(1)[2:4],
        mm=report_date.group(2),
        dd=report_date.group(3),
    )
    report_path = conf["REPORT_DIR"] + "/" + report_file
    return os.path.exists(report_path), report_path


def generate_report(conf, report_path, stats):
    """
    Generate report.
    :param conf: config dict
    :param report_path: path to result report file
    :param stats: ready to report stats list
    :return: None
    """
    report_template = conf["REPORT_DIR"] + "/" + conf["REPORT_TEMPLATE"]
    replace_dict = {conf["REPORT_INSERT_POINT"]: stats}
    with open(report_template, "r", encoding="UTF-8") as template:
        with open(report_path, "w", encoding="UTF-8") as report:
            for line in template:
                report.write(Template(line).safe_substitute(replace_dict))


def calculate_stats(conf, raw_stats):
    """
    Calculate log statistic.
    :param conf: config dict
    :param raw_stats: raw statistics dict
    :return: list with ready for report statistics
    """
    stats = []
    parsing_stats = raw_stats["parsing_stats"]
    del raw_stats["parsing_stats"]
    logging.info(
        "Calculating stats for %s uniq urls",
        "{0:,}".format(parsing_stats["uniq_urls_count"]).replace(",", " "),
    )
    processed = 0
    for item in raw_stats:
        raw_stats[item]["time_arr"] = sorted(raw_stats[item]["time_arr"])
        raw_stats[item]["count"] = len(raw_stats[item]["time_arr"])
        raw_stats[item]["count_perc"] = round(
            raw_stats[item]["count"] * 100 / parsing_stats["total"], 3
        )
        raw_stats[item]["time_sum"] = round(sum(raw_stats[item]["time_arr"]), 3)
        raw_stats[item]["time_perc"] = round(
            raw_stats[item]["time_sum"] * 100 / parsing_stats["all_req_time"], 3
        )
        raw_stats[item]["time_avg"] = round(mean(raw_stats[item]["time_arr"]), 3)
        raw_stats[item]["time_max"] = max(raw_stats[item]["time_arr"])
        raw_stats[item]["time_med"] = round(median(raw_stats[item]["time_arr"]), 3)
        del raw_stats[item]["time_arr"]
        processed += 1
        if processed % (round(int(parsing_stats["uniq_urls_count"]) / 10)) == 0 == 0:
            logging.debug(
                "Processed %s urls", "{0:,}".format(processed).replace(",", " ")
            )
    logging.info("Collect stats for %s longest urls", conf["REPORT_SIZE"])
    for i in range(0, int(conf["REPORT_SIZE"])):
        max_time_item = max(raw_stats, key=lambda item: raw_stats[item]["time_sum"])
        stats.append(raw_stats[max_time_item])
        del raw_stats[max_time_item]
        if (i + 1) % (round(int(conf["REPORT_SIZE"]) / 10)) == 0:
            logging.debug(
                "Collected %s urls", "{0:,}".format(i + 1).replace(",", " ")
            )
    return stats


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
        report_exists, report_path = actual_report_exists(config, latest_log_date)
        if not report_exists:
            raw_stats = parse_logfile(config, latest_log_path)
            stats = calculate_stats(config, raw_stats)
            generate_report(config, report_path, stats)
        else:
            logging.info("Report already exists.")
        logging.error("Log analyzer finished work. Have a nice day! :)")
    except Exception as err:
        logging.exception("%s", err, exc_info=err)
    except KeyboardInterrupt:
        logging.error("User interrupted the program.")


if __name__ == "__main__":
    main()
