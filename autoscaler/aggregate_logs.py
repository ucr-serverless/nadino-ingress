# Copyright 2025 University of California, Riverside
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

import os
import csv
from collections import defaultdict

def aggregate_wrk_logs(log_directory, output_file):
    """
    Aggregate request rates from multiple wrk instance logs.

    Args:
        log_directory (str): Path to the directory containing wrk log files.
        output_file (str): Path to the output aggregated log file.
    """
    # Dictionary to store aggregated request rates for each wc_time
    aggregated_data = defaultdict(int)

    start_wc_time = float('inf')

    # Iterate through all log files in the directory
    for log_file in os.listdir(log_directory):
        if log_file.startswith("wrk_clt_") and log_file.endswith("_traffic_log.csv"):
            log_path = os.path.join(log_directory, log_file)
            with open(log_path, "r") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    wc_time = int(row["wc_time"])
                    request_rate = int(row["request_rate"])
                    aggregated_data[wc_time] += request_rate
                    if start_wc_time > wc_time:
                        start_wc_time = wc_time

    # print(f"start_wc_time: {start_wc_time}")

    # Write the aggregated data to the output file
    with open(output_file, "w") as f:
        writer = csv.writer(f)
        writer.writerow(["wc_time", "total_request_rate"])
        for wc_time, total_request_rate in sorted(aggregated_data.items()):
            writer.writerow([wc_time - start_wc_time, total_request_rate])

if __name__ == "__main__":
    # Path to the directory containing wrk logs
    log_directory = "./"  # Change this to your actual directory path

    # Path to the output aggregated log file
    output_file = "aggregated_traffic_log.csv"

    # Aggregate the logs
    aggregate_wrk_logs(log_directory, output_file)
    print(f"Aggregated log saved to {output_file}")