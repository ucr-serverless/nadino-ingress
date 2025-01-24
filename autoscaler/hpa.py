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

"""Horizontal Autoscaler."""

import os
import subprocess
import time
import re
import signal
import socket

# Configuration
NGINX_CONF_PATH = "/usr/local/nginx_fstack/conf/nginx.conf"
FSTACK_CONF_PATH = "/usr/local/nginx_fstack/conf/f-stack.conf"

TOP_COMMAND = "/users/sqi009/palladium-ingress/f-stack/tools/sbin/top"
NGINX_RELOAD_CMD = "sudo /usr/local/nginx_fstack/sbin/nginx -s reload"

EWMA_ALPHA = 0.2  # Weight for EWMA

MAX_WORKERS = 20           # Maximum PDIN workers
SCALE_UP_THRESHOLD = 80    # Percentage
SCALE_DOWN_THRESHOLD = 30  # Percentage

# Interval for autoscaling-making
DECISION_INTERVAL = 30  # seconds

# Address of DNE (RDMA server in microbench)
DNE_SERVER_PORT = 9000            # Socket port of DNE
DNE_SERVER_IP = "128.110.219.177" # IP of DNE
DNE_RETRY_INTERVAL = 0.5          # Socket port of DNE

# HPA/DNE OP codes
DNE_ACK_READY = 200 # DNE notifies HPA that PDIN is ready
HPA_SND_TERM  = 300 # HPA notifies DNE to disconnect RC connections with PDIN
DNE_ACK_TERM  = 400 # DNE notifies HPA that PDIN can be reloaded

top_process = None

class HPA_Channel:
    def __init__(self, host, port):
        """
        Initialize the channel to DNE.

        :param host: DNE IP
        :param port: DNE Port
        """
        self.host = host
        self.port = port
        self.client_socket = None

    def connect_to_dne(self):
        """Connect to DNE and wait for ACK."""
        while True:
            try:
                self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.client_socket.connect((self.host, self.port))
                print(f"Successfully connected to DNE {self.host}:{self.port}")

                break
            except socket.error as e:
                print(f"Error connecting to DNE: {e}. Retrying in {DNE_RETRY_INTERVAL} second(s)...")
                time.sleep(DNE_RETRY_INTERVAL)
                self.client_socket = None

    def wait_for_ack(self):
        """Wait for DNE to send an ACK."""
        if not self.client_socket:
            print("Not yet connected to DNE, unable to receive ACK")
            return None
        try:
            ack = self.client_socket.recv(1024)
            if len(ack) < 4:
                raise ValueError("Incomplete ACK received")
            ack_code = int.from_bytes(ack, byteorder='little')
            print(f"Received ACK from DNE: {ack_code}")
            return ack_code
        except socket.error as e:
            print(f"Error receiving ACK: {e}")
            return None

    def send_terminate_signal(self, signal: int):
        """Sends a termination signal to the DNE."""
        try:
            if self.client_socket:
                self.client_socket.sendall(signal.to_bytes(4, byteorder='little'))
                print("The DNE has been sent a terminate signal (TERMINATE).")
        except Exception as e:
            print(f"Failed to send the termination signal: {e}")

    def close_connection(self):
        """Close the connection."""
        if self.client_socket:
            self.client_socket.close()
            self.client_socket = None
            print("The client connection has been closed.")

# Helper functions
def start_top():
    """Start the top command to monitor the NGINX CPU usage."""
    global top_process
    print("Starting F-stack top tool...")
    top_process = subprocess.Popen(
        ["sudo", TOP_COMMAND],
        stdout=subprocess.PIPE,
        text=True
    )
    print("top tool is running")

def stop_top():
    """Stops the running top command."""
    global top_process
    if top_process is not None:
        print("Stopping F-stack top tool...")
        try:
            # Flush stdout and stderr buffers before graceful termination
            if top_process.stdout:
                top_process.stdout.close()
            if top_process.stderr:
                top_process.stderr.close()
            top_process.send_signal(signal.SIGTERM)  # graceful termination
            top_process.wait(timeout=5)
            print("Top process terminated gracefully.")
        except subprocess.TimeoutExpired:
            print("Graceful termination failed. Sending SIGKILL...")
            top_process.kill()  # Forceful termination
            top_process.wait()
        finally:
            top_process = None

def calculate_ewma(prev_ewma, current_value):
    """Calculate the Exponentially Weighted Moving Average (EWMA)."""
    return EWMA_ALPHA * current_value + (1 - EWMA_ALPHA) * prev_ewma

def get_worker_processes():
    """Read the current worker_processes value from nginx.conf."""
    with open(NGINX_CONF_PATH, 'r') as f:
        for line in f:
            match = re.match(r'\s*worker_processes\s+(\d+);', line)
            if match:
                return int(match.group(1))
    return None

def update_nginx_conf(new_count):
    """Set the worker_processes value in nginx.conf."""
    try:
        with open(NGINX_CONF_PATH, 'r') as f:
            lines = f.readlines()

        with open(NGINX_CONF_PATH, 'w') as f:
            for line in lines:
                if re.match(r'\s*worker_processes\s+\d+;', line):
                    f.write(f'worker_processes  {new_count};\n')
                else:
                    f.write(line)
    except Exception as e:
        print(f"Error updating {FSTACK_CONF_PATH}: {e}")

def update_fstack_conf(new_count):
    """Set the lcore_mask value in f-stack.conf."""
    try:
        with open(FSTACK_CONF_PATH, 'r') as file:
            fstack_conf = file.readlines()
        
        lcore_mask = hex((1 << new_count) - 1)[2:]

        for i, line in enumerate(fstack_conf):
            if line.strip().startswith("lcore_mask"):
                # lcore_mask = '1' * new_count
                fstack_conf[i] = f"lcore_mask={lcore_mask}\n"
                break

        with open(FSTACK_CONF_PATH, 'w') as file:
            file.writelines(fstack_conf)
    except Exception as e:
        print(f"Error updating {FSTACK_CONF_PATH}: {e}")

def reload_nginx():
    """Reload the NGINX configuration."""
    try:
        subprocess.run(NGINX_RELOAD_CMD, shell=True, check=True)
    except Exception as e:
        print(f"Error reloading NGINX: {e}")

def parse_top_output(line):
    """Parse a line of top output to extract sys and usr CPU usage."""
    try:
        parts = line.split('|')
        if len(parts) >= 4:
            sys = float(parts[2].strip().strip('%'))
            usr = float(parts[3].strip().strip('%'))

            return sys + usr
        else:
            raise ValueError("Unexpected top output.")
    except (IndexError, ValueError):
        print(f"Unexpected top output: {line}. Restart top...")
        return None

def horizontal_scaling(cpu_ewma, hpa_clt):
    """Scale worker processes based on CPU EWMA."""

    # Step 1: Read the current number of worker_processes
    current_workers = get_worker_processes()
    if current_workers is None:
        raise ValueError("Unable to find worker_processes in nginx.conf")

    # Step 2: Adjust worker_processes based on EWMA
    if cpu_ewma > 80 and current_workers < MAX_WORKERS:
        new_workers = current_workers + 1
        print(f"Increasing worker_processes to {new_workers}")
    elif cpu_ewma < 30 and current_workers > 1:
        new_workers = current_workers - 1
        print(f"Decreasing worker_processes to {new_workers}")
    else:
        print(f"No adjustment needed. current_workers: {current_workers}")
        return

    # Step 3: Update configuration files
    update_nginx_conf(new_workers)
    update_fstack_conf(new_workers)

    # Step 4: Reload NGINX
    stop_top()

    """Signal DNE to disconnect and wait for ACK."""
    # hpa_clt.send_terminate_signal(int(HPA_SND_TERM))

    # # Wait for DNE_ACK_TERM from DNE
    # ack_code = hpa_clt.wait_for_ack()
    # if ack_code == DNE_ACK_TERM:
    #     print("DNE already disconnected PDIN.")
    # else:
    #     raise ValueError(f"DNE returns unexpected code {ack_code}")

    reload_nginx()
    print(f"Reloaded NGINX with {new_workers} worker processes.")

    # Ensure NGINX master process (DPDK primary process) ready before starting top
    # Otherwise, it will trigger fstack ipc message error
    # TODO: revisit the sleep time, 2 seconds sometimes trigger error
    time.sleep(5)
    start_top()

def main():
    global top_process

    # Connect with DNE
    hpa_clt = HPA_Channel(host = DNE_SERVER_IP, port = DNE_SERVER_PORT)
    hpa_clt.connect_to_dne()

    # Wait for the ACK returned by DNE to validate PDIN status
    ack_code = hpa_clt.wait_for_ack()
    if ack_code == DNE_ACK_READY:
        print("PDIN startup was confirmed by DNE.")

    cpu_ewma = 0.0
    start_top()

    last_decision_time = time.time()
    while True:
        if top_process.stdout:
            line = top_process.stdout.readline().strip()
            if line:
                current_cpu_usage = parse_top_output(line)

                if current_cpu_usage is None:
                    time.sleep(2)
                    start_top()
                    last_decision_time = time.time()
                    continue

                # Update EWMA
                if cpu_ewma == 0.0:
                    cpu_ewma = current_cpu_usage
                else:
                    cpu_ewma = calculate_ewma(cpu_ewma, current_cpu_usage)
                
                print(f"Current CPU usage: {current_cpu_usage:.2f}%, CPU EWMA: {cpu_ewma:.2f}%")

                # Check if it's time to make a scaling decision
                if time.time() - last_decision_time > DECISION_INTERVAL:
                    horizontal_scaling(cpu_ewma, hpa_clt)
                    last_decision_time = time.time()
            else:
                print("Line is None")
        else:
            print("top_process.stdout is NONE")

if __name__ == "__main__":
    main()
