-- Copyright 2025 University of California, Riverside
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--      http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
--
-- SPDX-License-Identifier: Apache-2.0

local output_file = "traffic_log.csv"

local last_time = 0
local req_counter = 0
local start_time = os.time()
local log = {}

local wrk_clt_id = 0

function init(args)
    wrk_clt_id = args[1] or error("Invalid number for wrk_clt_id: " .. args[1])

    output_file = "wrk_clt_" .. wrk_clt_id .. "_" .. output_file
    print("Output logged to: " .. output_file)

    local file = io.open(output_file, "w")
    file:write("wc_time,run_time,request_rate\n")
    file:close()
end

function request()
    req_counter = req_counter + 1
    local wall_clock_time = os.time()
    local now = wall_clock_time - start_time

    if now - last_time >= 1 then
        table.insert(log, {time = now, rate = req_counter})

        -- write metrics to output_file
        local file = io.open(output_file, "a")
        file:write(wall_clock_time .. "," .. now .. "," .. req_counter .. "\n")
        file:close()
        print("Wrk Client: " .. wrk_clt_id .. " WC_Time: " .. wall_clock_time .. " Run_Time: " .. now .. "s, Current Rate: " .. req_counter .. " requests/sec")

        req_counter = 0
        last_time = now
    end

    local path = "/"
    return wrk.format("GET", path)
end

function done(summary, latency, requests)
    print("Test completed.")
    print("Total Requests: " .. summary.requests)
    print("Total Duration: " .. summary.duration / 1000000 .. " seconds")
    print("Total Bytes: ", summary.bytes)
    print("Requests per Second: ", summary.requests / (summary.duration / 1e6))
    print("Latency Distribution:")
    for _, p in pairs({50, 90, 99}) do
        n = latency:percentile(p)
        print(string.format("  %g%%: %0.2f ms", p, n / 1000))
    end
end
