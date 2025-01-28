#!/bin/bash

cluster_ip=$1 # URL
wrk_script="traffic.lua"                            # lua script
duration="4200s"                                    # Running duration per wrk instance
initial_instances=1                                 # One wrk instance at the beginning
interval=10                                         # Time interval (in seconds) between each instance increase/decrease

global_instance_id=1

function start_wrk_instance() {
    local instance_id=$global_instance_id
    # local cpu_core=$1
    local log_file="wrk_clt_${instance_id}_traffic_log.csv"

    ((global_instance_id++))

    # taskset -c $cpu_core wrk -t1 -c12 -d$duration -s $wrk_script $cluster_ip -- $instance_id > /dev/null 2>&1 &
    wrk -t1 -c12 -d$duration -s $wrk_script $cluster_ip -- $instance_id > /dev/null 2>&1 &
    
    # echo "Started wrk instance $instance_id on CPU core $cpu_core (logging to $log_file)"
    echo "Started wrk instance $instance_id (logging to $log_file)"
}

function adjust_instances() {
    local target_instances=$1
    local current_instances=$(pgrep -c wrk)

    echo "Current wrk instances: $current_instances, Target wrk instances: $target_instances"

    if (( target_instances > current_instances )); then
        for ((i=current_instances+1; i<=target_instances; i++)); do
            echo "Increase one wrk instance!"
            start_wrk_instance
        done
    elif (( target_instances < current_instances )); then
        for ((i=current_instances; i>target_instances; i--)); do
            echo "Reduce one wrk instance!"
            local pid=$(pgrep -n wrk) # Get the PID of the most recently started wrk instance
            kill -9 $pid
            echo "Stopped wrk instance $i (PID $pid)"
        done
    fi
}

echo "Starting dynamic wrk instances experiment..."

# increase to 10 wrk instances
for ((j=$initial_instances; j<=10; j++)); do
    adjust_instances $j
    sleep $interval
done

echo "Let all wrk instances run simultaneously for 30 seconds"
sleep 30

# reduce to 5 wrk instances
# for ((j=10; j>5; j--)); do
#     adjust_instances $((j-1))
#     sleep $interval
# done

# increase to 15 wrk instances
for ((j=10; j<=15; j++)); do
    adjust_instances $j
    sleep $interval
done

echo "Wait until all wrk instances are complete."
wait
echo "Experiment completed!"
