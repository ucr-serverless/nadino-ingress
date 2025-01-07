# Palladium Ingress HPA (Horizontal Process Autoscaler)

## Build F-stack's top
We use the `top` tool from F-stack to collect the CPU usage of F-stack (reported as `sys`) and
NGINX (reported as `usr`).

`hpa.py` consumes `stdout` from the top tool to collect the CPU usage.
It's necessary to call `fflush(stdout)` after each output to ensure that
the contents of the buffer are written to standard output immediately.

We provide a customized F-stack `top` with `fflush(stdout)` enforced (in the current directory).
Please do not use the  default F-stack `top`.

```bash
# Copy top.c to designated directory
cp ~/palladium-ingress/autoscaler/top.c ~/palladium-ingress/f-stack/tools/top/

# Compile F-stack top
cd ~/palladium-ingress/f-stack/tools/
make -j
```

## Configure hpa.py
There are several configurable parameters in `hpa.py`:
- `NGINX_CONF_PATH`: Path to NGINX config file. Default is `/usr/local/nginx_fstack/conf/nginx.conf`
- `FSTACK_CONF_PATH`: Path to F-stack config file. Default is `/usr/local/nginx_fstack/conf/f-stack.conf`
- `TOP_COMMAND`: Path to the binary of F-stack top. Default is `/users/sqi009/palladium-ingress/f-stack/tools/sbin/top`
- `NGINX_RELOAD_CMD`: Command to reload NGINX. Default is `sudo /usr/local/nginx_fstack/sbin/nginx -s reload`
- `EWMA_ALPHA`: Smoothing factor of EWMA.
- `MAX_WORKERS`: Maximum number of worker processes allowed
- `SCALE_UP_THRESHOLD` and `SCALE_DOWN_THRESHOLD`: Scaling thresholds
- `DECISION_INTERVAL`: Interval for autoscaling-making

## Run Ingress HPA
```bash
cd ~/palladium-ingress/autoscaler
python hpa.py
```

## Notes
Palladium Cluster Ingress currently does not support graceful reloading, meaning that the Cluster Ingress is unavailable and causes service disruption during the autoscaling procedure.

We recommend using a load generator that supports TCP connection re-establishment (e.g. `wrk`) for experiments.

Load generators such as Apache Benchmark terminate after the connection reset and are therefore not recommended.
