# Palladium Ingress Microbenchmark

We provide `rdma_server` for testing the performance of Palladium Ingress for HTTP-RDMA protocol conversion.

# Compile `rdma_server`
```bash
cd microbench

meson /tmp/rdma_server/
ninja -C /tmp/rdma_server/
```

# Run `rdma_server`
Run `rdma_server` before starting the Palladium Ingress. 
There are several configurable parameters for `rdma_server`:
- `-d`: RDMA device to be used. Run `ibv_devinfo -l` to check usable RDMA device.
- `-s`: Message size
- `-a`: `rdma_server` node IP
- `-p`: `rdma_server` node port

```bash
/tmp/rdma_server/rdma_server -d mlx5_0 -n 1000 -s 1024 -a 128.110.219.82 -p 10000
```

# Note
We currently hardcode "client" parameters in `pdin_init_rdma_config()` in `src/core/pdi_rdma.c`. Changes on "client" parameters require re-compilation of Palladium Ingress.