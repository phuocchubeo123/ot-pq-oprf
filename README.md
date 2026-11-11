## Build
This repository contains a [Dockerfile](Dockerfile) that fetches and builds all dependencies required by [`main.cpp`](main.cpp), which contains both the code for the preprocessing and the OPRF online phase.

### Requirements
Linux/amd64 with AVX2 available. 
**MacOS/arm64 and other platforms are not supported.**
Docker is also required - we recommend installing docker according to the guide provided [here](https://docs.docker.com/engine/install/ubuntu/#install-using-the-repository).

### Instructions
To build the Docker image, make sure you have Docker properly installed and run 
```bash
$ docker build -t oprf .
```
Depending on your Docker installation, you may have to prepend the `docker` commands with `sudo`. 

This will fetch and build [libOTe](https://github.com/osu-crypto/libOTe) with the appropriate build options. 
Once the image is done building, you can run a container with this image by running
```bash
$ docker run -it oprf
```
This will launch a container and a `bash` instance. From there, you can execute 
```bash
$ ./oprf local 127.0.0.1 1212
```

### Running client and server on two machines
```bash
# server machine (listens)
$ ./oprf server 0.0.0.0 1212 [all|online] [num_rounds]
# client machine (connects)
$ ./oprf client <server-ip> 1212 [all|online] [num_rounds]
```
`all` (default) first runs the alternative preprocessing benchmarks (`benchmark_alt_preproc`), as
the original binary did. `online` only runs the preprocessing used by the online example, then the
online phase. Both parties must use the same mode and `num_rounds` (default 10).
Each party runs its own role: the client is the phase one sender and the phase two receiver, and
the server is the reverse. Each party prints its own time and traffic for every phase, plus totals.

The whole run uses a single coproto `AsioSocket` connection (TCP, `TCP_NODELAY`). A 1-byte
barrier, which is neither timed nor counted, aligns the parties before every measured phase. Byte
counts are coproto's socket counters and include its 8-byte per-message header. In the online
phase the request `(e_1, b')` and the response `(y_0, ..., y_{delta-1})` are sent over the network,
bit-packed to `lg_q`, `lg_delta` and `lg_p` bits per value. The server sends `b_bar = b xor sk`
once, at the end of preprocessing. The client reports its computation time and its end-to-end
latency per evaluation, and the server reports its BlindEval time. For the correctness check, the
server reveals `sk` after the measured online phase, for testing only.
Parameters can be adjusted via the constants in the `/home/ot-pq-oprf/main.cpp` file. Rebuilding is necessary and can be achieved by executing `make` in the `/home/ot-pq-oprf/build` directory inside the container.

### Performance discrepancies
The measures provided in the paper were obtained from a native build on ubuntu 24.04 running on an AWS EC2 instance with 4 vCPUs and 16 GB memory. 
Building natively or with Docker on different machines may yield different measures.
To reproduce the measures from the paper, one may follow the Dockerfile steps to natively install libOTe which will allow to natively build the Pool OPRF implementation. 

## Code structure
All the code relevant to the experiments is included in the [main.cpp](main.cpp) file. 
Comments throughout the file detail how the code is structured. 

At a high level, the code contains several implementations of the client and server roles for each phase of the preprocessing step as described in Figure 3. 
Each implementation uses a different OT extender, provided by the [libOTe](https://github.com/osu-crypto/libOTe) library.
The `benchmark_alt_preproc` function launches an execution of each of the three variants of preprocessing (`IKNP`, `Silent OT (n)` and `Silent OT (n * kappa)`) in order to obtain the measures presented in Tables 2, 4 and 6. 

The `main` function provides a working example of the online phase of the OPRF. It follows the description given in Figure 4, and its results are used to fill in Tables 3 and 5.

In order to entirely reproduce the results presented in the tables, one must launch the executable several times to obtain an average and repeat the process for each parameter set. 
Client and server complexity are respectively measured as described in the text output of the executable and in the code.

## Parameters
As is, the file contains a set of paramaters of interest for comparison with prior work (c.f. Table 4). 
Alternative parameter sets presented in the paper can be benchmarked by e.g. setting
```c
const uint n = 415;
const uint tau = 1 << 18;
const uint lg_q = 8;
const uint lg_lg_p = 2;

const uint kappa = 16384;
```
in the `main.cpp` file for the `(n, q, p) = (415, 2^8, 2^4)` parameter set.

The executable must then be rebuilt from the `build` directory by running the following commands: 
```bash
$ cd build
$ make
$ ./oprf
```