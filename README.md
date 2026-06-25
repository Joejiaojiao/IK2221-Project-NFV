# IK2221 Phase 1 NFV Project

This repository contains the Phase 1 implementation of the IK2221 Network Function Virtualization (NFV) project. The project builds a Mininet-based network that uses Click modular router scripts and a POX controller to implement three virtualized network functions: NAPT, IDS, and a load balancer for a virtual LLM inference service.

## Before Running: Reinstall Click

Before running the project, reinstall Click with the required configuration options. This ensures that the user-level Click runtime and the required elements, including `IPRewriter`, `ICMPPingRewriter`, `ARPQuerier`, `ARPResponder`, `Search`, `Classifier`, and related NFV elements, are available.

Run the following commands inside the VM before starting the controller or topology:

```bash
cd /opt/click
make clean
./configure --enable-user-multithread --enable-multithread --enable-all-elements --enable-ip6 --enable-nanotimestamp --enable-intel-cpu --enable-analysis --enable-ipsec --enable-local --enable-simple --disable-linuxmodule --disable-wifi --disable-avx2
make -j 4
sudo make install
```

After installation, return to the project directory and run the project with `make app`, `make topo`, or `make test`.


This repository contains the Phase 1 implementation of the IK2221 Network Function Virtualization (NFV) project. The project builds a Mininet-based network that uses Click modular router scripts and a POX controller to implement three virtualized network functions: NAPT, IDS, and a load balancer for a virtual LLM inference service.

## Project Overview

The network is divided into two zones:

- **User Zone (UZ)**: contains two user hosts, `h1` and `h2`, using private addresses in `10.0.0.0/24`.
- **Inferencing Zone (IZ)**: contains an inspector host, a virtual load balancer service, and three lightweight HTTP backend servers that emulate LLM inference servers.

Users access the service through the virtual IP:

```text
100.0.0.45:80
```

The request path is:

```text
h1/h2 -> s1 -> napt -> s2 -> ids -> lb1 -> s3 -> llm1/llm2/llm3
```

The implemented network functions are:

- **NAPT**: hides user-zone addresses and translates traffic between `10.0.0.0/24` and `100.0.0.0/24`.
- **IDS**: forwards normal traffic while redirecting suspicious HTTP requests to the inspector host.
- **Load Balancer**: exposes a virtual HTTP service at `100.0.0.45:80` and distributes requests to the backend servers.

## Topology

```text
User Zone                                      Inferencing Zone

h1 10.0.0.50 ─┐
              ├── s1 ── napt ── s2 ── ids ── lb1 ── s3 ── llm1 100.0.0.40
h2 10.0.0.51 ─┘                  │                    ├── llm2 100.0.0.41
                                  │                    └── llm3 100.0.0.42
                                  │
                               insp 100.0.0.30

Virtual HTTP service: 100.0.0.45:80
NAPT UZ gateway:      10.0.0.1
NAPT IZ address:      100.0.0.1
```

## Main Components

### `topology/topology.py`

Defines the Mininet topology and startup services.

It creates:

- user hosts: `h1`, `h2`
- normal learning switches: `s1`, `s2`, `s3`
- Click-based NFV nodes: `napt`, `ids`, `lb1`
- inspector host: `insp`
- backend HTTP servers: `llm1`, `llm2`, `llm3`

The `startup_services()` function also:

- configures default routes for `h1` and `h2` through `10.0.0.1`
- configures default routes for backend servers through `100.0.0.1`
- starts `tcpdump` on `insp` and writes captured packets to `/tmp/ids_capture.pcap`
- starts lightweight Python HTTP servers on `llm1`, `llm2`, and `llm3`

### `applications/controller/baseController.py`

Starts the correct function when each OpenFlow switch connects to the POX controller.

- DPID `1`, `2`, `3`: normal L2 learning switches
- DPID `4`: starts `napt.click`
- DPID `5`: starts `ids.click`
- DPID `6`: starts `lb1.click`

### `applications/controller/click_wrapper.py`

Provides a helper function for launching Click processes from POX.

### `applications/nfv/napt.click`

Implements Network Address and Port Translation.

Main behavior:

- responds to ARP on both user-zone and inferencing-zone interfaces
- translates outbound TCP traffic from `10.0.0.0/24` to `100.0.0.1` using `IPRewriter`
- translates ICMP echo request/reply traffic using `ICMPPingRewriter`
- restores inbound traffic to the original user-zone host
- drops unsupported or unexpected traffic
- writes counters to `results/napt.report`

### `applications/nfv/ids.click`

Implements the intrusion detection system.

Main behavior:

- transparently forwards ARP, ICMP, TCP signaling, and server responses
- inspects HTTP requests from the client side
- allows only `POST` and `PUT` HTTP methods
- redirects other HTTP methods to the inspector interface
- checks the beginning of HTTP `PUT` payloads for suspicious strings:
  - `cat /etc/passwd`
  - `cat /var/log/`
  - `INSERT`
  - `UPDATE`
  - `DELETE`
- writes counters to `results/ids.report`

### `applications/nfv/lb1.click`

Implements the virtual HTTP load balancer.

Main behavior:

- responds to ARP requests for virtual service IP `100.0.0.45`
- responds to ICMP echo requests to `100.0.0.45`
- rewrites incoming HTTP traffic from `100.0.0.45:80` to one of the backend servers
- uses `RoundRobinIPMapper` to distribute requests among:
  - `100.0.0.40`
  - `100.0.0.41`
  - `100.0.0.42`
- rewrites server responses so the client sees the virtual service IP instead of the backend server IP
- writes counters to `results/lb1.report`

### `topology/testing.py`

Contains reusable test helpers for:

- ping connectivity
- HTTP curl requests
- IDS blocking behavior
- load-balancing distribution
- NAPT reachability

### `topology/topology_test.py`

Runs the automated test suite. It verifies:

- basic connectivity inside the user zone and backend server zone
- blocking of direct access to backend servers
- ping reachability to the virtual service IP
- NAPT functionality
- load balancer distribution
- IDS method filtering and malicious payload blocking

## Requirements

This project is intended to run inside the IK2221 course VM or a compatible Linux environment with:

- Mininet
- Open vSwitch
- POX
- Click modular router
- Python 3
- curl
- tcpdump

The default POX path used by the Makefile is:

```text
/opt/pox/
```

A different POX directory can be supplied with:

```
make poxdir=/path/to/pox app
```

## How to Run

Open two terminals in the project root.

### Terminal 1: start the controller

```
make app
```

This copies the POX controller files and Click NFV modules into the POX `ext/` directory, then starts the controller.

### Terminal 2: start the topology

```
make topo
```

This starts the Mininet topology and opens the Mininet CLI.

## Run Automated Tests

```
make test
```

The automated tests are defined in `topology/topology_test.py` and `topology/testing.py`.

The existing `phase_1_report` shows a previous run with:

```text
Passed: 13
Failed: 0
Total: 13
Success rate: 100.00%
```

## Clean Up

```
make clean
```

This removes copied controller/NFV files from the POX `ext/` directory, kills POX and Click processes, and cleans Mininet state.
