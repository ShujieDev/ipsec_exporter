# IPsec Exporter
Prometheus exporter for ipsec metrics, written in Go.
(forked from https://github.com/dennisstritzke/ipsec_exporter)

## Functionality
The IPsec exporter is determining the state of the configured IPsec tunnels via the following procedure.
1. Starting up with requesting `list-conn` in the vici api. All tunnels configured are added to a list.
2. If the `/metrics` endpoint is queried, the exporter calls `list-sa`.
    * If the IKE_SA has state `ESTABLISHED`, we assume that only the connection is up.
    * If the CHILD_SA has state `INSTALLED`, we assume that the tunnel is up and running.
    * If the tunnel can not be found from the `list-sa` call, we assume that the connection is down.

## Value Definition
| Metric | Value | Description |
|--------|-------|-------------|
| ipsec_status | 0 | The connection is established and tunnel is installed. The tunnel is up and running. |
| ipsec_status | 1 | The connection is established, but the tunnel is not up. |
| ipsec_status | 2 | The tunnel is down. |
| ipsec_status | 3 | The tunnel is in an unknown state. |
| ipsec_status | 4 | The tunnel is ignored. |
