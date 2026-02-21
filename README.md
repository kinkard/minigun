# Minigun

A minimalistic HTTP load testing tool that replays real-world traffic from pcap files. Originally developed to test Valhalla and OSRM routing engines, but works with any HTTP service.

## Build & Run

```sh
cargo run --release -- --help
```

## Playbook

Capture HTTP requests to your service (replace `192.168.0.1` and `8002` with your target):

```sh
sudo tcpdump -i any dst host 192.168.0.1 and dst port 8002 -w service.pcap
```

Alternative approaches:

- Filter by network interface: `sudo tcpdump -i eth0 dst port 8002 -w service.pcap`
- Capture all traffic to port: `sudo tcpdump -i any dst port 8002 -w service.pcap`

Convert the pcap file to a compact playbook format:

```sh
cargo run --release -- extract service.pcap -o service.playbook
```

Filter for specific endpoints:
```sh
cargo run --release -- extract service.pcap -o service.playbook --filter "/api/"
```

The resulting playbook can be inspected with

```sh
cat service.playbook | capnp convert packed:json schema/playbook.capnp HttpRequest
```

And finally the playbook can be used to measure the latency and throughput

```sh
cargo run --release -- run http://localhost:8002 service.playbook
```

## License

All code in this project is dual-licensed under either:

- [MIT license](https://opensource.org/licenses/MIT) ([`LICENSE-MIT`](LICENSE-MIT))
- [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([`LICENSE-APACHE`](LICENSE-APACHE))

at your option.
