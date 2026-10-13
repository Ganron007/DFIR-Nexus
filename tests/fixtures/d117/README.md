# D117 fixtures: real Zeek, Suricata and tshark outputs (public sample captures)

Produced on the SIFT host on 2026-10-13, outside any case, to pin the raw column names the ECS map and the category
rules use. Nothing here is case evidence, and nothing here was indexed. The folders mirror the layout the lane writes
(`extractions/network/<capture>/zeek`, `.../suricata`, `ingest/network/<capture>-flows.csv`), because the walker and the
reader key on names and folders.

- Captures: Zeek's public test traces (zeek/zeek, testing/btest/Traces): `http/bro.org.pcap`, `dns53.pcap` and
  `conn-size.pcap`. SHA-256 of each capture as run:
  - bro.org.pcap (zeek/conn.log): db39186852a33f676c9cb6ea2841d5f70776ea54185754a80c73e57c40d96994
  - dns53.pcap (zeek/dns.log, suricata/eve.json): 02324d91deb3853f2c2f498db36dfc7f1018946a48d2fc50e825dff1d9309a2c
  - conn-size.pcap (suricata/eve.json, flows): fe4c4cda617518de5663697cc8ba8483b42d9de951b7204087caf173b1b162e2
- `zeek/http-bro-org/conn.log` and `zeek/dns53/dns.log`: Zeek 9.0.0, run as `zeek -Cr <capture> local
  Log::default_logdir=<dir>`, the lane's own argv. Their `#fields` lines are the column names.
- `suricata/conn-size/eve.json` (flow and alert events) and `suricata/dns53/eve.json` (dns events): Suricata 8.0.7 with the
  Emerging Threats Open ruleset from `suricata-update` (2026-10-13), run as `suricata -k none -r <capture> -S suricata.rules
  -l <dir>` with a copy of the system config whose paths point at the sample folders. Some ET Open DNP3 signatures do
  not parse under Suricata 8.0.7; they were skipped.
- `network/conn-size/capture-flows.csv`: `nexus.langgraph.network_lane.project_flows` (tshark) run on conn-size.pcap, the
  projection the lane writes as `ingest/network/<stem>-flows.csv`.
