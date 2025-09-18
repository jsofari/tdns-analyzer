# Technitium DNS Log Analyzer

Tools untuk analisis log DNS **Technitium DNS Server**.  
Membantu mendeteksi anomali query, flood, atau serangan berbasis DNS dengan dua mode:

- **Batch mode (`tdns_qps_monitor.py`)**  
  Rekap query per menit per client (QPM), bisa disimpan ke CSV.
- **Live mode (`tdns_qps_top.py`)**  
  Tampilan real-time ala `fastnetmon` / `top`, menampilkan QPS, peak, NxDomain%, Ref%, dan alert threshold.

---

## 🚀 Install

Clone repo ini dan pastikan Python 3 tersedia:

```bash
git clone https://github.com/<username>/technitium-dns-analyzer.git
cd technitium-dns-analyzer
chmod +x tdns_qps_monitor.py tdns_qps_top.py
```

# Proses log terbaru di /etc/dns/logs, summary sekali lalu keluar
python3 tdns_qps_monitor.py \
  --logdir /etc/dns/logs \
  --pattern "*.log" \
  --once \
  --from-beginning \
  --top 20 \
  --output-csv qpm.csv

# Mode live, refresh layar tiap 2 detik, window analisis 60 detik
python3 tdns_qps_top.py \
  --logdir /etc/dns/logs \
  --pattern "*.log" \
  --interval 2 \
  --window 60 \
  --rows 20 \
  --from-beginning \
  --alert-qps 200 \
  --alert-nxdomain 60 \
  --alert-refused 20
  
## Fitur 
- Hitung QPM (queries per minute) per IP
- Threshold alert --qpm-threshold
- Output CSV: minute,client,qpm
- Bisa jalan sekali (--once) atau tailing live
- QPS(60s): rata-rata query per detik
- Peak(1s): query terbanyak dalam 1 detik
- NxDom%: persentase query dengan RCODE: NxDomain
- Ref%: persentase query dengan RCODE: Refused
- Alerts: threshold configurable, dengan cooldown untuk cegah spam

