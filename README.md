# DeepTrace-DPI 🚀

DeepTrace-DPI is a high-performance Deep Packet Inspection (DPI) engine written in C++ that analyzes PCAP network traffic, classifies applications using TLS SNI, supports rule-based blocking, and provides evaluation and benchmarking.

---

## 🔥 Features

* PCAP parsing (Ethernet, IPv4, TCP)
* Bidirectional flow tracking
* TLS SNI extraction
* Application classification:

  * Google
  * YouTube
  * Facebook
  * Instagram
  * X (Twitter)
* Rule-based blocking:

  * Block by application
  * Block by domain
* CSV prediction export
* Evaluation (accuracy + confusion matrix)
* Benchmarking support (performance measurement)

---

## ⚙️ Build Instructions

```bash
mkdir build
cd build
cmake ..
cmake --build . --config Release
```

---

## ▶️ Basic Run

```bash
./Release/deeptrace_dpi.exe ../data/test_dpi.pcap 20
```

### 📌 Sample Output

```
FLOW CLASSIFIED: 142.250.185.206:443 <-> 192.168.1.100:54552 proto=TCP app=Google domain=www.google.com
FLOW CLASSIFIED: 142.250.185.110:443 <-> 192.168.1.100:58867 proto=TCP app=YouTube domain=www.youtube.com
FLOW CLASSIFIED: 157.240.1.35:443 <-> 192.168.1.100:64044 proto=TCP app=Facebook domain=www.facebook.com
FLOW CLASSIFIED: 157.240.1.174:443 <-> 192.168.1.100:58747 proto=TCP app=Instagram domain=www.instagram.com
FLOW CLASSIFIED: 104.244.42.65:443 <-> 192.168.1.100:59993 proto=TCP app=X domain=twitter.com
```

---

## 🚫 Blocking Example

```bash
./Release/deeptrace_dpi.exe ../data/test_dpi.pcap 20 --block-app YouTube --block-domain facebook
```

### 📌 Output
<img width="779" height="132" alt="image" src="https://github.com/user-attachments/assets/83a68bc7-b5fd-4f0d-9824-5a5ea72f03aa" />

```
[blocked/classified] 142.250.185.110:443 <-> 192.168.1.100:58867 proto=TCP app=YouTube block_reason=app:YouTube
[blocked/classified] 157.240.1.35:443 <-> 192.168.1.100:64044 proto=TCP app=Facebook block_reason=domain:facebook
[allowed/classified] 104.244.42.65:443 <-> 192.168.1.100:59993 proto=TCP app=X domain=twitter.com
```

---

## 📊 Prediction Output (CSV)

```bash
./Release/deeptrace_dpi.exe ../data/test_dpi.pcap 20 --pred-out predictions.csv
```

### 📌 predictions.csv
<img width="779" height="132" alt="image" src="https://github.com/user-attachments/assets/44e4fa8a-4717-4c57-987a-182118420fcc" />

```
flow_id,predicted_app,domain,packet_count,byte_count
142.250.185.206:443 <-> 192.168.1.100:54552 proto=TCP,Google,www.google.com,4,300
104.244.42.65:443 <-> 192.168.1.100:59993 proto=TCP,X,twitter.com,4,297
142.250.185.110:443 <-> 192.168.1.100:58867 proto=TCP,YouTube,www.youtube.com,4,301
157.240.1.35:443 <-> 192.168.1.100:64044 proto=TCP,Facebook,www.facebook.com,4,302
157.240.1.174:443 <-> 192.168.1.100:58747 proto=TCP,Instagram,www.instagram.com,4,303
```

---

## 📈 Evaluation

```bash
python ../scripts/eval.py --pred predictions.csv --labels ../data/labels.csv
```

### 📌 Output
<img width="626" height="526" alt="image" src="https://github.com/user-attachments/assets/b230d6f0-e975-419d-b4c9-410ed41e9b57" />

```
Accuracy: 0.8000

Confusion matrix:

actual\pred   Facebook   Google   Instagram   Twitter   X   YouTube
Facebook         1          0          0          0      0      0
Google           0          1          0          0      0      0
Instagram        0          0          1          0      0      0
Twitter          0          0          0          0      1      0
YouTube          0          0          0          0      0      1
```

---

## ⚡ Benchmark

```bash
powershell -ExecutionPolicy Bypass -File ../scripts/bench.ps1
```

### 📌 Output  
<img width="366" height="131" alt="image" src="https://github.com/user-attachments/assets/cd3e834f-f097-4093-a5b4-e3c5194e8475" />

```
Run 1: 0.001584 s
Run 2: 0.001422 s
Run 3: 0.001168 s
Run 4: 0.002361 s
Run 5: 0.002815 s

Average runtime over 5 runs: 0.001870 s
```

---

## 📊 Performance

* Average runtime: **~1.87 ms**
* Packets processed: **20**
* Throughput: ~600 packets/sec (sample test)

---

## 🧠 How It Works

1. Parse PCAP packets (Ethernet → IPv4 → TCP)
2. Track bidirectional flows using 5-tuple
3. Extract TLS SNI from packets
4. Map domain → application
5. Apply blocking rules (if enabled)
6. Export predictions + evaluation + metrics

---

## 🛠 Tech Stack

* C++
* CMake
* PowerShell (benchmarking)
* Python (evaluation)

---

## 🎯 Use Cases

* Network traffic analysis
* Application identification
* Security monitoring
* Content filtering systems

---

## 👩‍💻 Author

**Aastha Singh**

---

## ⭐ Project Highlights

* Real-world system-level project
* End-to-end pipeline (parsing → classification → evaluation → performance)
* Lightweight, fast, and modular design
