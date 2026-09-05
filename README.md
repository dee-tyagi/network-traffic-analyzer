# Signal Trace

A local Streamlit network traffic analyzer for exploring `.pcap`, `.pcapng`, and `.cap` packet captures.

## Features

- Upload and decode packet captures with Scapy
- Filter by protocol and search packet endpoints/details
- Summary metrics for packets, bytes, conversations, and protocols
- Protocol mix and endpoint charts
- Conversation ranking and decoded packet table
- Built-in demo traffic so the interface can be explored immediately

## Run locally

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
streamlit run app.py
```

Open the URL printed by Streamlit, usually `http://localhost:8501`.

## Capture permissions

This app analyzes existing capture files. Capturing live traffic is intentionally separate because it requires OS-level permissions and a capture driver such as Npcap on Windows. You can export a capture from Wireshark and upload it here.
