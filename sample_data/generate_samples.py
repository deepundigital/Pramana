"""
Sample Data Generator: Generates realistic synthetic evidence:
1. Synthetic PCAP with normal HTTPS traffic and Cobalt Strike C2 beaconing.
2. Synthetic Android WhatsApp SQLite database (msgstore.db) with Hinglish extortion & UPI mule transfers.
3. Synthetic Linux auth.log with SSH brute-force attempts.
"""

import sqlite3
import time
from pathlib import Path
from scapy.all import Ether, IP, TCP, Raw, wrpcap

from sutra_net.config import SAMPLE_DATA_DIR


def generate_synthetic_pcap(output_path: Path):
    """
    Creates a realistic synthetic PCAP containing normal HTTPS traffic
    and a periodic malicious Cobalt Strike C2 beacon.
    """
    packets = []
    base_time = time.time() - 3600

    # 1. Normal HTTPS Browsing (Variable inter-arrival time and sizes)
    for i in range(40):
        t = base_time + (i * 2.5) + (i % 3) * 0.4
        pkt = (
            Ether() /
            IP(src="192.168.1.105", dst="142.250.190.46") /
            TCP(sport=51234 + i, dport=443, flags="PA") /
            Raw(load=b"\x16\x03\x01\x00\xa0" + b"A" * (120 + (i * 15) % 800))
        )
        pkt.time = t
        packets.append(pkt)

    # 2. Malicious Cobalt Strike C2 Beacon (Strict 10-second periodic heartbeat, small uniform payloads)
    for i in range(25):
        # 10s period with tiny micro-jitter (< 0.1s)
        t = base_time + (i * 10.0) + ((i % 2) * 0.05)
        # Malicious JA3 payload signature representation
        load = (
            b"\x16\x03\x03\x01\x00" +
            b"\x00\x00\x00\x00" +
            b"COBALT_BEACON_PAYLOAD_TEST_" + str(i).encode()
        )
        pkt = (
            Ether() /
            IP(src="192.168.1.105", dst="198.51.100.77") / # Suspicious External C2 IP
            TCP(sport=49882, dport=8443, flags="PA") /
            Raw(load=load)
        )
        pkt.time = t
        packets.append(pkt)

    packets.sort(key=lambda p: p.time)
    wrpcap(str(output_path), packets)
    print(f"Generated synthetic PCAP at {output_path} ({len(packets)} packets)")


def generate_synthetic_whatsapp_db(output_path: Path):
    """
    Creates an Android WhatsApp SQLite database with Hinglish extortion,
    fake loan harassment, and UPI mule account transfers.
    """
    if output_path.exists():
        output_path.unlink()

    conn = sqlite3.connect(output_path)
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE jid (
        _id INTEGER PRIMARY KEY AUTOINCREMENT,
        raw_string TEXT NOT NULL
    );
    """)

    cur.execute("""
    CREATE TABLE message (
        _id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_jid_row_id INTEGER,
        timestamp INTEGER,
        text_data TEXT,
        from_me INTEGER DEFAULT 0
    );
    """)

    # Populate JIDs (suspects, mule accounts, victim)
    jids = [
        (1, "9876543210@s.whatsapp.net"),   # Primary Suspect / Recovery Agent
        (2, "9123456780@s.whatsapp.net"),   # Mule Account Handler
        (3, "9998887776@s.whatsapp.net"),   # Victim
    ]
    cur.executemany("INSERT INTO jid VALUES (?, ?);", jids)

    base_ts = int((time.time() - 86400) * 1000)

    # Realistic Hinglish messages
    messages = [
        (1, base_ts + 10000, "Hello sir, aapka instant loan approve ho gaya hai. Verify karne ke liye details bhejo.", 0),
        (3, base_ts + 20000, "Mujhe koi loan nahi chahiye, aap kaun ho?", 1),
        (1, base_ts + 30000, "Aapka pan card update karo turant payment karo warna police case hoga aur account freeze kar denge.", 0),
        (1, base_ts + 45000, "Last warning! FIR darj ho chuki hai. Rs 45,000 transfer karo directly on UPI: rajesh.mule@oksbi ya 9876543210@paytm pe!", 0),
        (3, base_ts + 60000, "Please arrest mat karo, main paise bhej raha hoon.", 1),
        (2, base_ts + 75000, "Bhai payment aa gaya 45000 from victim. Next cut transfer to syndicate account: cashout99@ybl UTR: 429188291048.", 0),
        (1, base_ts + 90000, "Daroga ko bol diya hai. Agar aur 25,000 nahi diya toh jail bhejenge. Jaldi transfer karo!", 0),
    ]

    cur.executemany("INSERT INTO message (sender_jid_row_id, timestamp, text_data, from_me) VALUES (?, ?, ?, ?);", messages)
    conn.commit()
    conn.close()
    print(f"Generated synthetic WhatsApp DB at {output_path}")


def generate_synthetic_syslog(output_path: Path):
    """
    Creates a synthetic Linux syslog with SSH brute-force and privilege escalation alerts.
    """
    lines = [
        "Oct 18 22:14:01 ip-10-0-0-15 sshd[14201]: Failed password for invalid user admin from 198.51.100.77 port 48212 ssh2",
        "Oct 18 22:14:05 ip-10-0-0-15 sshd[14205]: Failed password for invalid user test from 198.51.100.77 port 48218 ssh2",
        "Oct 18 22:14:10 ip-10-0-0-15 sshd[14210]: Failed password for root from 198.51.100.77 port 48224 ssh2",
        "Oct 18 22:14:18 ip-10-0-0-15 sshd[14215]: Accepted password for ubuntu from 198.51.100.77 port 48230 ssh2",
        "Oct 18 22:15:02 ip-10-0-0-15 sudo:   ubuntu : TTY=pts/1 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/bin/bash",
        "Oct 18 22:16:40 ip-10-0-0-15 kernel: [89421.120] audit: type=1102 msg=audit(1697667400.120:98): audit log cleared by root"
    ]
    with open(output_path, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"Generated synthetic syslog at {output_path}")


if __name__ == "__main__":
    generate_synthetic_pcap(SAMPLE_DATA_DIR / "sample_network.pcap")
    generate_synthetic_whatsapp_db(SAMPLE_DATA_DIR / "sample_msgstore.db")
    generate_synthetic_syslog(SAMPLE_DATA_DIR / "sample_syslog.log")
