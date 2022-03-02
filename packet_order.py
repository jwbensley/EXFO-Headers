#!/usr/bin/env python3
# $ sudo apt-get install tshark
import json
import re
import statistics
import subprocess as sp
import sys

def pcap_to_hex(filename: str) -> list:
    """
    Return all the frames in a capture file as a list of hex strings.
    One long hex string per packet.
    """
    cmds = ["tshark", "-x", "-r", filename, "-T", "json"]
    frames_text = sp.check_output(cmds, text=True)
    frames_json = json.loads(frames_text)
    hexstreams = [frame["_source"]["layers"]["frame_raw"][0] for frame in frames_json]
    return hexstreams


pkt_data = pcap_to_hex(sys.argv[1])
print(f"{len(pkt_data)} packets decoded from {sys.argv[1]}")

"""
Example FTB-860 NetBlaze 2.10 EXFO header:
0x45 58 46 F4 0A 00 68 00 00 00 90 DC C6 EA 27 00 0D FF

^ This is 4x 4-byte fields, and a 2-byte trailer.

Bytes 0-3:   0x45 58 46 F4 "EXFO" start of header marker

Bytes 4-7:   0x0A 00 68 00 This is the stream number and options.
1st seems to always be 0x0A?
2nd byte is the stream number (0 is 1st stream).
3rd & 4th bytes are stream options (e.g. single port or dual port).

Bytes 8-11:  0x00 00 90 DC Frame seq number (32b int that wraps)

Bytes 12-15: 0xC6 EA 27 00 Timestamp of Tx of this frame from tester internal
clock. The unit is the period of a byte in old STM-1 aggregates:
8x1000/155.52 ns = 51.44 ns
The diff between two consecutive timestamps is the delay between each frame Tx.
Example of these 4 bytes from 4 consecutive frames:
0xD7 93 A2 0E == 3616776718
0xD7 94 4E 96 == 3616820886 (+44168)
0xD7 94 FB 1D == 3616865053 (+44167)
0xD7 95 A7 A5 == 3616909221 (+44168)

A diff of 44168 means: (44168 x 51.44 ns)/1000/1000 = 2.272 ms
When looking at the PCAP in Wireshark this matched the field:
"Time delta from previous captured frame: 0.002272620 seconds"

Based on the time delta we can calculate the pps rate and througput, because
we know the frame size (from the PCAP):
EXFO was sending 1500 byte frames.
Pps == 1/0.00227262 = 440.020768980296 pps
Data rate == (440.0207 * 1500)*8/1000/1000 == 5.2802484Mbps.
Which is roughly correct, the EXFO was set to 5Mbps @ 1500 bytes.

Bytes 16-17: 0x0D FF Trailer of EXFO header.
These two bytes never change and are also 0D FF, which is the last two bytes
of this EXFOs MAC address. Over many tests they are always 0D FF, so not sure
if they are meant to by last 2 bytes of MAC or if that is just a coincidence.
Everthing after these two bytes is random per-frame garbage.
"""

"""
How many bytes to strip from the start of the frame, e.g. core MPLS headers.
Start from 0, this is the first byte of the destination MAC in the EXFO
generated test frame. For example, in an MPLS L2 VPN, this points to the first
byte of the L2 VPN destination MAC field, after all the core Ethernet and MPLS
headers.
Set to 0 to disable this front-stripping.
"""
core_offset = 30

"""
If some non-EXFO frames are included in this PCAP (using the MPLS L2 VPN
example again, maybe some CFM frames, or other LAN traffic), we can exclude
them by checking the Ethertype. EXFO sets the Ethertype to 0x00 0x00 for test
frames. Set this to the byte offset of the Ethertype value, after the core
above (if any).
# 12 if EXFO traffic is VLAN untagged.
# 16 if single tagged.
# 22 if double tagged.
"""
ethertype_offset = 16 


# DO NOT EDIT THESE OFFSETS:
exfo_offset = (core_offset*2) + (ethertype_offset*2) + 4
etype_start = (core_offset*2) + (ethertype_offset*2)
etype_end = etype_start + 4
seq_vals = []
ts_vals = []
seq_start = exfo_offset + 16 # Chars not bytes, pks decoded to hex str
seq_end = seq_start + 8
ts_start = seq_end
ts_end = ts_start + 8


# Totals found in PCAP
exfo_pkts = 0
other_pkts = 0
lost_pkts = 0
seq_ooo = 0
known_ooo = []

for idx, _ in enumerate(pkt_data):
    etype = int(pkt_data[idx][etype_start:etype_end], 16)
    if etype == 0:
        exfo_pkts += 1
        seq_vals.append(pkt_data[idx][seq_start:seq_end])
        ts_vals.append(pkt_data[idx][ts_start:ts_end])
    else:
        other_pkts += 1


# Skip the first packet
for i in range(1, len(seq_vals)-1):

    seq_diff = int(seq_vals[i], 16) - int(seq_vals[i-1], 16)

    if seq_diff > 1:
        """
        Out of order sequence number found.
        The frame could be out of order, and exist somewhere else in this pcap.
        The frame could be dropped.
        """
        if (int(seq_vals[i], 16) in known_ooo or
            int(seq_vals[i-1],16) in known_ooo):
            """
            This frame is the one from before/after a frame which came earlier
            in the pcap, so this OOO event is already known about.
            """
            continue

        # Otherwise it's a new OOO frame...
        seq_ooo += 1
        known_ooo.append(int(seq_vals[i], 16))
        known_ooo.append(int(seq_vals[i-1], 16))
        known_ooo.append(int(seq_vals[i-1], 16)+1)
        print(
            f"Out of sequence packet found: seq diff is {hex(int(seq_vals[i],16) - int(seq_vals[i-1],16))} {int(seq_vals[i],16) - int(seq_vals[i-1],16)}\n"
            f"Pkt {i-1}: seq 0x{seq_vals[i-1]} {int(seq_vals[i-1],16)} {int(seq_vals[i-1][0:2],16)}.{int(seq_vals[i-1][2:4],16)}.{int(seq_vals[i-1][4:6],16)}.{int(seq_vals[i-1][6:],16)}\n"
            f"Pkt {i}: seq 0x{seq_vals[i]} {int(seq_vals[i],16)} {int(seq_vals[i][0:2],16)}.{int(seq_vals[i][2:4],16)}.{int(seq_vals[i][4:6],16)}.{int(seq_vals[i][6:],16)}\n"
            f"Seq num is {seq_diff-1} packet(s) early/late"
        )

        """
        Check if the 32bit sequence number has wrapped around,
        assume we have < 2^32 packets in the pcap
        """
        if seq_diff > 1000000:
            print("Assuming counter wrap-around an not packet loss or ordering!")
            seq_ooo -= 1
            print("")
            continue

        # Missing/in-between sequence numbers:
        missing = [f'{m:08x}' for m in range(int(seq_vals[i-1], 16) + 1, int(seq_vals[i], 16))]
        missing_2 = missing.copy()
        for m in missing:
            if m in seq_vals:
                #print(f"Found inbetween seq num {m} at pkt {seq_vals.index(m)}")
                missing_2.remove(m)

        if missing_2:
            print(f"Found {len(missing) - len(missing_2)} inbetween seq nums")
            print(f"Couldn't find {len(missing_2)} sequence number(s) in pcap, assume lost?")
            for m in missing_2:
                f"Missing seq 0x{m} {int(m,16)} {int(m[0:2],16)}.{int(m[2:4],16)}.{int(m[4:6],16)}.{int(m[6:],16)}\n"
            lost_pkts += len(missing_2)
        else:
            print(f"Found all {len(missing) - len(missing_2)} inbetween seq nums in pcap, none are missing")
        print("")


# Skip the first packet
ts_diffs = []
for i in range(1, len(ts_vals)-1):
    ts_diffs.append(int(ts_vals[i], 16) - int(ts_vals[i-1], 16))

print("\n")
print(f"Non-EXFO packets found: {other_pkts}")
print(f"EXFO packets found: {exfo_pkts}")
print(f"Total SEQ OOO: {seq_ooo}")
print(f"Total lost packets: {lost_pkts}")
print(f"Mean timestamp diff {(statistics.mean(ts_diffs)*51.44)/1000/1000:.2f}ms")
print(f"Mode timestamp diff {(statistics.mode(ts_diffs)*51.44)/1000/1000:.2f}ms")
print(f"Median timestamp diff {(statistics.median(ts_diffs)*51.44)/1000/1000:.2f}ms")
