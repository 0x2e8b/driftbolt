"""Sycope Traffic Recorder: alert-triggered PCAP extraction service.

Sycope calls POST /extract with an alert; this package builds a BPF
filter from it, runs npcapextract against the n2disk rolling capture,
and returns a download URL for the extracted PCAP.
"""
