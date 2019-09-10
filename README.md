# RIST main profile Wireshark plugin

This Wireshark plugin dissects GRE over UDP protocol (RFC 8086), with GRE extensions defined by RIST main profile (VSF TR-06-02).
It works when GRE headers are not encrypted (no DTLS).

To use it-
- place the attached file in the Wireshark program folder
- include it at the end of 'init.lua' with: dofile(DATA_DIR.."gre_over_udp.lua")

It opens an option of "GREoUDP" in the "Decode as..." dialog.
It arbitrarily register UDP port 5000 by default.
