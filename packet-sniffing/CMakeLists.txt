cmake_minimum_required(VERSION 3.25)
project(packet_sniffing C)

set(CMAKE_C_STANDARD 11)

add_executable(packet_sniffing sniff_spoof.c sniff_spoof.c send_pkt.c)

target_link_libraries(packet_sniffing pcap)