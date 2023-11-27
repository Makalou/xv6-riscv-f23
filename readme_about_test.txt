## To test the function of enabling and disabling udp checksum when receiving udp packet.
1 Run the following command in xv6 to enable udp checksum
netPFTest enable_udp_checksum
2 Open another terminal in directory: xv6-riscv-f23, and run command: make server
This command will run a python script, to receive network packet from the xv6 and send packet to xv6.
3 Run nettests in xv6
4 Will see the debug information, "enable_udp_checksum_filter", which indicate the udp checksum is used to sift packet.
5 Run the command netPFTest, to disable udp checksum filter
6 Run nettests in xv6, the debug info "enable_udp_checksum_filter" will not be printed, which indicates the udp checksum is not used.

The above process will not affect other ubpf application.
