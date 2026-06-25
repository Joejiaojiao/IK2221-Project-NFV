define($LOADBALANCER_IP 100.0.0.45)
define($INTERFACE_CLIENT lb1-eth1)
define($INTERFACE_SERVER lb1-eth2)
define($SERVER1_IP 100.0.0.40)
define($SERVER2_IP 100.0.0.41)
define($SERVER3_IP 100.0.0.42)
define($HTTP_PORT 80)

stat_in_pkts_cli, stat_in_pkts_srv, stat_out_pkts_cli, stat_out_pkts_srv :: AverageCounter;
stat_in_bytes_cli, stat_in_bytes_srv, stat_out_bytes_cli, stat_out_bytes_srv :: AverageCounter;
stat_arp_req_cli, stat_arp_req_srv, stat_arp_res_cli, stat_arp_res_srv :: Counter;
stat_ip_pkts_cli, stat_ip_pkts_srv :: Counter;
stat_tcp_pkts_cli, stat_tcp_pkts_srv :: Counter;
stat_icmp_echo_req, stat_icmp_echo_rep :: Counter;
stat_drop_l3_cli, stat_drop_l3_srv, stat_drop_tcp_cli, stat_drop_tcp_oth, stat_drop_tcp_srv :: Counter;


FromDevice($INTERFACE_CLIENT, METHOD LINUX, SNIFFER false) -> stat_in_pkts_cli -> stat_in_bytes_cli;
FromDevice($INTERFACE_SERVER, METHOD LINUX, SNIFFER false) -> stat_in_pkts_srv -> stat_in_bytes_srv;

out_to_cli :: Queue -> stat_out_pkts_cli -> stat_out_bytes_cli -> ToDevice($INTERFACE_CLIENT, METHOD LINUX);
out_to_srv :: Queue -> stat_out_pkts_srv -> stat_out_bytes_srv -> ToDevice($INTERFACE_SERVER, METHOD LINUX);

cls_l2_cli, cls_l2_srv :: Classifier(
    12/0806 20/0001, // ARP request
    12/0806 20/0002, // ARP response
    12/0800,          // IPv4
    -                 // others
);

cls_l3_cli :: IPClassifier(
    dst $LOADBALANCER_IP and icmp,                // ICMP
    dst $LOADBALANCER_IP port $HTTP_PORT and tcp, // TCP HTTP
    tcp,                                          // Other TCP
    -                                             // others
);

cls_l3_srv :: IPClassifier(
    dst $LOADBALANCER_IP and icmp type echo,   // ICMP to lb
    src port $HTTP_PORT and tcp,               // TCP HTTP
    -                                          // others
);

stat_in_bytes_cli -> cls_l2_cli;
stat_in_bytes_srv -> cls_l2_srv;

res_arp_cli :: ARPQuerier($LOADBALANCER_IP, $INTERFACE_CLIENT);
res_arp_srv :: ARPQuerier($LOADBALANCER_IP, $INTERFACE_SERVER);
ans_arp_cli :: ARPResponder($LOADBALANCER_IP $INTERFACE_CLIENT);
ans_arp_srv :: ARPResponder($LOADBALANCER_IP $INTERFACE_SERVER);

res_icmp_cli :: ICMPPingResponder;
res_icmp_srv :: ICMPPingResponder;

path_ip_cli :: GetIPAddress(16) -> CheckIPHeader -> [0]res_arp_cli -> out_to_cli;
path_ip_srv :: GetIPAddress(16) -> CheckIPHeader -> [0]res_arp_srv -> out_to_srv;

rr_balancer_map :: RoundRobinIPMapper(
    $LOADBALANCER_IP - $SERVER1_IP - 0 1,
    $LOADBALANCER_IP - $SERVER2_IP - 0 1,
    $LOADBALANCER_IP - $SERVER3_IP - 0 1
);

nat_rewriter :: IPRewriter(rr_balancer_map);
nat_rewriter[0] -> path_ip_srv;
nat_rewriter[1] -> path_ip_cli;


cls_l2_cli[0] -> stat_arp_req_cli -> ans_arp_cli -> out_to_cli;
cls_l2_cli[1] -> stat_arp_res_cli -> [1]res_arp_cli;
cls_l2_cli[2] -> stat_ip_pkts_cli -> Strip(14) -> CheckIPHeader -> cls_l3_cli;
cls_l2_cli[3] -> stat_drop_l3_cli -> Discard;

cls_l3_cli[0] -> stat_icmp_echo_req -> res_icmp_cli -> path_ip_cli;
cls_l3_cli[1] -> stat_tcp_pkts_cli -> [0]nat_rewriter;
cls_l3_cli[2] -> stat_drop_tcp_oth -> Discard;
cls_l3_cli[3] -> stat_drop_tcp_cli -> Discard;

cls_l2_srv[0] -> stat_arp_req_srv -> ans_arp_srv -> out_to_srv;
cls_l2_srv[1] -> stat_arp_res_srv -> [1]res_arp_srv;
cls_l2_srv[2] -> stat_ip_pkts_srv -> Strip(14) -> CheckIPHeader -> cls_l3_srv;
cls_l2_srv[3] -> stat_drop_l3_srv -> Discard;

cls_l3_srv[0] -> stat_icmp_echo_rep -> res_icmp_srv -> path_ip_srv;
cls_l3_srv[1] -> stat_tcp_pkts_srv -> [0]nat_rewriter;
cls_l3_srv[2] -> stat_drop_tcp_srv -> Discard;

DriverManager(wait, print > /home/ik2221/IK2221-team5/Phase1/results/lb1.report "
        =============== Load Balancer Report ===============
        Traffic Summary:
        ------------------------
        Client Input:  $(stat_in_pkts_cli.count) packets ($(stat_in_bytes_cli.count) bytes)
        Server Input:  $(stat_in_pkts_srv.count) packets ($(stat_in_bytes_srv.count) bytes)
        Client Output: $(stat_out_pkts_cli.count) packets ($(stat_out_bytes_cli.count) bytes)
        Server Output: $(stat_out_pkts_srv.count) packets ($(stat_out_bytes_srv.count) bytes)
        
        Packet Rates:
        ------------------------
        Input Rate (pps):  $(add $(stat_in_pkts_cli.rate) $(stat_in_pkts_srv.rate))
        Output Rate (pps): $(add $(stat_out_pkts_cli.rate) $(stat_out_pkts_srv.rate))
        
        Protocol Breakdown:
        ------------------------
        ARP Requests:     $(add $(stat_arp_req_cli.count) $(stat_arp_req_srv.count))
        ARP Responses:    $(add $(stat_arp_res_cli.count) $(stat_arp_res_srv.count))
        IP Packets:       $(add $(stat_ip_pkts_cli.count) $(stat_ip_pkts_srv.count))
        TCP Packets:      $(add $(stat_tcp_pkts_cli.count) $(stat_tcp_pkts_srv.count))
        ICMP Echo Req:    $(stat_icmp_echo_req.count)
        ICMP Echo Reply:  $(stat_icmp_echo_rep.count)
        
        Error Statistics:
        ------------------------
        Dropped Non-IP:   $(add $(stat_drop_l3_cli.count) $(stat_drop_l3_srv.count))
        Dropped Non-TCP:  $(add $(stat_drop_tcp_cli.count) $(stat_drop_tcp_oth.count) $(stat_drop_tcp_srv.count))
        Total Dropped:    $(add $(stat_drop_l3_cli.count) $(stat_drop_l3_srv.count) $(stat_drop_tcp_cli.count) $(stat_drop_tcp_oth.count) $(stat_drop_tcp_srv.count))
        ====================================================",
stop);