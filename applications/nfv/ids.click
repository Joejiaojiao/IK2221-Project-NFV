define($INTERFACE_SWITCH ids-eth1, $INTERFACE_INSPECTION ids-eth2, $INTERFACE_SERVER ids-eth3)
define($NETWORK_INTERNAL 10.0.0.0/24, $NETWORK_EXTERNAL 100.0.0.0/24)

counter_input_switch, counter_input_server, counter_output_switch, counter_output_server :: AverageCounter;
counter_arp_request, counter_arp_response :: Counter;
counter_ipv4_from_switch, counter_ipv4_from_server :: Counter;
counter_icmp_traffic, counter_tcp_ack_packets, counter_tcp_syn_packets :: Counter;
counter_http_requests, counter_http_put_requests, counter_http_post_requests :: Counter;
counter_inspection_output :: Counter;
counter_attack_password_file, counter_attack_log_directory :: Counter;
counter_attack_sql_insert, counter_attack_sql_update, counter_attack_sql_delete :: Counter;
counter_dropped_switch, counter_dropped_server, counter_dropped_other :: Counter;

FromDevice($INTERFACE_SWITCH, METHOD LINUX, SNIFFER false) -> counter_input_switch;
FromDevice($INTERFACE_SERVER, METHOD LINUX, SNIFFER false) -> counter_input_server;

to_switch_interface :: Queue -> counter_output_switch -> Print("IDS: Forwarding to switch", -1) -> ToDevice($INTERFACE_SWITCH, METHOD LINUX);
to_server_interface :: Queue -> counter_output_server -> Print("IDS: Forwarding to server", -1) -> ToDevice($INTERFACE_SERVER, METHOD LINUX);
to_inspection_interface :: Queue -> counter_inspection_output -> Print("IDS: Forwarding to inspection", -1) -> ToDevice($INTERFACE_INSPECTION, METHOD LINUX);

packet_classifier_from_switch :: Classifier(
    12/0806,  // ARP    
    12/0800,  // IPv4
    -         // Everything else
);

packet_classifier_from_server :: Classifier(
    12/0806,  // ARP
    12/0800,  // IPv4
    -         // Everything else
);

ip_protocol_classifier :: IPClassifier(
    proto icmp && icmp type echo,  // ICMP Echo
    fin ack,                       // TCP ACK+FIN
    syn,                           // TCP SYN
    http,                          // HTTP
    -                              // Everything else
);

http_method_classifier :: Classifier(
    // PUT
    66/505554,
    // POST
    66/504F5354,
    // others
    -
);

attack_pattern_classifier :: Classifier(
    // cat/etc/passwd
    0/636174202F6574632F706173737764,
    // cat/var/log/
    0/636174202F7661722F6C6F672F,
    // INSERT
    0/494E53455254,
    // UPDATE
    0/555044415445,
    // DELETE
    0/44454C455445,
    // others (legitimate traffic)
    -
);

counter_input_switch -> packet_classifier_from_switch;
counter_input_server -> packet_classifier_from_server;

packet_classifier_from_switch[0] -> Print("IDS: ARP request detected, forwarding", -1) 
                                 -> counter_arp_request 
                                 -> to_server_interface;

packet_classifier_from_switch[1] -> Print("IDS: IPv4 packet from switch", -1) 
                                 -> Strip(14) 
                                 -> CheckIPHeader 
                                 -> counter_ipv4_from_switch 
                                 -> ip_protocol_classifier;

packet_classifier_from_switch[2] -> Print("IDS: Non-IP/ARP packet from switch, dropping", -1) 
                                 -> counter_dropped_switch 
                                 -> Discard;

// Handle traffic from server
packet_classifier_from_server[0] -> Print("IDS: ARP response detected, forwarding", -1) 
                                  -> counter_arp_response 
                                  -> to_switch_interface;

packet_classifier_from_server[1] -> Print("IDS: IPv4 packet from server, forwarding", -1) 
                                  -> counter_ipv4_from_server 
                                  -> to_switch_interface;

packet_classifier_from_server[2] -> Print("IDS: Non-IP/ARP packet from server, dropping", -1) 
                                  -> counter_dropped_server 
                                  -> Discard;

ip_protocol_classifier[0] -> Unstrip(14) 
                           -> Print("IDS: ICMP echo detected, forwarding", -1) 
                           -> counter_icmp_traffic 
                           -> to_server_interface;

ip_protocol_classifier[1] -> Unstrip(14) 
                           -> Print("IDS: TCP ACK+FIN detected, forwarding", -1) 
                           -> counter_tcp_ack_packets 
                           -> to_server_interface;

ip_protocol_classifier[2] -> Unstrip(14) 
                           -> Print("IDS: TCP SYN detected, forwarding", -1) 
                           -> counter_tcp_syn_packets 
                           -> to_server_interface;

ip_protocol_classifier[3] -> Unstrip(14) 
                           -> Print("IDS: HTTP traffic detected", -1)  
                           -> counter_http_requests 
                           -> http_method_classifier;

ip_protocol_classifier[4] -> Print("IDS: Unclassified IP packet, dropping", -1) 
                           -> counter_dropped_other 
                           -> Discard;

payload_scanner :: Search("\r\n\r\n")
payload_scanner[0] -> Print("IDS: HTTP payload inspection", -1) -> attack_pattern_classifier;
payload_scanner[1] -> Print("IDS: Suspicious HTTP header structure, inspecting", -1) -> to_inspection_interface;

http_method_classifier[0] -> Print("IDS: HTTP PUT detected", -1) 
                           -> counter_http_put_requests 
                           -> payload_scanner;

http_method_classifier[1] -> Print("IDS: HTTP POST detected, forwarding", -1) 
                           -> counter_http_post_requests 
                           -> to_server_interface;

http_method_classifier[2] -> Print("IDS: Unclassified HTTP method, inspecting", -1) 
                           -> to_inspection_interface;

attack_pattern_classifier[0] -> Print("IDS ALERT: Password file access attempt detected!", -1) 
                              -> counter_attack_password_file 
                              -> UnstripAnno() 
                              -> to_inspection_interface;

attack_pattern_classifier[1] -> Print("IDS ALERT: Log directory access attempt detected!", -1) 
                              -> counter_attack_log_directory 
                              -> UnstripAnno() 
                              -> to_inspection_interface;

attack_pattern_classifier[2] -> Print("IDS ALERT: SQL INSERT detected!", -1) 
                              -> counter_attack_sql_insert 
                              -> UnstripAnno() 
                              -> to_inspection_interface;

attack_pattern_classifier[3] -> Print("IDS ALERT: SQL UPDATE detected!", -1) 
                              -> counter_attack_sql_update 
                              -> UnstripAnno() 
                              -> to_inspection_interface;

attack_pattern_classifier[4] -> Print("IDS ALERT: SQL DELETE detected!", -1) 
                              -> counter_attack_sql_delete 
                              -> UnstripAnno() 
                              -> to_inspection_interface;

attack_pattern_classifier[5] -> Print("IDS: No attack pattern detected in PUT, forwarding", -1) 
                              -> UnstripAnno() 
                              -> to_server_interface;

DriverManager(wait, print > /home/ik2221/IK2221-team5/Phase1/results/ids.report "
      ====================== Intrusion Detection System Report ======================
      
      System Status: Active
      Monitoring Interfaces: $INTERFACE_SWITCH, $INTERFACE_SERVER, $INTERFACE_INSPECTION
      
      -------------- Traffic Statistics --------------
      Input Packet rate (pps): $(add $(counter_input_switch.rate) $(counter_input_server.rate))
      Output Packet rate (pps): $(add $(counter_output_switch.rate) $(counter_output_server.rate))

      Total incoming packets: $(add $(counter_input_switch.count) $(counter_input_server.count))
      Total outgoing packets: $(add $(counter_output_switch.count) $(counter_output_server.count))
 
      IPv4 packet distribution:
        - From switch: $(counter_ipv4_from_switch.count)
        - From server: $(counter_ipv4_from_server.count)
        - Total: $(add $(counter_ipv4_from_switch.count) $(counter_ipv4_from_server.count))
      
      Protocol distribution:
        - ARP requests: $(counter_arp_request.count)
        - ARP responses: $(counter_arp_response.count)
        - ICMP traffic: $(counter_icmp_traffic.count)
        - TCP ACK packets: $(counter_tcp_ack_packets.count) 
        - TCP SYN packets: $(counter_tcp_syn_packets.count)
      
      HTTP traffic analysis:
        - Total HTTP packets: $(counter_http_requests.count)
        - HTTP PUT requests: $(counter_http_put_requests.count)
        - HTTP POST requests: $(counter_http_post_requests.count) 
      
      -------------- Security Events --------------
      Attack patterns detected:
        - Password file access attempts: $(counter_attack_password_file.count)
        - Log directory access attempts: $(counter_attack_log_directory.count)
        - SQL INSERT statements: $(counter_attack_sql_insert.count)
        - SQL UPDATE statements: $(counter_attack_sql_update.count)
        - SQL DELETE statements: $(counter_attack_sql_delete.count)
        - Total attacks detected: $(add $(counter_attack_password_file.count) 
                                       $(counter_attack_log_directory.count) 
                                       $(counter_attack_sql_insert.count) 
                                       $(counter_attack_sql_update.count) 
                                       $(counter_attack_sql_delete.count))
      
      Traffic handling:
        - Packets forwarded to inspection: $(counter_inspection_output.count)
        - Packets dropped: $(add $(counter_dropped_switch.count) 
                                $(counter_dropped_server.count) 
                                $(counter_dropped_other.count))
      
      ========================================================================
    ", 
    stop
);