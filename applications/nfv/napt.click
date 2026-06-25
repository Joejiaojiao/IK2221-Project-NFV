//================ BASIC CONFIG ================

define($UZ_INTERFACE napt-eth1, $IZ_INTERFACE napt-eth2)
define($UZ_IP 10.0.0.1, $IZ_IP 100.0.0.1)
define($UZ_MAC 00:00:00:01:03:06, $IZ_MAC 00:00:00:01:04:14)
define($PORT_RANGE 1024-65535)

input_counter_UZ :: AverageCounter;
input_counter_IZ :: AverageCounter;

counter_tcp_UZ :: Counter;
counter_tcp_IZ :: Counter;

counter_icmp_UZ :: Counter;
counter_icmp_IZ :: Counter;

counter_dropped_UZ_other :: Counter;
counter_dropped_UZ_icmp_reply :: Counter;
counter_dropped_UZ_other_ip :: Counter;

counter_dropped_IZ_other :: Counter;
counter_dropped_IZ_icmp_req :: Counter;
counter_dropped_IZ_other_ip :: Counter;

FromDevice($UZ_INTERFACE, METHOD LINUX, SNIFFER false)
    -> input_counter_UZ;

FromDevice($IZ_INTERFACE, METHOD LINUX, SNIFFER false)
    -> input_counter_IZ;

output_device_UZ ::
    Queue
    -> output_counter_UZ :: AverageCounter
    -> ToDevice($UZ_INTERFACE, METHOD LINUX);

output_device_IZ ::
    Queue
    -> output_counter_IZ :: AverageCounter
    -> ToDevice($IZ_INTERFACE, METHOD LINUX);

classifier_UZ, classifier_IZ :: Classifier(
    12/0806 20/0001,        //ARP request
    12/0806 20/0002,        //ARP reply
    12/0800,                //IPv4 packet
    -                       //Other
);

ip_classifier_UZ, ip_classifier_IZ :: IPClassifier(
    tcp,                    //TCP
    icmp type echo,         //ICMP echo request
    icmp type echo-reply,   //ICMP echo reply
    -                       //Other
);

arp_responder_UZ ::
    ARPResponder($UZ_IP $UZ_MAC);       //find MAC address

arp_responder_IZ ::
    ARPResponder($IZ_IP $IZ_MAC);

arp_querier_UZ ::
    ARPQuerier($UZ_IP, $UZ_MAC);

arp_querier_IZ ::
    ARPQuerier($IZ_IP, $IZ_MAC);

tcp_translator ::
    IPRewriter(pattern $IZ_IP $PORT_RANGE - - 0 1);

icmp_translator ::
    ICMPPingRewriter(pattern $IZ_IP - - - 0 1);

input_counter_UZ -> classifier_UZ;

classifier_UZ[0]
    -> Print("[UserZone] ARP Request")
    -> arp_responder_UZ
    -> output_device_UZ;

classifier_UZ[1]
    -> Print("[UserZone] ARP Reply")
    -> [1]arp_querier_UZ;

classifier_UZ[2]
    -> Print("[UserZone] IP Packet")
    -> Strip(14)
    -> CheckIPHeader
    -> ip_classifier_UZ;

classifier_UZ[3]
    -> Print("[UserZone] Discard")
    -> counter_dropped_UZ_other
    -> Discard;

ip_classifier_UZ[0]
    -> Print("[UserZone] TCP Packet")
    -> counter_tcp_UZ
    -> tcp_translator[0]
    -> Print("[UserZone->InferZone] Translated TCP")
    -> [0]arp_querier_IZ
    -> output_device_IZ;

ip_classifier_UZ[1]
    -> Print("[UserZone] ICMP Echo Request")
    -> counter_icmp_UZ
    -> icmp_translator[0]
    -> Print("[UserZone->InferZone] Translated ICMP")
    -> [0]arp_querier_IZ
    -> output_device_IZ;

ip_classifier_UZ[2]
    -> Print("[UserZone] ICMP Echo Reply - Discarded")
    -> counter_dropped_UZ_icmp_reply
    -> Discard;

ip_classifier_UZ[3]
    -> Print("[UserZone] Other IP - Discarded")
    -> counter_dropped_UZ_other_ip
    -> Discard;

input_counter_IZ -> classifier_IZ;

classifier_IZ[0]
    -> Print("[InferZone] ARP Request")
    -> arp_responder_IZ
    -> output_device_IZ;

classifier_IZ[1]
    -> Print("[InferZone] ARP Reply")
    -> [1]arp_querier_IZ;

classifier_IZ[2]
    -> Print("[InferZone] IP Packet")
    -> Strip(14)
    -> CheckIPHeader
    -> ip_classifier_IZ;

classifier_IZ[3]
    -> Print("[InferZone] Discard")
    -> counter_dropped_IZ_other
    -> Discard;

ip_classifier_IZ[0]
    -> Print("[InferZone] TCP Packet")
    -> counter_tcp_IZ
    -> tcp_translator[1]
    -> Print("[InferZone->UserZone] Translated TCP")
    -> [0]arp_querier_UZ
    -> output_device_UZ;

ip_classifier_IZ[1]
    -> Print("[InferZone] ICMP Echo Request - Discarded")
    -> counter_dropped_IZ_icmp_req
    -> Discard;

ip_classifier_IZ[2]
    -> Print("[InferZone] ICMP Echo Reply")
    -> counter_icmp_IZ
    -> icmp_translator[1]
    -> Print("[InferZone->UserZone] Translated ICMP")
    -> [0]arp_querier_UZ
    -> output_device_UZ;

ip_classifier_IZ[3]
    -> Print("[InferZone] Other IP - Discarded")
    -> counter_dropped_IZ_other_ip
    -> Discard;

DriverManager(
    wait,
    print > /home/ik2221/IK2221-team5/Phase1/results/napt.report "

=================== NAPT Report ===================

Input UserZone packets:  $(input_counter_UZ.count)
Input InferZone packets: $(input_counter_IZ.count)

Output UserZone packets:  $(output_counter_UZ.count)
Output InferZone packets: $(output_counter_IZ.count)

UserZone TCP packets:  $(counter_tcp_UZ.count)
UserZone ICMP packets: $(counter_icmp_UZ.count)

InferZone TCP packets:  $(counter_tcp_IZ.count)
InferZone ICMP packets: $(counter_icmp_IZ.count)

Dropped UserZone Other:      $(counter_dropped_UZ_other.count)
Dropped UserZone ICMP Reply: $(counter_dropped_UZ_icmp_reply.count)
Dropped UserZone Other IP:   $(counter_dropped_UZ_other_ip.count)

Dropped InferZone Other:     $(counter_dropped_IZ_other.count)
Dropped InferZone ICMP Req:  $(counter_dropped_IZ_icmp_req.count)
Dropped InferZone Other IP:  $(counter_dropped_IZ_other_ip.count)

===================================================

",
    stop
);