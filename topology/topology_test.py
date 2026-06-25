from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Switch
from mininet.cli import CLI
from mininet.node import RemoteController
from mininet.node import OVSSwitch
from topology import *
import testing
import time
import sys
import os


topos = {'mytopo': (lambda: MyTopo())}


def run_tests(net):
    """
    Run all test scenarios to verify network functionality
    """
    print("\n============== RUNNING AUTOMATED TESTS ==============")
    
    # Get hosts from the net
    h1 = net.get('h1')
    h2 = net.get('h2')
    insp = net.get('insp')
    llm1 = net.get('llm1')
    llm2 = net.get('llm2')
    llm3 = net.get('llm3')

    # The virtual service IP for the load balancer
    lb_service_ip = "100.0.0.45"
    
    # Track test results
    test_results = {"passed": 0, "failed": 0}
    
    # Give the network time to initialize
    print("\nWaiting for network to initialize...")
    time.sleep(5)
    
    # ===== Test 1: Basic Connectivity Tests =====
    print("\n----- Test 1: Basic Connectivity Tests -----")
    
    # Test 1.1: Hosts in user zone can ping each other
    if testing.ping(h1, h2, True):
        test_results["passed"] += 1
    else:
        test_results["failed"] += 1
    
    # Test 1.2: Hosts in inferencing zone can ping each other
    if testing.ping(llm1, llm2, True):
        test_results["passed"] += 1
    else:
        test_results["failed"] += 1
    
    # Test 1.3: User zone hosts cannot directly ping inferencing zone hosts
    # (NAPT should block direct access)
    if testing.ping(h1, llm1, False):
        test_results["passed"] += 1
    else:
        test_results["failed"] += 1
    
    # Test 1.4: User zone hosts can ping the virtual service IP (load balancer)
    if testing.ping(h1, lb_service_ip, True):
        test_results["passed"] += 1
    else:
        test_results["failed"] += 1
    
    # ===== Test 2: NAPT Functionality =====
    print("\n----- Test 2: NAPT Functionality -----")
    
    # Test 2.1: HTTP request through NAPT to the virtual service IP (using POST since GET is blocked)
    if testing.curl(h1, lb_service_ip, "POST", "test_data", 80, True, timeout=60):
        test_results["passed"] += 1
    else:
        test_results["failed"] += 1
    
    # Test 2.2: NAPT translation test
    if testing.test_napt(h2, lb_service_ip, 80, timeout=60):
        test_results["passed"] += 1
    else:
        test_results["failed"] += 1
    
    # ===== Test 3: Load Balancer Functionality =====
    print("\n----- Test 3: Load Balancer Functionality -----")
    
    # Test 3.1: Load balancer distributes requests among servers
    if testing.test_load_balancing(h1, lb_service_ip, 80, num_requests=6, timeout=60):
        test_results["passed"] += 1
    else:
        test_results["failed"] += 1
    
    # ===== Test 4: IDS Functionality Tests =====
    print("\n----- Test 4: IDS Functionality Tests -----")
    
    # Test 4.1: IDS allows legitimate POST request
    if testing.test_ids_blocking(h1, lb_service_ip, "POST", "legitimate_data", expected_block=False, timeout=60):
        test_results["passed"] += 1
    else:
        test_results["failed"] += 1
    
    # Test 4.2: IDS blocks requests with malicious payload - cat /etc/passwd
    if testing.test_ids_blocking(h1, lb_service_ip, "PUT", "cat /etc/passwd", expected_block=True, timeout=60):
        test_results["passed"] += 1
    else:
        test_results["failed"] += 1
    
    # Test 4.3: IDS blocks requests with malicious payload - SQL DELETE
    if testing.test_ids_blocking(h1, lb_service_ip, "PUT", "DELETE FROM users", expected_block=True, timeout=60):
        test_results["passed"] += 1
    else:
        test_results["failed"] += 1
    
    # Test 4.4: IDS blocks requests with malicious payload - SQL INSERT
    if testing.test_ids_blocking(h1, lb_service_ip, "PUT", "INSERT INTO users VALUES", expected_block=True, timeout=60):
        test_results["passed"] += 1
    else:
        test_results["failed"] += 1
    
    # Test 4.5: IDS blocks unauthorized HTTP methods
    if testing.test_ids_blocking(h1, lb_service_ip, "DELETE", "", expected_block=True, timeout=60):
        test_results["passed"] += 1
    else:
        test_results["failed"] += 1
    
    # ===== Test 5: HTTP Method Tests =====
    print("\n----- Test 5: HTTP Method Tests -----")
    
    # Test 5.1: GET request should be blocked by IDS
    if testing.curl(h1, lb_service_ip, "GET", "", 80, False, timeout=60):
        test_results["passed"] += 1
        print("PASS: GET request correctly blocked by IDS")
    else:
        test_results["failed"] += 1
        print("FAIL: GET request not properly blocked by IDS")
    
    # # Test 5.2: POST request should be allowed
    # if testing.curl(h1, lb_service_ip, "POST", "test_data", 80, True, timeout=60):
    #     test_results["passed"] += 1
    #     print("PASS: POST request correctly allowed through IDS")
    # else:
    #     test_results["failed"] += 1
    #     print("FAIL: POST request not properly passed through IDS")
    
    # # Test 5.3: PUT request with legitimate data should be allowed
    # if testing.curl(h1, lb_service_ip, "PUT", "legitimate_update", 80, True, timeout=60):
    #     test_results["passed"] += 1
    #     print("PASS: Legitimate PUT request correctly allowed through IDS")
    # else:
    #     test_results["failed"] += 1
    #     print("FAIL: Legitimate PUT request not properly passed through IDS")
    
    # ===== Print Test Summary =====
    print("\n============== TEST SUMMARY ==============")
    print(f"Passed: {test_results['passed']}")
    print(f"Failed: {test_results['failed']}")
    print(f"Total: {test_results['passed'] + test_results['failed']}")
    print(f"Success rate: {(test_results['passed'] / (test_results['passed'] + test_results['failed'])) * 100:.2f}%")
    print("=========================================")
    
    # Check if all files are captured correctly
    print("\nVerifying captured files:")
    
    # Check for PCAP file in inspector
    insp.cmd("ls -l /tmp/ids_capture.pcap")
    
    # Check for Click reports
    os.system("ls -l *.report 2>/dev/null || echo 'No report files found'")
    

if __name__ == "__main__":
    # Create topology
    topo = MyTopo()

    ctrl = RemoteController("c0", ip="127.0.0.1", port=6633)

    # Create the network
    net = Mininet(topo=topo,
                  switch=OVSSwitch,
                  controller=ctrl,
                  autoSetMacs=True,
                  autoStaticArp=True,
                  build=True,
                  cleanup=True)

    # Start the network
    net.start()

    # Initialize services
    print("Starting network services...")
    startup_services(net)
    
    # Give time for services to start
    time.sleep(5)
    
    # Run the automated tests if specified
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        run_tests(net)
        # Skip CLI if auto-testing
        pass
    else:
        # Run the tests
        run_tests(net)
        
        # Start the CLI
        CLI(net)

    # Any cleanup before stopping the network
    # Commands to save PCAP files, report files, etc.
    print("Stopping network and saving results...")
    

    # Stop the network
    net.stop()