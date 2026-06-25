import topology
import time
import re

def ping(client, server, expected, count=1, wait=1):
    """
    Test connectivity between client and server using ping.
    
    Args:
        client: Source mininet host
        server: Destination mininet host or IP address
        expected: Expected result (True for success, False for failure)
        count: Number of ping packets to send
        wait: Time to wait between pings in seconds
        
    Returns:
        True if test passed, False otherwise
    """
    if not client:
        print("Error: Client is None")
        return False

    # Get the server IP if server is a string (IP address)
    if isinstance(server, str):
        server_ip = server
    else:
        # Otherwise, use the IP of the server host
        if not server:
            print("Error: Server is None")
            return False
        server_ip = server.IP()
    
    # Run ping with a timeout to avoid hanging
    cmd = f"ping -c {count} -W 2 {server_ip} >/dev/null 2>&1; echo $?"
    ret = client.cmd(cmd)
    ret = ret.strip()
    
    print(f"Ping from {client.name} to {server_ip}: Return code = {ret}")
    
    # Return code 0 means success, anything else is failure
    ping_success = (ret == "0")
    
    # Compare result with expectation
    test_passed = (ping_success == expected)
    
    # Wait specified time
    if wait > 0:
        time.sleep(wait)
    
    if test_passed:
        print(f"PASS: Ping test from {client.name} to {server_ip} {'succeeded' if expected else 'failed'} as expected")
    else:
        print(f"FAIL: Ping test from {client.name} to {server_ip} {'failed' if expected else 'succeeded'} contrary to expectation")
    
    return test_passed


def curl(client, server, method="GET", payload="", port=80, expected=True, timeout=60):
    """
    Run curl for HTTP request. Request method and payload should be specified
    Server can either be a host or a string
    return True in case of success, False if not
    
    Args:
        client: Source mininet host
        server: Destination mininet host or IP address
        method: HTTP method (GET, POST, PUT, etc.)
        payload: HTTP payload data
        port: HTTP port
        expected: Expected result (True for success, False for failure)
        timeout: Timeout for curl request in seconds
        
    Returns:
        True if test passed, False otherwise
    """
    if not client:
        print("Error: Client is None")
        return False

    # Get the server IP if server is a host
    if isinstance(server, str):
        server_ip = server
    else:
        # If it's a string it should be the IP address of the node (e.g., the load balancer)
        if not server:
            print("Error: Server is None")
            return False
        server_ip = server.IP()
    
    print(f"\nTesting HTTP {method} request to {server_ip}:{port}")
    print(f"Expected result: {'SUCCESS' if expected else 'FAIL'}")
    
    # Prepare curl command with proper method and payload
    curl_cmd = f"curl --connect-timeout {timeout} --max-time {timeout} -v -X {method}"
    
    # Add payload for POST/PUT methods
    if payload and method in ["POST", "PUT"]:
        curl_cmd += f" -d '{payload}'"
    
    # Add server and port, redirect output and get return code
    curl_cmd += f" {server_ip}:{port} > /dev/null 2>&1; echo $?"
    
    print(f"Executing: {curl_cmd}")
    
    # Execute the command
    start_time = time.time()
    ret = client.cmd(curl_cmd).strip()
    end_time = time.time()
    
    print(f"Curl {method} from {client.name} to {server_ip}:{port}: Return code = {ret}")
    print(f"Request took {end_time - start_time:.2f} seconds")
    
    # Return code 0 means success, anything else is failure
    curl_success = (ret == "0")
    
    # Compare result with expectation
    test_passed = (curl_success == expected)
    
    if test_passed:
        print(f"PASS: Curl {method} from {client.name} to {server_ip}:{port} {'succeeded' if expected else 'failed'} as expected")
    else:
        print(f"FAIL: Curl {method} from {client.name} to {server_ip}:{port} {'failed' if expected else 'succeeded'} contrary to expectation")
    
    return test_passed


def curl_with_response(client, server, method="GET", payload="", port=80, expected_status=200, timeout=5):
    """
    Run curl for HTTP request and return the response
    
    Args:
        client: Source mininet host
        server: Destination mininet host or IP address
        method: HTTP method (GET, POST, PUT, etc.)
        payload: HTTP payload data
        port: HTTP port
        expected_status: Expected HTTP status code
        timeout: Timeout for curl request in seconds
        
    Returns:
        Tuple of (test_passed, response)
    """
    if not client:
        print("Error: Client is None")
        return False, ""

    # Get the server IP if server is a host
    if isinstance(server, str):
        server_ip = server
    else:
        # If it's a string it should be the IP address of the node (e.g., the load balancer)
        if not server:
            print("Error: Server is None")
            return False, ""
        server_ip = server.IP()
    
    # Prepare curl command with proper method, payload, and output
    curl_cmd = f"curl -v --connect-timeout {timeout} --max-time {timeout} -X {method}"
    
    # Add payload for POST/PUT methods
    if payload and method in ["POST", "PUT"]:
        curl_cmd += f" -d '{payload}'"
    
    # Add server and port, capture response
    curl_cmd += f" {server_ip}:{port} 2>&1"
    
    # Execute the command
    response = client.cmd(curl_cmd)
    print(f"Curl {method} from {client.name} to {server_ip}:{port} response length: {len(response)} chars")
    
    # Check if we got an HTTP status code in the response
    status_match = re.search(r'HTTP/\d\.\d (\d+)', response)
    if status_match:
        status_code = int(status_match.group(1))
        print(f"HTTP Status Code: {status_code}")
        
        # Check if status code matches expected
        status_match = (status_code == expected_status)
        if status_match:
            print(f"PASS: Curl {method} returned expected status code {expected_status}")
        else:
            print(f"FAIL: Curl {method} returned status code {status_code}, expected {expected_status}")
            
        return status_match, response
    else:
        # No HTTP status found in response, likely connection failed
        print(f"FAIL: Curl {method} did not return a valid HTTP response")
        return False, response


def test_ids_blocking(client, server, method, payload, port=80, expected_block=True, timeout=60):
    """
    Test if the IDS is correctly blocking malicious requests
    
    Args:
        client: Source mininet host
        server: Destination mininet host or IP address
        method: HTTP method (GET, POST, PUT, etc.)
        payload: Potentially malicious payload
        port: HTTP port
        expected_block: Whether IDS should block this request
        timeout: Timeout for curl request in seconds
        
    Returns:
        True if test passed, False otherwise
    """
    if not client:
        print("Error: Client is None")
        return False

    # Get the server IP if server is a host
    if isinstance(server, str):
        server_ip = server
    else:
        if not server:
            print("Error: Server is None")
            return False
        server_ip = server.IP()
    
    print(f"Testing IDS with {method} request containing payload: '{payload}'")
    print(f"Expected result: {'BLOCK' if expected_block else 'ALLOW'}")
    
    # Prepare curl command with proper method and payload
    curl_cmd = f"curl --connect-timeout {timeout} --max-time {timeout} -v -X {method}"
    
    # Add payload for appropriate methods
    if payload and method in ["POST", "PUT"]:
        if "cat" in payload or "INSERT" in payload or "DELETE" in payload or "UPDATE" in payload:
            # For malicious payloads, we need to match the format expected by the IDS
            # The IDS is checking the very beginning of the payload
            curl_cmd += f" -d '{payload}'"
        else:
            curl_cmd += f" -d '{payload}'"
    
    # Add server and port, capture both stdout and stderr but only return exit code
    curl_cmd += f" {server_ip}:{port} > /dev/null 2>&1; echo $?"
    
    print(f"Executing: {curl_cmd}")
    
    # Execute the command
    ret = client.cmd(curl_cmd).strip()
    print(f"IDS Test: Curl {method} with payload '{payload}' from {client.name} to {server_ip}:{port}: Return code = {ret}")
    
    # For IDS test, success (code 0) means request was not blocked
    request_succeeded = (ret == "0")
    
    # If expected_block is True, we expect the request to fail (non-zero)
    # If expected_block is False, we expect the request to succeed (zero)
    test_passed = (request_succeeded != expected_block)
    
    if test_passed:
        if expected_block:
            print(f"PASS: IDS correctly blocked malicious {method} request with payload '{payload}'")
        else:
            print(f"PASS: IDS correctly allowed legitimate {method} request with payload '{payload}'")
    else:
        if expected_block:
            print(f"FAIL: IDS failed to block malicious {method} request with payload '{payload}'")
        else:
            print(f"FAIL: IDS incorrectly blocked legitimate {method} request with payload '{payload}'")
    
    return test_passed


def test_load_balancing(client, server_ip, port=80, num_requests=6, timeout=60):
    """
    Test if load balancer is distributing requests among servers
    
    Args:
        client: Source mininet host
        server_ip: Load balancer IP address
        port: HTTP port
        num_requests: Number of requests to send
        timeout: Timeout for curl request in seconds
        
    Returns:
        True if test passed, False otherwise
    """
    if not client:
        print("Error: Client is None")
        return False
    
    # Store server responses and request durations
    server_responses = {}
    request_times = []
    
    print(f"\nTesting load balancing with {num_requests} requests to {server_ip}:{port}")
    print("Note: Using POST method as GET is blocked by IDS")
    
    for i in range(num_requests):
        print(f"\nRequest {i+1}/{num_requests}:")
        
        # Use POST method as it's allowed by IDS
        # Add a unique identifier to help track which server responds
        request_id = f"request_{i+1}"
        curl_cmd = f"curl --connect-timeout {timeout} --max-time {timeout} -s -X POST -d '{request_id}' {server_ip}:{port}"
        
        print(f"Executing: {curl_cmd}")
        start_time = time.time()
        response = client.cmd(curl_cmd)
        end_time = time.time()
        request_time = end_time - start_time
        request_times.append(request_time)
        
        print(f"Request took {request_time:.2f} seconds")
        print(f"Response: {response[:200]}...")  # Show first 200 chars to avoid overflow
        
        # Check if this was a JSON response (will be from POST/PUT requests)
        try:
            import json
            json_response = json.loads(response)
            # For debugging
            print(f"Parsed JSON: {json_response}")
            
            # Extract server ID from the JSON response
            if "server_id" in json_response:
                server_id = json_response["server_id"]
                server_responses[server_id] = server_responses.get(server_id, 0) + 1
                print(f"Request {i+1}: Served by LLM Server #{server_id}")
            else:
                print(f"Request {i+1}: Server ID not found in response")
        except json.JSONDecodeError:
            # Not a JSON response, try to find server identifier in HTML
            server_match = re.search(r'LLM Inference Server (\d+)', response)
            if server_match:
                server_id = server_match.group(1)
                server_responses[server_id] = server_responses.get(server_id, 0) + 1
                print(f"Request {i+1}: Served by LLM Server #{server_id}")
            else:
                print(f"Request {i+1}: Could not identify server in response")
    
    # Calculate and print average request time
    avg_time = sum(request_times) / len(request_times) if request_times else 0
    print(f"\nAverage request time: {avg_time:.2f} seconds")
    
    # Check if at least 2 different servers were used
    if len(server_responses) >= 2:
        print(f"PASS: Load balancer distributed requests among {len(server_responses)} servers")
        print(f"Distribution: {server_responses}")
        return True
    elif len(server_responses) == 1:
        print(f"FAIL: Load balancer only used one server: {list(server_responses.keys())[0]}")
        print(f"Distribution: {server_responses}")
        return False
    else:
        print(f"FAIL: Could not identify any servers in responses")
        return False


def test_napt(client, server_ip, port=80, timeout=60):
    """
    Test if NAPT is correctly translating addresses
    
    Args:
        client: Source mininet host (from user zone)
        server_ip: Server IP address in inferencing zone
        port: HTTP port
        timeout: Timeout for curl request in seconds
        
    Returns:
        True if test passed, False otherwise
    """
    if not client:
        print("Error: Client is None")
        return False
    
    print(f"\nTesting NAPT translation from {client.name} to {server_ip}:{port}")
    
    # Use POST method as GET is blocked by IDS
    curl_cmd = f"curl --connect-timeout {timeout} --max-time {timeout} -v -X POST -d 'napt_test' {server_ip}:{port}"
    
    print(f"Executing: {curl_cmd}")
    
    # Execute the command with timing
    start_time = time.time()
    ret = client.cmd(f"{curl_cmd} > /dev/null 2>&1; echo $?").strip()
    end_time = time.time()
    
    print(f"Request took {end_time - start_time:.2f} seconds")
    print(f"Return code: {ret}")
    
    # Check if request succeeded
    napt_working = (ret == "0")
    
    if napt_working:
        print(f"PASS: NAPT successfully translated request from {client.name} to {server_ip}:{port}")
    else:
        print(f"FAIL: NAPT failed to translate request from {client.name} to {server_ip}:{port}")
    
    return napt_working