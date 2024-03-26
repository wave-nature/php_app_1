<form method="post" action="">
    Enter URL: <input type="text" name="url">
    <input type="submit" value="Get Wayback URLs">
</form><br><br>
<?php


// Function to fetch URLs from Wayback Machine
function fetchWaybackURLs($url) {
    $api_url = "https://web.archive.org/cdx/search/cdx?url=*.$url/*&output=text&fl=original&collapse=urlkey";
    $response = @file_get_contents($api_url); // Suppress warning using @ symbol
    if ($response !== false) {
        $lines = explode("\n", $response);
        $wayback_urls = [];
        foreach ($lines as $line) {
            $wayback_url = trim($line);
            if (!empty($wayback_url) && strpos($wayback_url, '?') !== false) {
                $wayback_urls[] = $wayback_url;
            }
        }
       
        return $wayback_urls;
    } else {
        return false; // Return false if unable to fetch content
    }
}

// Function to modify parameter values with "><img src=x onerror=alert(1)>
function modifyParameterValues($url) {
    $parsed_url = parse_url($url);
    $query_string = isset($parsed_url['PHP_URL_QUERY']) ? $parsed_url['PHP_URL_QUERY'] : '';
    parse_str($query_string, $query_parameters);
    foreach ($query_parameters as &$value) {
        $value = '"><img src=x onerror=alert(1)>';
    }
    $encoded_query_string = http_build_query($query_parameters);
    $modified_url = $parsed_url['scheme'] . '://' . $parsed_url['host'] . $parsed_url['path'] . '?' . $encoded_query_string;
    return $modified_url;
    print_r($modified_url);
    exit();
}

// Function to check if response contains alert(1)
function checkAlert($url) {
    try {
        $response = @file_get_contents($url); // Suppress warning using @ symbol
        if ($response !== false) {
            return strpos($response, 'alert(1)') !== false;
        } else {
            return false; // Return false if unable to fetch content
        }
    } catch (Exception $e) {
        return false; // Return false if an exception occurs
    }
}


function addProtocolHeader($url) {
    // Check if the URL starts with "http://" or "https://"
    if (!preg_match("~^(?:f|ht)tps?://~i", $url)) {
        // If not, assume http:// and append it
        $url = "http://" . $url;
    }
    return $url;
}

// Function to check for Clickjacking vulnerability
function checkClickjacking($url) {
    // Add protocol header if missing
    $url = addProtocolHeader($url);

    $headers = get_headers($url, 1);

    $result = array();

    if (isset($headers['Content-Security-Policy'])) {
        $csp_header = $headers['Content-Security-Policy'];
        if (strpos($csp_header, 'frame-ancestors \'none\'') !== false) {
            $result['status'] = "Not vulnerable";
            $result['details'] = "CSP frame-ancestors directive is set to 'none'.";
        } else {
            $result['status'] = "Vulnerable";
            $result['details'] = "CSP does not mitigate clickjacking.";
        }
    } elseif (isset($headers['X-Frame-Options'])) {
        $x_frame_options = $headers['X-Frame-Options'];
        if (strpos($x_frame_options, 'DENY') !== false || strpos($x_frame_options, 'SAMEORIGIN') !== false) {
            $result['status'] = "Not vulnerable";
            $result['details'] = "X-Frame-Options header is set to DENY or SAMEORIGIN.";
        } else {
            $result['status'] = "Vulnerable";
            $result['details'] = "X-Frame-Options does not mitigate clickjacking.";
        }
    } else {
        $result['status'] = "Vulnerable";
        $result['details'] = "No clickjacking protection headers found.";
    }

    return json_encode($result);
}


// Function to check for Clickjacking vulnerability
function checkSecurityHeaders($url) {
    // Add protocol header if missing
    $url = addProtocolHeader($url);

    $headers = get_headers($url, 1);
    $x_xss_protection = isset($headers['X-XSS-Protection']) ? $headers['X-XSS-Protection'] : null;
    $csp_header = isset($headers['Content-Security-Policy']) ? $headers['Content-Security-Policy'] : null;

    $result = array();

    if ($csp_header && strpos($csp_header, 'frame-ancestors \'none\'') !== false) {
        $result['csp'] = "Not vulnerable to Clickjacking (CSP frame-ancestors directive)";
    } else {
        $result['csp'] = "Vulnerable to Clickjacking (CSP does not mitigate)";
    }

    if ($x_xss_protection && $x_xss_protection === '1; mode=block') {
        $result['x_xss_protection'] = "X-XSS-Protection header set to 1; mode=block (Protected against XSS)";
    } else {
        $result['x_xss_protection'] = "X-XSS-Protection header not set to 1; mode=block (Considered vulnerable)";
    }

    return json_encode($result);
}

function checkServerHeader($url) {
    // Add protocol header if missing
    $url = addProtocolHeader($url);

    $headers = get_headers($url, 1);
    $server_header = isset($headers['Server']) ? $headers['Server'] : null;

    $result = array();

    if ($server_header) {
        foreach($server_header as $product){
            $result['status'] = "Server header present";
            $result['product'] = $product;
        }
        
    } else {
        $result['status'] = "Server header not set";
    }

    return json_encode($result);
}


function checkXPoweredByHeader($url) {
    // Add protocol header if missing
    $url = addProtocolHeader($url);

    $headers = get_headers($url, 1);
    $x_powered_by_header = isset($headers['X-Powered-By']) ? $headers['X-Powered-By'] : null;

    $result = array();

    if ($x_powered_by_header) {
        $result['status'] = "X-Powered-By header present";
        $result['value'] = $x_powered_by_header;
    } else {
        $result['status'] = "X-Powered-By header not set";
    }

    return json_encode($result);
}


function checkCORSVulnerability($url) {
    // Add protocol header if missing
    $url = addProtocolHeader($url);

    $headers = get_headers($url, 1);
    $cors_headers = [];

    foreach ($headers as $key => $value) {
        if (strpos($key, 'Access-Control-Allow-Origin') === 0) {
            $cors_headers[$key] = $value;
        }
    }

    $result = array();

    foreach ($cors_headers as $header) {
        if ($header === '*') {
            $result['status'] = "CORS policy set to allow all origins ('*')";
            $result['vulnerability'] = "Potentially vulnerable";
            return json_encode($result);
        }
    }

    $result['status'] = "CORS policy not set to allow all origins ('*')";
    $result['vulnerability'] = "Considered secure";
    return json_encode($result);
}


function getHttpResponseCode($url) {
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true); // Follow redirects
    curl_setopt($ch, CURLOPT_HEADER, true); // Include header in output
    curl_setopt($ch, CURLOPT_NOBODY, true); // Exclude body from output
    curl_exec($ch);
    $response_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    $result = array(
        'url' => $url,
        'response_code' => $response_code
    );

    return json_encode($result);
}

// Function to check if the website is running WordPress
function isWordPress($url) {
    // Add protocol header if missing
    $url = addProtocolHeader($url);

    $content = file_get_contents($url);

    $result = array(
        'url' => $url,
        'isWordPress' => (stripos($content, 'wp-content') !== false) ? true : false
    );

    return json_encode($result);
}


// Function to check for known WordPress vulnerabilities
function checkWordPressVulnerabilities($url) {
    // Add protocol header if missing
    $url = addProtocolHeader($url);

    $wordpress_version = getWordPressVersion($url);

    $result = array(
        'url' => $url,
        'wordpress_version' => $wordpress_version
    );

    if ($wordpress_version) {
        // Check if WordPress version has known vulnerabilities
        $vulnerabilities = getWordPressVulnerabilities($wordpress_version);
        if ($vulnerabilities) {
            $result['message'] = "WordPress version $wordpress_version has known vulnerabilities";
            $result['vulnerabilities'] = $vulnerabilities;
        } else {
            $result['message'] = "WordPress version $wordpress_version is up to date (No known vulnerabilities)";
        }
    } else {
        $result['message'] = "Unable to determine WordPress version (Not running WordPress or not accessible)";
    }

    return json_encode($result);
}


// Function to get the WordPress version
function getWordPressVersion($url) {
    // Add protocol header if missing
    $url = addProtocolHeader($url);

    $content = file_get_contents($url);
    preg_match('/<meta name="generator" content="WordPress (\d+\.\d+\.\d+)"/i', $content, $matches);

    $result = array(
        'url' => $url,
        'wordpress_version' => isset($matches[1]) ? $matches[1] : false
    );

    return json_encode($result);
}


// Function to get known WordPress vulnerabilities for a given version
function getWordPressVulnerabilities($version) {
    // You need to implement this function to fetch known vulnerabilities for a given WordPress version
    // This could involve querying a database, accessing an API, or using a predefined list of vulnerabilities
    // For demonstration purposes, we'll return a hardcoded list of vulnerabilities
    // $known_vulnerabilities = [
    //     'WP-001: XSS vulnerability in comments section',
    //     'WP-002: SQL Injection vulnerability in plugin XYZ',
    //     // Add more vulnerabilities here if needed
    // ];
    // return implode("\n", $known_vulnerabilities);
}

// Function to check for login page disclosure
function checkLoginPageDisclosure($url) {
    // Add protocol header if missing
    $url = addProtocolHeader($url);

    $login_page_url = rtrim($url, '/') . '/wp-login.php';
    $response_code = getHttpResponseCode($login_page_url);

    $result = array(
        'url' => $url,
        'login_page_url' => $login_page_url,
        'status' => ($response_code === 200) ? "Login page is accessible" : "Login page is not accessible or not found"
    );

    return json_encode($result);
}


// Function to check for WP REST API user enumeration
function checkWPAPIUserEnumeration($url) {
    // Add protocol header if missing
    $url = addProtocolHeader($url);

    $user_endpoint_url = rtrim($url, '/') . '/wp-json/wp/v2/users';
    $response_code = getHttpResponseCode($user_endpoint_url);

    $result = array(
        'url' => $url,
        'user_endpoint_url' => $user_endpoint_url,
        'status' => ($response_code === 200) ? "WP REST API users endpoint is accessible (Potential user enumeration vulnerability)" : "WP REST API users endpoint is not accessible or not found"
    );

    return json_encode($result);
}


// Function to check for SSRF and brute force potential via XML-RPC
function checkXMLRPC($url) {
    // Add protocol header if missing
    $url = addProtocolHeader($url);

    $xmlrpc_url = rtrim($url, '/') . '/xmlrpc.php';
    $response_code = getHttpResponseCode($xmlrpc_url);

    $result = array(
        'url' => $url,
        'xmlrpc_url' => $xmlrpc_url
    );

    if ($response_code === 405) {
        $result['status'] = "XML-RPC is enabled but method not allowed (Potential SSRF or brute force vulnerability)";
    } elseif ($response_code === 200) {
        $result['status'] = "XML-RPC is enabled (Potential SSRF or brute force vulnerability)";
    } else {
        $result['status'] = "XML-RPC is not enabled or not found";
    }

    return json_encode($result);
}


function checkCookiePolicySecurity($url) {
    // Initialize cURL session
    $ch = curl_init();

    // Set cURL options
    curl_setopt($ch, CURLOPT_URL, $url); // Set URL
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true); // Return the transfer as a string
    curl_setopt($ch, CURLOPT_HEADER, true); // Include header in output
    curl_setopt($ch, CURLOPT_NOBODY, true); // Exclude body from output

    // Execute cURL request
    $response = curl_exec($ch);
    $header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    $headers = substr($response, 0, $header_size);

    // Close cURL session
    curl_close($ch);

    // Check for secure cookie attribute
    if (stripos($headers, 'Set-Cookie:') !== false) {
        if (stripos($headers, 'Set-Cookie: Secure') !== false) {
            $secure_cookie = true;
        } else {
            $secure_cookie = false;
        }
    } else {
        // No Set-Cookie header found
        $secure_cookie = null;
    }

    // Check for HTTPOnly cookie attribute
    if (stripos($headers, 'Set-Cookie: HTTPOnly') !== false) {
        $httponly_cookie = true;
    } else {
        $httponly_cookie = false;
    }

    // Construct scan result message
    $result = array(
        'url' => $url,
        'secure_cookie' => $secure_cookie,
        'httponly_cookie' => $httponly_cookie
    );

    return json_encode($result);
}



function checkCookieDisclaimer($url) {
    // Initialize cURL session
    $ch = curl_init();

    // Set cURL options
    curl_setopt($ch, CURLOPT_URL, $url); // Set URL
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true); // Return the transfer as a string

    // Execute cURL request
    $content = curl_exec($ch);

    // Close cURL session
    curl_close($ch);

    // Check if the content contains a cookie disclaimer
    $cookie_disclaimer_found = (stripos($content, 'cookie') !== false && stripos($content, 'disclaimer') !== false);

    // Construct result message
    $result = array(
        'url' => $url,
        'cookie_disclaimer_found' => $cookie_disclaimer_found ? 'Cookie Disclaimer found' : 'Cookie Disclaimer not found'
    );

    return json_encode($result);
}



function checkStrictTransportSecurity($url) {
    // Initialize cURL session
    $ch = curl_init();

    // Set cURL options
    curl_setopt($ch, CURLOPT_URL, $url); // Set URL
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true); // Return the transfer as a string
    curl_setopt($ch, CURLOPT_HEADER, true); // Include header in output

    // Execute cURL request
    $response = curl_exec($ch);
    $header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    $headers = substr($response, 0, $header_size);

    // Close cURL session
    curl_close($ch);

    // Check for Strict-Transport-Security header
    $sts_header_found = (stripos($headers, 'Strict-Transport-Security') !== false);

    // Construct result message
    $result = array(
        'url' => $url,
        'sts_header_found' => $sts_header_found ? 'Strict-Transport-Security header found' : 'Strict-Transport-Security header not found'
    );

    return json_encode($result);
}



function enumerateDirectoriesAndFiles($url) {
    $paths = [
        "/", // Root path
        "/robots.txt",
        "/.htaccess",
        "/phpinfo.php",
        "/admin/",
        "/wp-login.php",
        "/wp-admin/",
        "/login/",
        "/.git/config",
        "/.git/HEAD",
    ];

    $results = [];

    foreach ($paths as $path) {
        $full_url = rtrim($url, "/") . $path;
        $response_code = getHttpResponseCode($full_url);

        if ($response_code != 404) {
            $results[] = array(
                'url' => $full_url,
                'status_code' => $response_code
            );
        }
    }

    return json_encode($results);
}


// Function to get HTTP response code

// Check if URL is provided in the form submission
if(isset($_POST['url'])) {
    $url = $_POST['url'];
    $clickjacking_result = checkClickjacking($url);
    echo "Clickjacking Scan Result for $url: <br>";
    // echo $clickjacking_result;
    $security_results = checkSecurityHeaders($url);
    echo "Security Headers Scan Result for $url: <br>";
    // echo "CSP: {$security_results['csp']}<br>";
    // echo "X-XSS-Protection: {$security_results['x_xss_protection']}";

    $server_result = checkServerHeader($url);
    // echo "Server Header Scan Result for $url: <br>";
    // echo $server_result;

    $x_powered_by_result = checkXPoweredByHeader($url);
    // echo "X-Powered-By Header Scan Result for $url: <br>";
    // echo $x_powered_by_result;

    $cors_result = checkCORSVulnerability($url);
    // echo "CORS Scan Result for $url: <br>";
    // echo $cors_result;


    $cookie = checkCookiePolicySecurity($url);
    // echo $cookie;

    $cookie_des = checkCookieDisclaimer($url);
    echo $cookie_des;

    $transfer = checkStrictTransportSecurity($url);
    echo $transfer;


    $enumeration_results = enumerateDirectoriesAndFiles($url);

    // Display enumeration results
    if (!empty($enumeration_results)) {
        echo "Directory and File Enumeration Results for $url:\n";
        foreach ($enumeration_results as $result) {
            echo "- $result\n";
        }
    } else {
        echo "No directories or files found.\n";
    }

    echo"<br>";

    if (isWordPress($url)) {
        $wordpress_result = checkWordPressVulnerabilities($url);
        $login_page_result = checkLoginPageDisclosure($url);
        $wpapi_result = checkWPAPIUserEnumeration($url);
        $xmlrpc_result = checkXMLRPC($url);

        echo "WordPress Vulnerability Scan Result for $url: <br>";
        echo nl2br($wordpress_result . "\n");
        echo nl2br($login_page_result . "\n");
        echo nl2br($wpapi_result . "\n");
        echo nl2br($xmlrpc_result . "\n");
    } else {
        echo "The website is not running WordPress";
    }
    // $wayback_urls = fetchWaybackURLs($url);

    // if ($wayback_urls !== false) {
    //     // Store modified URLs
    //     $modified_urls = [];
    //     foreach ($wayback_urls as $wayback_url) {
    //         $modified_urls[] = modifyParameterValues($wayback_url);
    //     }

    //     echo "Checking for alert(1) in Wayback URLs with modified parameters:<br>";
    //     foreach ($modified_urls as $modified_url) {
    //         if (checkAlert($modified_url)) {
    //             echo "<b>XSS found:</b> <a href='$modified_url'>$modified_url</a><br>";
    //         }
    //     }
    // } else {
    //     echo "Error fetching Wayback URLs";
    // }
}
?>

<!-- HTML Form for user input -->

