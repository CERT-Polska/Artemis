<?php
// Stand-in for the NVD CVE API, used by the cve_lookup integration test. Returns a fixed two-CVE
// response - one where Apache is the vulnerable component and one where it's only a "runs on"
// platform - so the test can verify the platform CVE is filtered out over real HTTP.
header("Content-Type: application/json");
echo json_encode([
    "resultsPerPage" => 2,
    "startIndex" => 0,
    "totalResults" => 2,
    "vulnerabilities" => [
        [
            "cve" => [
                "id" => "CVE-2100-0001",
                "descriptions" => [
                    ["lang" => "en", "value" => "Remote code execution in Apache HTTP Server."],
                ],
                "metrics" => [
                    "cvssMetricV31" => [
                        ["type" => "Primary", "cvssData" => ["baseScore" => 9.1]],
                    ],
                ],
                "configurations" => [
                    [
                        "nodes" => [
                            [
                                "operator" => "OR",
                                "cpeMatch" => [
                                    [
                                        "vulnerable" => true,
                                        "criteria" => "cpe:2.3:a:apache:http_server:2.4.53:*:*:*:*:*:*:*",
                                    ],
                                ],
                            ],
                        ],
                    ],
                ],
            ],
        ],
        [
            "cve" => [
                "id" => "CVE-2100-0002",
                "descriptions" => [
                    ["lang" => "en", "value" => "Vulnerability in an app that runs on Apache HTTP Server."],
                ],
                "metrics" => [
                    "cvssMetricV31" => [
                        ["type" => "Primary", "cvssData" => ["baseScore" => 7.5]],
                    ],
                ],
                "configurations" => [
                    [
                        "operator" => "AND",
                        "nodes" => [
                            [
                                "operator" => "OR",
                                "cpeMatch" => [
                                    [
                                        "vulnerable" => true,
                                        "criteria" => "cpe:2.3:a:example:someapp:1.0:*:*:*:*:*:*:*",
                                    ],
                                ],
                            ],
                            [
                                "operator" => "OR",
                                "cpeMatch" => [
                                    [
                                        "vulnerable" => false,
                                        "criteria" => "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                                    ],
                                ],
                            ],
                        ],
                    ],
                ],
            ],
        ],
    ],
]);
