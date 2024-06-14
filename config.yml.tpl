dns_wildcards:
    # wildcard dns entries to issue
    - *.example.com 



conf:
    local.jumidev.com:
        PROXY_PASS_TARGET: http://jumiserv1.local:8080