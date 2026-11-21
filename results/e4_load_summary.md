# E4 load test (20 Nov 2026), ATS in codespace 1, gateway in codespace 2 (2 vCPU, 8 GB, single uvicorn worker, Python PDP, theta=2)
## Remote client (laptop over internet + GitHub public port forwarding)
c=10:  31.8 rps, p50 52.3 ms, p95 188.7, p99 586.4; exch p50 32.9; ALLOW 1143 DENY 141; 10 ReadTimeout
c=50:  27.5 rps, p50 263.3, p95 638.1, p99 4303; exch p50 173.4; ALLOW 1008 DENY 106; 50 ReadTimeout
c=100: 30.7 rps, p50 605.4, p95 22500, p99 22961; exch p50 626.7; ALLOW 895 DENY 76; 0 errors
## Co-located client (load generator on the gateway's own 2 vCPU; token exchange still cross-host)
c=10:  161.2 rps, p50 36.3, p95 182.8, p99 277.4; exch p50 35.2 p95 69.9; ALLOW 4335 DENY 508; 0 errors
c=50:  121.6 rps, p50 268.2, p95 1188.3, p99 1809.3; exch p50 77.2; ALLOW 3294 DENY 374; 0 errors
c=100:  94.5 rps, p50 676.2, p95 3010.2, p99 4814.6; exch p50 218.0; ALLOW 2662 DENY 268; 0 errors
