# Diagnostic capture: paul-john-caffeine

- **Slug:** `paul-john-caffeine`
- **URL:** https://pauljohncaffeine.com/
- **Host:** `pauljohncaffeine.com`
- **First seen down:** 2026-08-16T14:38:16Z
- **Diagnostic captured at:** 2026-08-16T14:46:14Z
- **Marker age at capture:** 467s
- **Captured from:** GitHub Actions ubuntu-latest runner

## Runner external IP
```
52.161.82.85
```

## DNS resolution (dig)
```
23.227.38.65
```

## TCP connect test to :443 (nc -zv)
```
Connection to pauljohncaffeine.com (23.227.38.65) 443 port [tcp/https] succeeded!
```

## Verbose curl to https://pauljohncaffeine.com/
```
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0* Host pauljohncaffeine.com:443 was resolved.
* IPv6: (none)
* IPv4: 23.227.38.65
*   Trying 23.227.38.65:443...
* Connected to pauljohncaffeine.com (23.227.38.65) port 443
* ALPN: curl offers h2,http/1.1
} [5 bytes data]
* TLSv1.3 (OUT), TLS handshake, Client hello (1):
} [512 bytes data]
*  CAfile: /etc/ssl/certs/ca-certificates.crt
*  CApath: /etc/ssl/certs
{ [5 bytes data]
* TLSv1.3 (IN), TLS handshake, Server hello (2):
{ [122 bytes data]
* TLSv1.3 (IN), TLS handshake, Encrypted Extensions (8):
{ [19 bytes data]
* TLSv1.3 (IN), TLS handshake, Certificate (11):
{ [3426 bytes data]
* TLSv1.3 (IN), TLS handshake, CERT verify (15):
{ [80 bytes data]
* TLSv1.3 (IN), TLS handshake, Finished (20):
{ [52 bytes data]
* TLSv1.3 (OUT), TLS change cipher, Change cipher spec (1):
} [1 bytes data]
* TLSv1.3 (OUT), TLS handshake, Finished (20):
} [52 bytes data]
* SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384 / X25519 / id-ecPublicKey
* ALPN: server accepted h2
* Server certificate:
*  subject: CN=pauljohncaffeine.com
*  start date: Aug  1 10:29:02 2026 GMT
*  expire date: Oct 30 10:29:01 2026 GMT
*  subjectAltName: host "pauljohncaffeine.com" matched cert's "pauljohncaffeine.com"
*  issuer: C=US; O=Let's Encrypt; CN=YE1
*  SSL certificate verify ok.
*   Certificate level 0: Public key type EC/prime256v1 (256/128 Bits/secBits), signed using ecdsa-with-SHA384
*   Certificate level 1: Public key type EC/secp384r1 (384/192 Bits/secBits), signed using ecdsa-with-SHA384
*   Certificate level 2: Public key type EC/secp384r1 (384/192 Bits/secBits), signed using ecdsa-with-SHA384
*   Certificate level 3: Public key type EC/secp384r1 (384/192 Bits/secBits), signed using ecdsa-with-SHA384
} [5 bytes data]
* using HTTP/2
* [HTTP/2] [1] OPENED stream for https://pauljohncaffeine.com/
* [HTTP/2] [1] [:method: GET]
* [HTTP/2] [1] [:scheme: https]
* [HTTP/2] [1] [:authority: pauljohncaffeine.com]
* [HTTP/2] [1] [:path: /]
* [HTTP/2] [1] [user-agent: Mozilla/5.0 (compatible; KilowottUptime/1.0; +https://github.com/Kilowott-HQ/uptime)]
* [HTTP/2] [1] [accept: */*]
} [5 bytes data]
> GET / HTTP/2
> Host: pauljohncaffeine.com
> User-Agent: Mozilla/5.0 (compatible; KilowottUptime/1.0; +https://github.com/Kilowott-HQ/uptime)
> Accept: */*
> 
{ [5 bytes data]
* TLSv1.3 (IN), TLS handshake, Newsession Ticket (4):
{ [238 bytes data]
* TLSv1.3 (IN), TLS handshake, Newsession Ticket (4):
{ [238 bytes data]
* old SSL session ID is stale, removing
{ [5 bytes data]
< HTTP/2 200 
< date: Sun, 16 Aug 2026 14:46:14 GMT
< content-type: text/html; charset=utf-8
< x-permitted-cross-domain-policies: none
< cf-cache-status: DYNAMIC
< set-cookie: localization=US; path=/; expires=Mon, 16 Aug 2027 14:46:14 GMT; SameSite=Lax
< set-cookie: cart_currency=USD; path=/; expires=Sun, 30 Aug 2026 14:46:14 GMT; SameSite=Lax
< set-cookie: _shopify_y=c6acf49c-ee4e-4464-a237-6eb2d7f85cec; domain=pauljohncaffeine.com; path=/; expires=Mon, 16 Aug 2027 20:46:14 GMT; SameSite=Lax
< set-cookie: _shopify_s=3abea3c0-fa16-4363-9037-150de418afe0; domain=pauljohncaffeine.com; path=/; expires=Sun, 16 Aug 2026 15:16:14 GMT; SameSite=Lax
< set-cookie: _shopify_essential=:AaALCZzkAAEAazs195NR7_T8Cchcm71bkgZ-Z4F-bVkuhdWH8dZuMG665pWh27WUTz6XpIXgjp1D4cRfi8I4s2cjhfc72uN3qwV9zYLQbyrori43FMFh3ghWJvr8DdMAPCqyyvDRQgKbrFRSLwryTXB9pnRhn3EmKNdYzQjRF9EFi-ypmmfYlCkoMP2OzneiBTHQK_iZXjmh7uewvj-eiI5erhf_TnOMa_fUQwvr40iQ7vNvlCeoDIWUj49APhU4gOmHNX5MZiEneAuHUtjy9zHB8u_1LpcJAyc6QxAOZyM2cxrzGdkDRjudusYLgwGj7rXd-mV-a0LMobqU_j70RaFoPzEynyPIBWVdVCLlEChQDnxIoSuJiUpDrTYLrOvbCHc_hB27FSBpu_JMGGnQ7blzNsBKkUmcSVjZ_xRC6MD8DLDnqfINid3GQiEIrkcguQyBzMdqK0LQMdo8c281WHRKUljZG6qop4atLD9_QVlhVFZMwGyH_rB5hnNdesb7upHdfyj8vjc8Z9gXZIoZEvn5hRecX6pLTxKkerGl4uWHXDqkxg:; Max-Age=31536000; Path=/; HttpOnly; Secure; Priority=High; SameSite=Lax
< set-cookie: _shopify_analytics=:AaALCZ2GAAEA03M3i01vYcY6ckPDLuDMHyLKy5ggAuJ4DQJdmhf5n077ApMmu-zjf5ulV8yIRw3LD5IH8sU2s-ao7as5hs4fjMMmxB97aBO20-WEvx8dzl6Rqzoy0SSvDhNapNuktB31H6-M:; Max-Age=31536000; Path=/; HttpOnly; Secure; Priority=High; SameSite=Lax
< set-cookie: _shopify_marketing=:AaALCZ2GAAEA9Uzsw0URoxO273H_skAFOjKlHBLu-9hkaknY98f0cvt2s0Qa1GtxMgfhR76WnH9AmHT5pM51-9DyWg_HHociE35RVUClJrY3h2WZ_3E2q_INAfJTeWLEYJGV:; Max-Age=31536000; Path=/; HttpOnly; Secure; Priority=High; SameSite=Lax
< link: <https://cdn.shopify.com>; rel="preconnect", <https://cdn.shopify.com>; rel="preconnect"; crossorigin, <https://cdn.jsdelivr.net>; rel="preconnect", <//pauljohncaffeine.com/cdn/shop/t/14/assets/base.css?v=2834341686314325271786093427>; as="style"; rel="preload", <//pauljohncaffeine.com/cdn/shop/t/14/assets/pj-base.css?v=91428646896832210721786093136>; as="style"; rel="preload", <//pauljohncaffeine.com/cdn/shop/t/14/assets/pj-header.css?v=75320757942627302471786093140>; as="style"; rel="preload", <//pauljohncaffeine.com/cdn/shop/t/14/assets/component-price.css?v=55950416259692611311786093446>; as="style"; rel="preload", <https://cdn.jsdelivr.net/npm/swiper@11/swiper-bundle.min.css>; as="style"; rel="preload", <https://cdn.shopify.com/extensions/01a00213-ccb4-765f-a7c4-b9e1f5c56da6/variant-options-product-options-460/assets/bcpo-front.css>; as="style"; rel="preload", <https://pauljohncaffeine.com/cdn/shopifycloud/portable-wallets/latest/accelerated-checkout-backwards-compat.css>; as="style"; rel="preload"; crossorigin, <//pauljohncaffeine.com/cdn/shop/files/paul_john_site_logo.svg?v=1777544566&width=600>; as="image"; rel="preload"; imagesrcset="//pauljohncaffeine.com/cdn/shop/files/paul_john_site_logo.svg?v=1777544566&width=90 90w, //pauljohncaffeine.com/cdn/shop/files/paul_john_site_logo.svg?v=1777544566&width=135 135w, //pauljohncaffeine.com/cdn/shop/files/paul_john_site_logo.svg?v=1777544566&width=180 180w"; imagesizes="(min-width: 750px) 90px, 50vw"
< report-to: {"group":"cf-nel","max_age":604800,"endpoints":[{"url":"https://a.nel.cloudflare.com/report/v4?s=a3O2j%2FRkDGJ2BBX6csjUIH9VBvvZpeSDXidmghWRM%2FKCOGAEGSVi0CpLHynui8WVbpgceiwJLKKVxnGyWgs2bZVIPbUostjakLayo5kxroRUGcXZkEZs9WlF7L0h%2BK0v2BCL4qBD"}]}
< x-content-type-options: nosniff
< nel: {"report_to":"cf-nel","success_fraction":0.01,"max_age":604800}
< shopify-complexity-score: 176
< shopify-complexity-score-v2: 176
< x-frame-options: DENY
< content-security-policy: block-all-mixed-content; frame-ancestors 'none'; upgrade-insecure-requests;
< strict-transport-security: max-age=7889238
< x-dc: gcp-us-central1,gcp-us-central1,gcp-us-central1
< vary: Accept
< vary: accept-encoding
< alt-svc: h3=":443"; ma=86400
< content-language: en-US
< powered-by: Shopify
< server-timing: processing;dur=183;desc="gc:2", db;dur=102, render;dur=55, asn;desc="8075", edge;desc="DFW", country;desc="US", theme;desc="150201008267", pageType;desc="index", servedBy;desc="7fx6", requestID;desc="1b9aba3b-2abd-47fd-a33c-b030f5a125c9-1786891574", _y;desc="c6acf49c-ee4e-4464-a237-6eb2d7f85cec", _s;desc="3abea3c0-fa16-4363-9037-150de418afe0", _cmp;desc="3.AMPS_USWY_f_f_AnZQ736yQl2H2TB39cGusQ", compressionLevel;desc="5", compressionTime;dur=9.516
< x-download-options: noopen
< server: cloudflare
< x-xss-protection: 1; mode=block
< x-request-id: 1b9aba3b-2abd-47fd-a33c-b030f5a125c9-1786891574
< etag: W/"page_cache:73776824459:IndexController:ab68e8c190b181f93e86dbc653b1afef"
< cf-ray: a2c13a344cbf2251-DFW
< 
{ [8196 bytes data]
100  8196    0  8196    0     0  22357      0 --:--:-- --:--:-- --:--:-- 22332100  265k    0  265k    0     0   650k      0 --:--:-- --:--:-- --:--:--  650k
* Connection #0 to host pauljohncaffeine.com left intact
```

## TCP traceroute to :443 (traceroute -T -p 443)
```
sudo: traceroute: command not found
(traceroute failed or unavailable)
```

## MTR TCP path summary (mtr --tcp --port 443 -c 5)
```
Start: 2026-08-16T14:46:14+0000
HOST: runnervmzvulz               Loss%   Snt   Last   Avg  Best  Wrst StDev
  1.|-- ???                       100.0     5    0.0   0.0   0.0   0.0   0.0
  2.|-- ???                       100.0     5    0.0   0.0   0.0   0.0   0.0
  3.|-- ???                       100.0     5    0.0   0.0   0.0   0.0   0.0
  4.|-- ???                       100.0     5    0.0   0.0   0.0   0.0   0.0
  5.|-- ???                       100.0     5    0.0   0.0   0.0   0.0   0.0
  6.|-- ???                       100.0     5    0.0   0.0   0.0   0.0   0.0
  7.|-- ???                       100.0     5    0.0   0.0   0.0   0.0   0.0
  8.|-- ???                       100.0     5    0.0   0.0   0.0   0.0   0.0
  9.|-- ???                       100.0     5    0.0   0.0   0.0   0.0   0.0
 10.|-- ???                       100.0     5    0.0   0.0   0.0   0.0   0.0
 11.|-- ???                       100.0     5    0.0   0.0   0.0   0.0   0.0
 12.|-- ???                       100.0     5    0.0   0.0   0.0   0.0   0.0
 13.|-- 23.227.38.65               0.0%     5   23.8  19.6  17.9  23.8   2.4
```

## External confirmation

This diagnostic was captured from the same runner-class that reported the site down.
The confirm-down-alerts workflow's Gate 1 (check-host.net multi-node probe) also
reported this site down from independent international networks at the same moment;
see the workflow run log for the specific request_id and node IPs.
