# Diagnostic capture: paul-john-caffeine

- **Slug:** `paul-john-caffeine`
- **URL:** https://pauljohncaffeine.com/
- **Host:** `pauljohncaffeine.com`
- **First seen down:** 2026-08-16T16:45:46Z
- **Diagnostic captured at:** 2026-08-16T16:54:34Z
- **Marker age at capture:** 519s
- **Captured from:** GitHub Actions ubuntu-latest runner

## Runner external IP
```
40.81.7.228
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
{ [79 bytes data]
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
< date: Sun, 16 Aug 2026 16:54:35 GMT
< content-type: text/html; charset=utf-8
< x-permitted-cross-domain-policies: none
< cf-cache-status: DYNAMIC
< set-cookie: localization=US; path=/; expires=Mon, 16 Aug 2027 16:54:35 GMT; SameSite=Lax
< set-cookie: cart_currency=USD; path=/; expires=Sun, 30 Aug 2026 16:54:35 GMT; SameSite=Lax
< set-cookie: _shopify_y=330cb042-18cd-4b55-82cb-ddab9783d6d3; domain=pauljohncaffeine.com; path=/; expires=Mon, 16 Aug 2027 22:54:35 GMT; SameSite=Lax
< set-cookie: _shopify_s=f7608b8e-b2e2-4cb7-90e5-d8319880d42b; domain=pauljohncaffeine.com; path=/; expires=Sun, 16 Aug 2026 17:24:35 GMT; SameSite=Lax
< set-cookie: _shopify_essential=:AaALfx5vAAEAUeWvewjFf_mi9j6WMsrzRM9m1X_aG4hVDBfOfKKE3eUdsgVpv6RZOzdn6YdUmjQAmc_hkae4gIUlNAGspBIlfWVjNsQrzWNkSRrz611hbLy1s_mtpMiZ7koqdPg7e7Sp9_2-LnZqgnPCj-mUJBJhPnKUefMDNuRZKsNXZcRGVwGNfaL16c5pIj5ItOVi1mTDWtqEO54Bi0lLrajVscBjDIM2zIL88zmfloVlCoo2PgPB0MDzVGO6Y_D5OIvm8Ax8XuO9xJgUc9GR7Yvcp-cgcT8vPtcM6-2WaKs4bLfMf57OH8zkxEFOCwckpzxYqtVU3rSsR1OmSkw6CWqRGqt5ZBOWbLuD-QIrVDjgFeNCaDsfSg4ilFxD7MqbKneIoukqmAq1Fh7N_EWTL32jPRY92lNYmON5ZTxaFOB86Wxd99M-MEOiwF_JRf4scgpJIFQjZEMnnxNBXqkeERQDg8U90oe6wbLWoGi8bZu3KeUZ-AyPIUVvJvGZsjlHawgozsjEdJHVHIRyCByib4YMqOkBHgML-4zCiRBHHT_HQmc8:; Max-Age=31536000; Path=/; HttpOnly; Secure; Priority=High; SameSite=Lax
< set-cookie: _shopify_analytics=:AaALfx8sAAEAKEwHnCDAhRvc2CIv83YzPlCIYDX1bAz-RfBsb-IXPdYonZpNedJoNBvOP8FkDi_j_qfchcU4U-MMDVBOG60_-IEA2pcqBYIhH-9YwbX5Y8BGhCIVTAISPTrgLtFYf8HHf2ar:; Max-Age=31536000; Path=/; HttpOnly; Secure; Priority=High; SameSite=Lax
< set-cookie: _shopify_marketing=:AaALfx8sAAEAc14q73mY1NS5kuGraujBSGku9D0zpYCPQHmoYOYZB-DSPMnu3Jhs9tzW74YbXBZIstze71IM80gX2DaL_TAeZQilwbw_i9h1VVNNr-ajFdREaqwLy-mw31zU:; Max-Age=31536000; Path=/; HttpOnly; Secure; Priority=High; SameSite=Lax
< link: <https://cdn.shopify.com>; rel="preconnect", <https://cdn.shopify.com>; rel="preconnect"; crossorigin, <https://cdn.jsdelivr.net>; rel="preconnect", <//pauljohncaffeine.com/cdn/shop/t/14/assets/base.css?v=2834341686314325271786093427>; as="style"; rel="preload", <//pauljohncaffeine.com/cdn/shop/t/14/assets/pj-base.css?v=91428646896832210721786093136>; as="style"; rel="preload", <//pauljohncaffeine.com/cdn/shop/t/14/assets/pj-header.css?v=75320757942627302471786093140>; as="style"; rel="preload", <//pauljohncaffeine.com/cdn/shop/t/14/assets/component-price.css?v=55950416259692611311786093446>; as="style"; rel="preload", <https://cdn.jsdelivr.net/npm/swiper@11/swiper-bundle.min.css>; as="style"; rel="preload", <https://cdn.shopify.com/extensions/01a00213-ccb4-765f-a7c4-b9e1f5c56da6/variant-options-product-options-460/assets/bcpo-front.css>; as="style"; rel="preload", <https://pauljohncaffeine.com/cdn/shopifycloud/portable-wallets/latest/accelerated-checkout-backwards-compat.css>; as="style"; rel="preload"; crossorigin, <//pauljohncaffeine.com/cdn/shop/files/paul_john_site_logo.svg?v=1777544566&width=600>; as="image"; rel="preload"; imagesrcset="//pauljohncaffeine.com/cdn/shop/files/paul_john_site_logo.svg?v=1777544566&width=90 90w, //pauljohncaffeine.com/cdn/shop/files/paul_john_site_logo.svg?v=1777544566&width=135 135w, //pauljohncaffeine.com/cdn/shop/files/paul_john_site_logo.svg?v=1777544566&width=180 180w"; imagesizes="(min-width: 750px) 90px, 50vw"
< report-to: {"group":"cf-nel","max_age":604800,"endpoints":[{"url":"https://a.nel.cloudflare.com/report/v4?s=Bevik31DPI7ewQyfaVtX4J1aQkyhrhVFEdOy6S6joPKLKJXC9zJPmXj4efjQDP9lvk4kANh7ILeRMzv0YXCshBaEeFS%2BA5FIIVozCXQVE2vge0vL4h7Ocf31nmphkxNXSScHcB2R"}]}
< x-content-type-options: nosniff
< nel: {"report_to":"cf-nel","success_fraction":0.01,"max_age":604800}
< shopify-complexity-score: 197
< shopify-complexity-score-v2: 197
< x-frame-options: DENY
< content-security-policy: block-all-mixed-content; frame-ancestors 'none'; upgrade-insecure-requests;
< strict-transport-security: max-age=7889238
< x-dc: gcp-us-west1,gcp-us-west1,gcp-us-west1
< vary: Accept
< vary: accept-encoding
< alt-svc: h3=":443"; ma=86400
< content-language: en-US
< powered-by: Shopify
< server-timing: processing;dur=203;desc="gc:3", db;dur=74, db_async;dur=20.087, render;dur=56, asn;desc="8075", edge;desc="SJC", country;desc="US", theme;desc="150201008267", pageType;desc="index", servedBy;desc="g5ds", requestID;desc="5a9592fc-2d70-4238-acfc-0f86aac58669-1786899275", _y;desc="330cb042-18cd-4b55-82cb-ddab9783d6d3", _s;desc="f7608b8e-b2e2-4cb7-90e5-d8319880d42b", _cmp;desc="3.AMPS_USCA_f_t_mE590ZJHQXKjKJzjmx7e1A", compressionLevel;desc="5", compressionTime;dur=8.046
< x-download-options: noopen
< server: cloudflare
< x-xss-protection: 1; mode=block
< x-request-id: 5a9592fc-2d70-4238-acfc-0f86aac58669-1786899275
< etag: W/"page_cache:73776824459:IndexController:c6726fca2f5761cb8fc3da40c0c277fa"
< cf-ray: a2c1f636cc30f9c5-SJC
< 
{ [57670 bytes data]
100  266k    0  266k    0     0   694k      0 --:--:-- --:--:-- --:--:--  696k
* Connection #0 to host pauljohncaffeine.com left intact
```

## TCP traceroute to :443 (traceroute -T -p 443)
```
sudo: traceroute: command not found
(traceroute failed or unavailable)
```

## MTR TCP path summary (mtr --tcp --port 443 -c 5)
```
Start: 2026-08-16T16:54:35+0000
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
 12.|-- 23.227.38.65               0.0%     5    1.9   1.7   1.6   1.9   0.1
```

## External confirmation

This diagnostic was captured from the same runner-class that reported the site down.
The confirm-down-alerts workflow's Gate 1 (check-host.net multi-node probe) also
reported this site down from independent international networks at the same moment;
see the workflow run log for the specific request_id and node IPs.
