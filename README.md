# Network Scanning and Fingerprinting

## OVERVIEW

**tcpscan** is a TCP connect scanner and service fingerprinting tool. It scans a list of TCP ports on a given target (IP address or hostname) and attempts to determine what type of service is running on each open port. It uses both plain TCP and TLS-based probes to classify services into one of six types:  

  (1) TCP server-initiated  
  (2) TLS server-initiated  
  (3) HTTP server  
  (4) HTTPS server  
  (5) Generic TCP server  
  (6) Generic TLS server  

It prints up to 1024 bytes of server response (if available), with non-printable bytes replaced by dots ('.').  


## USAGE

Syntax:  
    tcpscan [-p port_range] target  

Examples:  
 ```tcpscan -p 80 www.example.com  
    tcpscan -p 20-25 192.168.1.10  
    tcpscan www.cs.stonybrook.edu      (scans default port list)
```  


### EXAMPLE INPUT & OUTPUT

Example command:  
`tcpscan -p 80 www.stonybrook.edu`  

Example output:  
Target IP: 104.18.32.123  
Port(s): 80  
Parsed port list: [80]  
[*] Starting TCP Connect Scan...  

[+] Open ports: [80]  

Host: 104.18.32.123:80  
Type: (3) HTTP server  
Response:  
  HTTP/1.1 400 Bad Request  
  Date: Mon, 31 Mar 2025 23:36:16 GMT  
  Content-Type: text/html  
  Content-Length: 155  
  Connection: close  
  Server: cloudflare  
  CF-RAY: 9293aafdab3c43cf-EWR  
  
```
  <html>
  <head><title>400 Bad Request</title></head>
  <body>
  <center><h1>400 Bad Request</h1></center>
  <hr><center>cloudflare</center>
  </body>
  </html>
```

In this example, port 80 was found open, and the server responded to a client-initiated GET request. tcpscan correctly identified it as:  
  Type: (3) HTTP server


