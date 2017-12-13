# burp-ssp-decoder

![Burp SSP Decoder](/images/version_1.png)

Burp extension to decode NTLM SSP headers. NTLM challenges over HTTP allows us to decode interesting information about a server, such as:
- The server's hostname
- The server's operating system
- The server's timestamp
- The domain's name
- The domain's FQDN
- The parent domain's name

# Sources, credits
- https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-NLMP/[MS-NLMP].pdf
- http://msdn.microsoft.com/en-us/library/cc236621.aspx
- https://gist.github.com/aseering/829a2270b72345a1dc42
