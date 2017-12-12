# burp-ssp-decoder

Burp extension to decode NTLM SSP headers. NTLM challenges over HTTP allows us to decode interesting information about a server, such as:
- The server's hostname
- The server's operating system
- The server's timestamp
- The domain's name
- The domain's FQDN
- The parent domain's name

## Branches
Both will be combined once `ntlm-ssp-decoder` is mature enough to be used

### ntlm-ssp-decoder
WIP for the decoding of the NTLM SSP protocol
https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-NLMP/[MS-NLMP].pdf
http://msdn.microsoft.com/en-us/library/cc236621.aspx

### burp-extension
The Burp extension itself, mostly UI stuff.
