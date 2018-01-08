package burp

fun IResponseInfo.getHeader(headerKey:String):String = getHeaderCommon(headerKey, this.headers)

fun IRequestInfo.getHeader(headerKey:String):String = getHeaderCommon(headerKey, this.headers)

/**
 * Go through the list of lines from the headers, split for key value and extract the value associate to the key if present.
 * Return empty if not found.
 */
internal fun getHeaderCommon(headerKey:String,headers: List<String>):String {
    var headerValue = ""
    for (headerLine in headers) {
        val headerArray = headerLine.split("\\s*:\\s*".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()

        // is it a `Key: value' header?
        if (headerArray.size > 1) {

            // are we looking for this key?
            if (headerKey == headerArray[0]) {
                val authorizationTokens = headerArray[1].split(" ".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()

                // Are there two token?
                if (authorizationTokens.size == 2) {

                    // is the 1st token a NTLM marker?
                    if (authorizationTokens[0] == "NTLM") {

                        // assume 2nd token is NTLM blob
                        headerValue = authorizationTokens[1]
                    }
                }
            }
        }
    }
    return headerValue
}