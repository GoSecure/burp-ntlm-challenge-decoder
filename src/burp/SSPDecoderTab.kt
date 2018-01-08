package burp

import burp.messages.SSPMessageFactory
import java.awt.Component
import java.io.IOException
import javax.xml.bind.DatatypeConverter

/**
 * Tab component display under the Request and Response tab
 */
class SSPDecoderTab(val controller: IMessageEditorController, private val editable: Boolean, val callbacks: IBurpExtenderCallbacks, val helpers: IExtensionHelpers) : IMessageEditorTab {

    private val txtInput: ITextEditor
    private var sspHeaderValue: String? = null

    init {
        // create an instance of Burp's text editor, to display our deserialized data
        txtInput = callbacks.createTextEditor()
        txtInput.setEditable(editable)

    }

    override fun getTabCaption(): String {
        return "SSP Decoder"
    }

    override fun getUiComponent(): Component {
        return txtInput.component
    }


    override fun isEnabled(content: ByteArray, isRequest: Boolean): Boolean {
        var enabled = false

        if (isRequest) {
            val httpInfo = helpers.analyzeRequest(content)
            this.sspHeaderValue = getSSPHeaderValue(httpInfo.headers, "Authorization")
        } else {
            val httpInfo = helpers.analyzeResponse(content)
            this.sspHeaderValue = getSSPHeaderValue(httpInfo.headers, "WWW-Authenticate")
        }

        if (this.sspHeaderValue != "")
            enabled = true

        return enabled
    }

    override fun setMessage(content: ByteArray, isRequest: Boolean) {
        val rawSSPHeader = DatatypeConverter.parseBase64Binary(this.sspHeaderValue)
        val sspMessage = SSPMessageFactory.getMessage(rawSSPHeader)

        val outputMap = sspMessage.output


        var outputString = StringBuilder()
        for ((key, value) in outputMap) {
            outputString.append("$key: $value\n")
        }

        txtInput.text = outputString.toString().toByteArray()
    }

    // called when checking if we enable the tab
    private fun getSSPHeaderValue(headers: List<String>, headerKey: String): String {
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

    override fun getMessage(): ByteArray? {
        try {
            callbacks.stdout.write("Test".toByteArray())
        } catch (e: IOException) {
        }

        return null
    }


    override fun isModified(): Boolean {
        return txtInput.isTextModified
    }

    override fun getSelectedData(): ByteArray {
        return txtInput.selectedText
    }
}