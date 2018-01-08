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
            this.sspHeaderValue = httpInfo.getHeader("Authorization")
        } else {
            val httpInfo = helpers.analyzeResponse(content)
            this.sspHeaderValue = httpInfo.getHeader("WWW-Authenticate")
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