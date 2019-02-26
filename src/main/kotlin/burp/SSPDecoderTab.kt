package burp

import burp.messages.SSPMessageFactory
import burp.ui.PropertyPanel
import burp.ui.PropertyPanelController
import java.awt.Component
import java.io.IOException

/**
 * Tab component display under the Request and Response tab
 */
class SSPDecoderTab(val controller: IMessageEditorController,
                    private val editable: Boolean,
                    val callbacks: IBurpExtenderCallbacks,
                    val helpers: IExtensionHelpers) : IMessageEditorTab {


    private val propertyPanel = PropertyPanel(PropertyPanelController())
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
        //return txtInput.component
        callbacks.customizeUiComponent(propertyPanel.component)
        return propertyPanel.component
    }


    override fun isEnabled(content: ByteArray, isRequest: Boolean): Boolean {
        var enabled = false

        if (isRequest) {
            //val httpInfo = helpers.analyzeRequest(content)
            //this.sspHeaderValue = httpInfo.getHeader("Authorization")
            //At the moment, the request header 'Authorization' is not supported.
            return false
        } else {
            val httpInfo = helpers.analyzeResponse(content)
            this.sspHeaderValue = httpInfo.getHeader("WWW-Authenticate")
        }

        if (this.sspHeaderValue != "")
            enabled = true

        return enabled
    }

    override fun setMessage(content: ByteArray, isRequest: Boolean) {
        val rawSSPHeader = helpers.base64Decode(this.sspHeaderValue)
        val sspMessage = SSPMessageFactory.getMessage(rawSSPHeader)

        val outputMap = sspMessage.output

        propertyPanel.clearProperties()
        var outputString = StringBuilder()
        for ((key, value) in outputMap) {
            outputString.append("$key: $value\n")
            propertyPanel.addProperty(key, value)
        }

        //txtInput.text = outputString.toString().toByteArray()
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