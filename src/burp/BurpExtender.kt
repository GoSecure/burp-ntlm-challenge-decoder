package burp

class BurpExtender : IBurpExtender, IMessageEditorTabFactory {

    lateinit var callbacks: IBurpExtenderCallbacks
    lateinit var helpers: IExtensionHelpers


    override fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks) {
        this.callbacks = callbacks
        helpers = callbacks.helpers

        callbacks.setExtensionName("NTLM SSP Decoder")

        callbacks.registerMessageEditorTabFactory(this)
    }

    override fun createNewInstance(controller: IMessageEditorController, editable: Boolean): IMessageEditorTab {
        // create a new instance of our custom decoder tab
        return SSPDecoderTab(controller, editable,callbacks,helpers)
    }


}
