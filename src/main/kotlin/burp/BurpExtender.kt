package burp

import com.esotericsoftware.minlog.Log
import java.io.IOException

class BurpExtender : IBurpExtender, IMessageEditorTabFactory {

    lateinit var callbacks: IBurpExtenderCallbacks
    lateinit var helpers: IExtensionHelpers


    override fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks) {
        this.callbacks = callbacks
        helpers = callbacks.helpers

        callbacks.setExtensionName("NTLM Challenge Decoder")


        Log.setLogger(object : Log.Logger() {
            override fun print(message: String) {
                try {
                    if (message.contains("ERROR:")) { //Not the most elegant way, but should be effective.
                        callbacks.issueAlert(message)
                    }
                    callbacks.stdout.write(message.toByteArray())
                    callbacks.stdout.write('\n'.toInt())
                } catch (e: IOException) {
                    System.err.println("Error while printing the log : " + e.message) //Very unlikely
                }

            }
        })
        Log.INFO()

        callbacks.registerMessageEditorTabFactory(this)
    }

    override fun createNewInstance(controller: IMessageEditorController, editable: Boolean): IMessageEditorTab {
        // create a new instance of our custom decoder tab
        return SSPDecoderTab(controller, editable,callbacks,helpers)
    }


}
