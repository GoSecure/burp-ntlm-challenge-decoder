package burp.ui

import com.esotericsoftware.minlog.Log

import java.awt.*
import java.awt.datatransfer.Clipboard
import java.awt.datatransfer.StringSelection

class PropertyPanelController {

    fun copyToClipboard(code: String) {
        val clip = Toolkit.getDefaultToolkit().systemClipboard
        clip.setContents(StringSelection(code), null)
    }

    fun saveToFile(code: String, parent: Component) {
        SaveFileChooser().saveScriptToFile(code, "", parent, this)
    }

    fun fileSaveSuccess(fileName: String) {
        Log.debug(String.format("Script '%s' saved with success!", fileName))
    }

    fun fileSaveError(fileName: String) {
        Log.debug(String.format("Unable to save '%s'", fileName))
    }
}
