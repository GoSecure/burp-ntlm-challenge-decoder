package burp.ui

import com.esotericsoftware.minlog.Log
import java.awt.Component
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import javax.swing.JFileChooser

class SaveFileChooser {

    fun saveScriptToFile(code: String, filename: String, parent: Component, cont: PropertyPanelController) {

        val fileChooser = JFileChooser()

        fileChooser.dialogTitle = "Save to file"
        val currentDirectory = File(".").absolutePath

        fileChooser.selectedFile = File(currentDirectory, filename)
        fileChooser.name = FILE_CHOOSER

        if (fileChooser.showSaveDialog(parent) == JFileChooser.APPROVE_OPTION) {
            val file = fileChooser.selectedFile

            try {
                if (file.createNewFile()) {
                    val out = FileOutputStream(file)
                    out.write(code.toByteArray())
                    out.close()

                    cont.fileSaveSuccess(file.absolutePath)
                }
            } catch (e: IOException) {
                Log.error(e.message, e)

                cont.fileSaveError(file.absolutePath)
            }

        }
    }

    companion object {

        var FILE_CHOOSER = "FILE_CHOOSER"
    }
}
