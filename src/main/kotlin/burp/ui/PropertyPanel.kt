package burp.ui

import java.awt.BorderLayout
import java.awt.Container
import java.awt.FlowLayout
import java.awt.event.ActionEvent
import java.awt.event.ActionListener
import javax.swing.*
import javax.swing.table.DefaultTableModel


class PropertyPanel(private val controller: PropertyPanelController) {

    lateinit var propertiesPanel: JPanel
    lateinit var messagePanel: JPanel
    lateinit var component: JPanel //Containing either the messagePanel or the propertiesPanel

    //Components of the Properties Panel
    lateinit var table: JTable
    lateinit var tableModel: DefaultTableModel

    //Components of the Message Panel
    lateinit var labelMessage: JLabel

    /**
     * Expose to the save option a text representation
     * @return
     */
    protected val propertiesToString: String
        get() {
            val columns = tableModel.columnCount
            val buffer = StringBuilder()
            for (i in 0 until tableModel.rowCount) {
                for (j in 0 until columns) {
                    val value = tableModel.getValueAt(i, j) as String
                    buffer.append(value)
                    if (j == 0) {
                        buffer.append('\t')
                    }
                }
                buffer.append('\n')
            }
            return buffer.toString()
        }

    init {
        buildPropertyTable()
    }

    /**
     * This method must be called ASAP after its instantiation
     */
    private fun buildPropertyTable() {

        //Table grid
        tableModel = object : DefaultTableModel(arrayOf<Array<String>>(), columns) {

            override fun isCellEditable(col: Int, row: Int): Boolean {
                return false
            }
        }
        this.table = JTable(tableModel)

        //Properties Panel
        this.propertiesPanel = JPanel()
        propertiesPanel.name = "Properties Panel"
        propertiesPanel.layout = BorderLayout()
        propertiesPanel.add(JScrollPane(table), BorderLayout.CENTER)

        table.columnModel.getColumn(0).preferredWidth = 150
        table.columnModel.getColumn(0).maxWidth = 300
        table.autoResizeMode = JTable.AUTO_RESIZE_LAST_COLUMN

        buildSaveOptions(propertiesPanel)

        //Message Panel
        this.messagePanel = JPanel()
        messagePanel.name = "Message Panel"
        this.labelMessage = JLabel(NO_METADATA_FOUND)
        messagePanel.add(labelMessage)

        //Container
        this.component = JPanel()
        component.layout = BorderLayout()

        setActivePanel(messagePanel)
    }

    private fun buildSaveOptions(container: Container) {
        val buttonContainer = JPanel(FlowLayout())

        val buttonCopy = JButton("Copy to clipboard")
        val buttonSave = JButton("Save to file")
        buttonCopy.addActionListener(CopyScriptToClipboard())
        buttonSave.addActionListener(SaveScriptToFile())

        buttonContainer.add(buttonCopy)
        buttonContainer.add(buttonSave)

        container.add(buttonContainer, BorderLayout.SOUTH)
    }

    private fun setActivePanel(panel: JPanel?) {
        component.removeAll()
        component.add(panel!!, BorderLayout.CENTER)
        //Update UI
        component.validate()
        component.repaint()
    }

    fun clearProperties() {
        setActivePanel(messagePanel) //Switch to message panel
        labelMessage!!.text = NO_METADATA_FOUND //Replace potential error message (previously displayed)
        tableModel.rowCount = 0
    }

    fun addProperty(key: String, value: String) {
        setActivePanel(propertiesPanel) //Switch to properties panel
        tableModel.addRow(arrayOf(key, value))
    }

    fun displayErrorMessage(errorMessage: String) {
        if (tableModel.rowCount == 0)
            setActivePanel(messagePanel) //Switch to message panel
        labelMessage.text = errorMessage
    }


    /// Actions display at the bottom of the panel

    private inner class CopyScriptToClipboard : ActionListener {

        override fun actionPerformed(e: ActionEvent) {
            controller.copyToClipboard(propertiesToString)
        }
    }

    private inner class SaveScriptToFile : ActionListener {

        override fun actionPerformed(e: ActionEvent) {
            controller.saveToFile(propertiesToString, this@PropertyPanel.component)
        }
    }

    companion object {
        private val columns = arrayOf("Property", "Value")
        private val NO_METADATA_FOUND = "No metadata found"
    }
}