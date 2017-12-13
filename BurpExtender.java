package burp;

import java.io.PrintWriter;
import java.awt.Component;
import java.util.Arrays;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import javax.swing.JButton;
import javax.swing.SwingUtilities;
import java.awt.BorderLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import java.io.IOException;
import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import javax.xml.bind.DatatypeConverter;


public class BurpExtender implements IBurpExtender, IMessageEditorTabFactory, ITab
{

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private JPanel mainPane;
    final JTextArea SSPTextArea = new JTextArea(5, 10);

    
    public void registerExtenderCallbacks (IBurpExtenderCallbacks callbacks) 
    {
        this.callbacks = callbacks;

        helpers = callbacks.getHelpers();

	callbacks.setExtensionName("NTLM SSP Decoder");


        callbacks.registerMessageEditorTabFactory(this);


        // create our UI
	SwingUtilities.invokeLater(new Runnable() {
		@Override
		public void run() {
		    //Main split pane
		    mainPane = new JPanel(new BorderLayout());


		    SSPTextArea.setLineWrap(true);
		    JPanel beautifyTextWrapper = new JPanel(new BorderLayout());
		    JScrollPane beautifyScrollPane = new JScrollPane(SSPTextArea);
		    beautifyTextWrapper.add(beautifyScrollPane, BorderLayout.CENTER);
		    mainPane.add(beautifyTextWrapper, BorderLayout.CENTER);



		    callbacks.customizeUiComponent(mainPane);

		    // Add the custom tab to Burp's UI
		    callbacks.addSuiteTab(BurpExtender.this);
		    
		}
		            
	    });







    }


    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
	// create a new instance of our custom decoder tab
	return new SSPDecoderTab(controller, editable);
    }    

    @Override
    public String getTabCaption() {
	return "SSP Decoder";
    }

    @Override
    public Component getUiComponent() {
	return mainPane;
    }



    class SSPDecoderTab implements IMessageEditorTab {
	
	private boolean editable;
	private ITextEditor txtInput;
	private byte[] currentMessage;
	private String SSPHeaderValue;
	Map<String, String> headers;

	
        public SSPDecoderTab(IMessageEditorController controller, boolean editable) {
	    this.editable = editable;

	    // create an instance of Burp's text editor, to display our deserialized data
	    txtInput = callbacks.createTextEditor();
	    txtInput.setEditable(editable);
	            
	}

	@Override
	public String getTabCaption() {
	    return "SSP Decoder";
	}

	@Override
	public Component getUiComponent() {
	    return txtInput.getComponent();
	}



	@Override
	public boolean isEnabled(byte[] content, boolean isRequest) {
	    boolean enabled = false;

	    if (isRequest) {
	    	IRequestInfo httpInfo = helpers.analyzeRequest(content);
	    	this.SSPHeaderValue = getSSPHeaderValue(httpInfo.getHeaders(), "Authorization");
	    } else {
	    	IResponseInfo httpInfo = helpers.analyzeResponse(content);
	    	this.SSPHeaderValue = getSSPHeaderValue(httpInfo.getHeaders(), "WWW-Authenticate");
	    }

	    if (!this.SSPHeaderValue.equals(""))
		enabled = true;

	    return enabled;
	}

	@Override
	public void setMessage(byte[] content, boolean isRequest) {
	    byte[] rawSSPHeader = DatatypeConverter.parseBase64Binary(this.SSPHeaderValue);
	    SSPMessage SSPMessage = SSPMessageFactory.getMessage(rawSSPHeader);

		Map<String,String> outputMap = SSPMessage.output;



		String outputString = "";
		for (Map.Entry<String, String> line : outputMap.entrySet()) {
			outputString += line.getKey() + ": " + line.getValue() + "\n";
		}
	    
	    txtInput.setText(outputString.getBytes());
	}

	// called when checking if we enable the tab
	private String getSSPHeaderValue(List<String> headers, String headerKey) {   
	    String headerValue = "";
	    for (String headerLine : headers) {
		String[] headerArray = headerLine.split("\\s*:\\s*");

		// is it a `Key: value' header?
		if (headerArray.length > 1) {

		    // are we looking for this key?
		    if (headerKey.equals(headerArray[0])) {
			String[] authorizationTokens = headerArray[1].split(" ");

			// Are there two token?
			if (authorizationTokens.length == 2) {

			    // is the 1st token a NTLM marker?
			    if (authorizationTokens[0].equals("NTLM")) {

				// assume 2nd token is NTLM blob
				headerValue = authorizationTokens[1];
			    }
			}
		    }
		}
	    }
	    return headerValue;
	}

        @Override
	public byte[] getMessage() {
	    try {callbacks.getStdout().write("Test".getBytes()); } catch (IOException e) {}
	    return null;
	}


	@Override
        public boolean isModified() {
	    return txtInput.isTextModified();
	}

	@Override
	public byte[] getSelectedData() {
	    return txtInput.getSelectedText();
	}
    }

}
