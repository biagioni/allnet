
package allnetui;

import java.awt.Color;
import java.util.Arrays;
import utils.StatusPanel;

/**
 *
 * @author Henry
 */
public class KeyExchangePanel extends StatusPanel {

    // just to avoid a warning
    private static final long serialVersionUID = 1L;
    // commands to send to UIController
    public static final String CLOSE_COMMAND = "CLOSE";
    public static final String CANCEL_COMMAND = "CANCEL";
    public static final String RESEND_KEY_COMMAND = "RESEND_KEY";
    // name of the cancel button
    private static final String CANCEL_BUTTON_NAME = "cancel";
    //
    // border params for the labels in the panel
    private int borderWidth = 1; // 4;
    private int borderRadius = 10;
    private int borderInset = 8;
    //
    // hold data from NewContactPanel, set when this KeyExchangePanel is created
    private String variableInput, secret, contactName;
    private int buttonState;

    public KeyExchangePanel(String contactName, int[] labelHeights,
                            boolean keyExchange) {
        super(labelHeights, getBooleans(labelHeights.length),
              UI.getBgndColor(), UI.getOtherColor(),
              UI.KEY_EXCHANGE_PANEL_ID + "_" + contactName,
              new String[]{keyExchange?"resend your key":"resend key request",
                           RESEND_KEY_COMMAND,
                           CANCEL_BUTTON_NAME, CANCEL_COMMAND});
        this.contactName = contactName;
        setColor(1, Color.WHITE);
        setColor(2, Color.PINK);
        String title = " exchanging keys with " + contactName;
        if (! keyExchange)
            title = " requesting key for " + contactName;
        setText(0, title);
        setBorderParams(borderWidth, borderRadius, borderInset);
    }

    // returns an array of booleans, all true except first
    private static boolean [] getBooleans(int n) {
        boolean temp [] = new boolean[n];
        Arrays.fill(temp, true);
        temp[0] = false;
        return(temp);
    }
    
    public int getButtonState() {
        return buttonState;
    }

    public void setButtonState(int buttonState) {
        this.buttonState = buttonState;
    }

    public String getContactName() {
        return contactName;
    }

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    public String getVariableInput() {
        return variableInput;
    }

    public void setVariableInput(String variableInput) {
        this.variableInput = variableInput;
    }

    
    public void setSuccess(String contactName) {
        setText(0, " Got key from " + contactName);
        hideLabel(1);
        setText(2, " Key Received Successfully");
        setColor(2, Color.GREEN);
        getButton(CANCEL_BUTTON_NAME).setEnabled(false);
    }
}
