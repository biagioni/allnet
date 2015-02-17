package allnetui;

import java.awt.Color;
import utils.StatusPanel;

/**
 *
 * @author Henry
 */
public class KeyExchangePanel extends StatusPanel {

    // commands to send to UIController
    public static final String CLOSE_COMMAND = "CLOSE";
    public static final String CANCEL_COMMAND = "CANCEL";
    public static final String RESEND_KEY_COMMAND = "RESEND_KEY";
    //
    private static final long serialVersionUID = 1L;

    public KeyExchangePanel(String contactName, int[] labelHeights) {
        super(labelHeights, UI.getBgndColor(), UI.getOtherColor(), UI.KEY_EXCHANGE_PANEL_ID + "_" + contactName,
                new String[]{"resend your key", RESEND_KEY_COMMAND, "cancel", CANCEL_COMMAND});
        setColor(1, Color.WHITE);
        setColor(2, Color.PINK);
        setText(0, " exchanging keys with " + contactName);

    }
}
