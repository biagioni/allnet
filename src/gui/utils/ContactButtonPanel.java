package utils;

import java.awt.GridLayout;
import java.awt.event.ActionListener;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;

/**
 * Panel to hold labels and buttons
 *
 * @author henry
 */
public class ContactButtonPanel extends JPanel {

    private JButton[] buttons;
    private JLabel[] labels;

    // define this panel's command here; later we should move all commands to one place
    public static final String SAVE_CHANGES = "SAVE_CHANGES";
    public static final String EXPORT_CONVERSATION = "EXPORT_CONVERSATION";
    public static final String CLEAR_CONVERSATION = "CLEAR_CONVERSATION";
    public static final String DELETE_CONTACT = "DELETE_CONTACT";
    //
    private String[] labelStrings = new String[]{"Export Conversation", "Clear Conversation", "Delete Contact"};
    private String[] buttonStrings = new String[]{"Export", "Clear", "DELETE"};
    private String[] buttonCommands = new String[]{EXPORT_CONVERSATION, CLEAR_CONVERSATION, DELETE_CONTACT};

    public ContactButtonPanel() {

        labels = new JLabel[labelStrings.length];
        buttons = new JButton[labelStrings.length];
        for (int i = 0; i < buttons.length; i++) {
            labels[i] = new JLabel(labelStrings[i]);
            buttons[i] = new JButton(buttonStrings[i]);
            buttons[i].setActionCommand(buttonCommands[i]);
        }
        // now add these components to our panel
        setLayout(new GridLayout(3, 2, 5, 5));
        for (int i = 0; i < buttons.length; i++) {
            add(labels[i]);
            add(buttons[i]);
        }
    }

    public void addListener(ActionListener listener) {
        for (JButton button : buttons) {
            button.addActionListener(listener);
        }
    }

    public JButton [] getButtons() {
        return(buttons);
    }
    
}
