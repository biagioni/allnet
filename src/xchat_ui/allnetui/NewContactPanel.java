package allnetui;

import java.awt.*;
import java.awt.event.ActionListener;
import javax.swing.*;
import javax.swing.border.LineBorder;
import javax.swing.border.MatteBorder;
import utils.HtmlLabel;

/**
 *
 * @author Henry
 */
class NewContactPanel extends JPanel {

    private static final long serialVersionUID = 1L;
    private HtmlLabel topLabel;
    private JTextField nameInput, variableInput;
    private String mySecretShortString, mySecretLongString;
    private JPanel selectionPanel;
    private JPanel keyPanel;
    private JButton goButton;
    private JLabel mySecretShort, mySecretLong;
    private JRadioButton[] buttons;
    private ButtonGroup group;
    private String commandPrefix = "NewContactPanel";

    private String newSecretChar (byte b) {
        if (b < 0)
          b += 128;
        char [] A = new char [1];
        byte [] c = new byte [1];
        A [0] = 'A';
        c [0] = (byte) ((b % 26) + Character.codePointAt(A, 0));
        String result = new String(c);
        if (result.equalsIgnoreCase("I"))
            result = "L";
        if (result.equalsIgnoreCase("Q"))
            result = "O";
        return result;
    }

    private String randomString(int numchars) {
        java.security.SecureRandom random = new java.security.SecureRandom();
        byte bytes[] = new byte[numchars];
        random.nextBytes(bytes);
        String result = "";
        for (int i = 0; i < numchars; i++)
            result = result + newSecretChar(bytes [i]);
        return result;
    }

    NewContactPanel(String info, Color background, Color foreground) {
        setBackground(background);
        // make the info label for the top of the panel
        topLabel = new HtmlLabel(info);
        topLabel.setOpaque(true);
        topLabel.setBackground(foreground);
        topLabel.setLineBorder(Color.BLACK, 1, false);
        //
        JLabel enterLabel = new JLabel(" name or AllNet address:  ");
        enterLabel.setOpaque(true);
        enterLabel.setBackground(Color.WHITE);
        enterLabel.setBorder(new LineBorder(Color.BLACK, 1, false));
        nameInput = getTextField();
        // no border on left edge since label has a border on right edge
        nameInput.setBorder(new MatteBorder(1, 0, 1, 1, Color.BLACK));
        JPanel namePanel = new JPanel();
        // use GridLayout to equalize size of label and text field
        // as an alternative, could set preferred size of text field to max
        namePanel.setLayout(new GridLayout(1, 2));
        namePanel.add(enterLabel, 0, 0);
        namePanel.add(nameInput, 0, 1);
        mySecretShort = new JLabel(" ");
        mySecretLong = new JLabel(" ");
        setMySecret();
        makeSelectionPanel();
        makeKeyPanel();
        goButton = new JButton("go");
        goButton.setBackground(foreground);
        goButton.setActionCommand(commandPrefix + ":" + "go");
        //
        setLayout(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.CENTER;
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridheight = 1;
        gbc.gridwidth = 2;
        add(topLabel, gbc);
        gbc.gridy++;
        add(selectionPanel, gbc);
        gbc.gridy++;
        add(namePanel, gbc);
        gbc.gridy++;
        add(keyPanel, gbc);
        gbc.gridy++;
        gbc.weightx = 0.0;
        add(goButton, gbc);
        gbc.gridy++;
        // expand bottom area vertically to fill extra space
        gbc.weighty = 1.0;
        add(Box.createRigidArea(new Dimension(1, 0)), gbc);
    }

    // like the name says
    void setTopLabelText(String text) {
        topLabel.setText(text);
    }

    // get the new contact name
    String getInputName() {
        return (nameInput.getText());
    }

    // get the new contact's input, whatever it is used for
    String getVariableInput() {
        return (variableInput.getText());
    }

    // change my secret string
    void setMySecret() {
        mySecretShortString = randomString (6);
        mySecretLongString = randomString (14);
        mySecretShort.setText("your short secret: " + mySecretShortString);
        mySecretLong.setText("or your long secret: " + mySecretLongString);
    }
    String getMySecretShort() {
        return (mySecretShortString);
    }
    String getMySecretLong() {
        return (mySecretLongString);
    }


    // return the index of the selected button
    int getSelectedButton() {
        for (int i = 0; i < buttons.length; i++) {
            if (buttons[i].isSelected()) {
                return (i);
            }
        }
        return (-1);
    }

    // set where we will send events
    void setActionListener(ActionListener listener) {
        goButton.addActionListener(listener);
        for (JRadioButton rb : buttons) {
            rb.addActionListener(listener);
        }
    }

    String getCommandPrefix() {
        return commandPrefix;
    }

    void setCommandPrefix(String commandPrefix) {
        this.commandPrefix = commandPrefix;
    }

    private JTextField getTextField() {
        JTextField field = new JTextField();
        field.setHorizontalAlignment(JTextField.CENTER);
        return (field);
    }

    final int unimplemented_offset = 1;  // for "both contacts of"
    final int num_choices = 5 - unimplemented_offset;

    private void makeSelectionPanel() {
        JPanel panel = new JPanel();
        // if we are using a L&F, then we can't change the button color, which is nuts.
        // the best way (I think) is to make one's own button component, which is not
        // so hard to do.
        panel.setBackground(Color.WHITE);
        panel.setBorder(new LineBorder(Color.BLACK, 1));
        // make components
        group = new ButtonGroup();
        buttons = new JRadioButton[num_choices];
        JLabel[] labels = new JLabel[num_choices];
        String[] labelText = new String[]{
            "new contact has a wireless device<br>" +
                 "within 10m (30ft): " +
                 "give contact your secret<br>" +
                 "and enter their secret",
            "new contact is at a distance:<br>" +
                 "give contact your secret<br>" +
                 "and enter their secret",
            "subscribe to a broadcast:<br>" +
                 "enter the address<br>" +
                 "(no secrets needed)</b>",
            "create a new group:<br>" +
                 "enter the group name<br>" +
                 "(no secrets needed)</b>",
//            "you are both contacts of:<br>" +
//                 "enter the name below<br>" +
//                 "(not yet available)",
        };
        for (int i = 0; i < num_choices; i++) {
            if (i != 1)
                buttons[i] = new JRadioButton();
            else
                buttons[i] = new JRadioButton("", true);
            buttons[i].setActionCommand(commandPrefix + ":radiobutton" + i);
            buttons[i].setBackground(Color.WHITE);
            group.add(buttons[i]);
            labels[i] = new HtmlLabel(labelText[i]);
        }
        variableInput = getTextField();
        variableInput.setBorder(new LineBorder(Color.BLACK, 1));
        // do layout
        panel.setLayout(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.CENTER;
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridheight = 1;
        gbc.gridwidth = 1;
        for (int i = 0; i < num_choices; i++) {
            gbc.gridx = 0;
            panel.add(buttons[i], gbc);
            gbc.gridx = 1;
            panel.add(labels[i], gbc);
            gbc.gridy++;
//            if (gbc.gridy == 1) {
//                panel.add(otherSecretShort, gbc);
//                gbc.gridy++;
//            }
//            if (gbc.gridy == 3) {
//                panel.add(ahra, gbc);
//                gbc.gridy++;
//            }
//            if (gbc.gridy == 5) {
//                panel.add(thirdParty, gbc);
//                gbc.gridy++;
//            }
        }
        selectionPanel = panel;
    }

    private void makeKeyPanel() {
        JPanel panel = new JPanel();
        panel.setBackground(Color.WHITE);
        panel.setBorder(new LineBorder(Color.BLACK, 1));
        // make components
        variableInput = getTextField();
        variableInput.setBorder(new LineBorder(Color.BLACK, 1));
        JLabel instruction0 =
            new HtmlLabel("enter your contact's secret and press <b>go</b>,");
        JLabel instruction1 = new HtmlLabel("or just press <b>go</b> and " +
                                            "your secret will be shown on " +
                                            "the next panel:");
        // do the layout
        panel.setLayout(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.CENTER;
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridheight = 1;
        gbc.gridwidth = 1;
        panel.add(instruction0, gbc);
        gbc.gridy++;
        panel.add(variableInput, gbc);
        gbc.gridy++;
        panel.add(instruction1, gbc);
//        gbc.gridy++;
//        panel.add(mySecretShort, gbc);
//        gbc.gridy++;
//        panel.add(mySecretLong, gbc);
        keyPanel = panel;
    }
}
