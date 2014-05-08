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
    private JTextField nameInput, otherAddress, thirdParty, hisSecret;
    private JPanel selectionPanel;
    private JPanel keyPanel;
    private JButton goButton;
    private JLabel mySecret;
    private JRadioButton[] buttons;
    private ButtonGroup group;
    private String commandPrefix = "NewContactPanel";

    NewContactPanel(String info, Color background, Color foreground) {
        setBackground(background);
        // make the info label for the top of the panel
        topLabel = new HtmlLabel(info);
        topLabel.setOpaque(true);
        topLabel.setBackground(foreground);
        topLabel.setLineBorder(Color.BLACK, 1, false);
        //
        JLabel enterLabel = new JLabel(" enter contact name:  ");
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
        add(namePanel, gbc);
        gbc.gridy++;
        add(selectionPanel, gbc);
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

    // display my secret string
    void setMySecret(String secretString) {
        mySecret.setText(secretString);
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

    private void makeSelectionPanel() {
        JPanel panel = new JPanel();
        // if we are using a L&F, then we can't change the button color, which is nuts.
        // the best way (I think) is to make one's own button component, which is not
        // so hard to do.
        panel.setBackground(Color.WHITE);
        panel.setBorder(new LineBorder(Color.BLACK, 1));
        // make components
        group = new ButtonGroup();
        buttons = new JRadioButton[5];
        JLabel[] labels = new JLabel[5];
        String[] labelText = new String[]{
            "new contact has a wireless device and<br>is close enough to be in range",
            "you are in contact over email<br>or other insecure method",
            "you are in contact over telephone<br>or other somewhat insecure method",
            "you know your contact's AllNet address<br>(fill in the address below)",
            "you are both contacts of:<br>(fill in the name below)"
        };
        for (int i = 0; i < 5; i++) {
            buttons[i] = new JRadioButton();
            buttons[i].setActionCommand(commandPrefix + ":" + "radiobutton" + i);
            buttons[i].setBackground(Color.WHITE);
            group.add(buttons[i]);
            labels[i] = new HtmlLabel(labelText[i]);
        }
        otherAddress = getTextField();
        otherAddress.setBorder(new LineBorder(Color.BLACK, 1));
        thirdParty = getTextField();
        thirdParty.setBorder(new LineBorder(Color.BLACK, 1));
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
        for (int i = 0; i < 5; i++) {
            gbc.gridx = 0;
            panel.add(buttons[i], gbc);
            gbc.gridx = 1;
            panel.add(labels[i], gbc);
            gbc.gridy++;
            if (gbc.gridy == 4) {
                panel.add(otherAddress, gbc);
                gbc.gridy++;
            }
            if (gbc.gridy == 6) {
                panel.add(thirdParty, gbc);
                gbc.gridy++;
            }
        }
        selectionPanel = panel;
    }

    private void makeKeyPanel() {
        JPanel panel = new JPanel();
        panel.setBackground(Color.WHITE);
        panel.setBorder(new LineBorder(Color.BLACK, 1));
        // make components
        mySecret = new JLabel(" ");
        hisSecret = getTextField();
        hisSecret.setBorder(new LineBorder(Color.BLACK, 1));
        JLabel instruction0 = new HtmlLabel("enter your contact's secret string<br>(displayed on their device)");
        JLabel instruction1 = new HtmlLabel("or tell your contact this string:");
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
        panel.add(hisSecret, gbc);
        gbc.gridy++;
        panel.add(instruction1, gbc);
        gbc.gridy++;
        panel.add(mySecret, gbc);
        keyPanel = panel;
    }
}
