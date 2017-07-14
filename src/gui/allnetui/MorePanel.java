package allnetui;

import java.awt.*;
import java.awt.event.ActionListener;
import javax.swing.*;
import javax.swing.border.LineBorder;
import javax.swing.border.MatteBorder;
import utils.HtmlLabel;

/**
 *
 * @author edo (using code by Henry)
 */
class MorePanel extends JPanel {

    private static final long serialVersionUID = 1L;
    // commands to send to UIController
    public static final String CLOSE_COMMAND = "CLOSE";
    public static final String TRACE_COMMAND = "TRACE";
    private static final String UNVERIFIED_INIT_STRING
        = "no unverified broadcasts yet";
    // private data fields
    // private data fields
    private JLabel recentUnverifiedBroadcasts;
    private String recentText;
    private JButton traceButton;
    private JLabel traceLabel;
    private String traceText;

/*
    private HtmlLabel topLabel;
    private JTextField nameInput, variableInput;
    private String mySecretShortString, mySecretLongString;
    private JPanel selectionPanel;
    private JPanel keyPanel;
    private JButton goButton;
    private JLabel mySecretShort, mySecretLong;
    private JRadioButton[] buttons;
    private ButtonGroup group;
*/
    private String commandPrefix = UI.MORE_PANEL_ID;

    MorePanel(Color background, Color foreground) {
        setBackground(background);
        // put the trace button and the space for the trace output
        traceButton = new JButton("trace");
        traceButton.setBackground(foreground);
        traceButton.setActionCommand(commandPrefix + ":" + TRACE_COMMAND);
        traceText = "<html><br>\n<br>\n<br>\n<br>\n<br>\n<br></html>\n ";
        traceLabel = new JLabel(traceText);
        traceLabel.setOpaque(true);
        traceLabel.setBackground(Color.WHITE);
        traceLabel.setBorder(new LineBorder(Color.BLACK, 1, false));
        recentText = "";
        recentUnverifiedBroadcasts = new JLabel(UNVERIFIED_INIT_STRING);
        recentUnverifiedBroadcasts.setOpaque(true);
        recentUnverifiedBroadcasts.setBackground(Color.WHITE);
        recentUnverifiedBroadcasts.setBorder(new LineBorder(Color.BLACK,
                                                            1, false));
        // add them to the panel
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
        add(recentUnverifiedBroadcasts, gbc);
        gbc.gridy++;
        add(traceButton, gbc);
        gbc.gridy++;
        add(traceLabel, gbc);
        // expand bottom area vertically to fill extra space
        gbc.weighty = 1.0;
        add(Box.createRigidArea(new Dimension(1, 0)), gbc);
    }

    // like the name says
    void setTraceText(String text) {
        traceText = text;
// System.out.println ("trace text is " + traceText);
        traceLabel.setText("<html><pre>" + traceText + "</pre></html>");
    }

    void addTraceText(String text) {
        traceText = traceText + text;
// System.out.println ("add trace text gives " + traceText);
        traceLabel.setText("<html><pre>" + traceText + "</pre></html>");
    }

    static String addAndTruncateToNlines (String text,
                                          String previousText, int n) {
        String result = text + "\n<br>" + previousText;
        int count = 0;
        int index = 0;
        while ((index = result.indexOf("\n", index)) >= 0) {
            if ((count++) >= n)  // truncate the rest of the string
                return result.substring(0, index);
            index++;  // start looking at the next character position
        }
// System.out.println ("addAndTruncateToNLines (" + n + ") gives " + result);
        return result;
    }

    void addUnverifiedBroadcasts(String text) {
System.out.print("concatenating " + text + " with " + recentText + " gives ");
        recentText = addAndTruncateToNlines (text, recentText, 4);
System.out.println(recentText);
        recentUnverifiedBroadcasts.setText(recentText);
    }

//    // return the index of the selected button
//    int getSelectedButton() {
//        for (int i = 0; i < buttons.length; i++) {
//            if (buttons[i].isSelected()) {
//                return (i);
//            }
//        }
//        return (-1);
//    }

    // set where we will send events
    void setActionListener(ActionListener listener) {
        traceButton.addActionListener(listener);
    }

    String getCommandPrefix() {
        return commandPrefix;
    }

    void setCommandPrefix(String commandPrefix) {
        this.commandPrefix = commandPrefix;
    }

//    private JTextField getTextField() {
//        JTextField field = new JTextField();
//        field.setHorizontalAlignment(JTextField.CENTER);
//        return (field);
//    }
//
//    final int unimplemented_offset = 1;  // for "both contacts of"
//    final int num_choices = 4 - unimplemented_offset;
//
//    private void makeSelectionPanel() {
//        JPanel panel = new JPanel();
//        // if we are using a L&F, then we can't change the button color, which is nuts.
//        // the best way (I think) is to make one's own button component, which is not
//        // so hard to do.
//        panel.setBackground(Color.WHITE);
//        panel.setBorder(new LineBorder(Color.BLACK, 1));
//        // make components
//        group = new ButtonGroup();
//        buttons = new JRadioButton[num_choices];
//        JLabel[] labels = new JLabel[num_choices];
//        String[] labelText = new String[]{
//            "new contact has a wireless device<br>" +
//                 "within 10m (30ft):<br>" +
//                 "give contact your short secret<br>" +
//                 "or enter their short secret below",
//            "new contact is at a distance:<br>" +
//                 "give contact your long secret<br>" +
//                 "or enter their long secret below",
//            "subscribe to a broadcast:<br>" +
//                 "enter the address below<br>" +
//                 "(no secrets needed)</b>",
////            "you know your contact's AllNet address:<br>" +
////                 "(or want to subscribe to a broadcast)<br>" +
////                 "enter the address above",
////            "you are both contacts of:<br>" +
////                 "enter the name below<br>" +
////                 "(not yet available)",
//        };
//        for (int i = 0; i < num_choices; i++) {
//            if (i != 1)
//                buttons[i] = new JRadioButton();
//            else
//                buttons[i] = new JRadioButton("", true);
//            buttons[i].setActionCommand(commandPrefix + ":radiobutton" + i);
//            buttons[i].setBackground(Color.WHITE);
//            group.add(buttons[i]);
//            labels[i] = new HtmlLabel(labelText[i]);
//        }
//        variableInput = getTextField();
//        variableInput.setBorder(new LineBorder(Color.BLACK, 1));
//        // do layout
//        panel.setLayout(new GridBagLayout());
//        GridBagConstraints gbc = new GridBagConstraints();
//        gbc.fill = GridBagConstraints.HORIZONTAL;
//        gbc.weightx = 1.0;
//        gbc.weighty = 0.0;
//        gbc.insets = new Insets(5, 5, 5, 5);
//        gbc.anchor = GridBagConstraints.CENTER;
//        gbc.gridx = 0;
//        gbc.gridy = 0;
//        gbc.gridheight = 1;
//        gbc.gridwidth = 1;
//        for (int i = 0; i < 4 - unimplemented_offset; i++) {
//            gbc.gridx = 0;
//            panel.add(buttons[i], gbc);
//            gbc.gridx = 1;
//            panel.add(labels[i], gbc);
//            gbc.gridy++;
////            if (gbc.gridy == 1) {
////                panel.add(otherSecretShort, gbc);
////                gbc.gridy++;
////            }
////            if (gbc.gridy == 3) {
////                panel.add(ahra, gbc);
////                gbc.gridy++;
////            }
////            if (gbc.gridy == 5) {
////                panel.add(thirdParty, gbc);
////                gbc.gridy++;
////            }
//        }
//        selectionPanel = panel;
//    }
//
//    private void makeKeyPanel() {
//        JPanel panel = new JPanel();
//        panel.setBackground(Color.WHITE);
//        panel.setBorder(new LineBorder(Color.BLACK, 1));
//        // make components
//        variableInput = getTextField();
//        variableInput.setBorder(new LineBorder(Color.BLACK, 1));
//        JLabel instruction0 =
//            new HtmlLabel("enter your contact's secret and press <b>go</b>,");
//        JLabel instruction1 = new HtmlLabel("or just press <b>go</b> and " +
//                                            "your secret will be shown on " +
//                                            "the next panel:");
//        // do the layout
//        panel.setLayout(new GridBagLayout());
//        GridBagConstraints gbc = new GridBagConstraints();
//        gbc.fill = GridBagConstraints.HORIZONTAL;
//        gbc.weightx = 1.0;
//        gbc.weighty = 0.0;
//        gbc.insets = new Insets(5, 5, 5, 5);
//        gbc.anchor = GridBagConstraints.CENTER;
//        gbc.gridx = 0;
//        gbc.gridy = 0;
//        gbc.gridheight = 1;
//        gbc.gridwidth = 1;
//        panel.add(instruction0, gbc);
//        gbc.gridy++;
//        panel.add(variableInput, gbc);
//        gbc.gridy++;
//        panel.add(instruction1, gbc);
////        gbc.gridy++;
////        panel.add(mySecretShort, gbc);
////        gbc.gridy++;
////        panel.add(mySecretLong, gbc);
//        keyPanel = panel;
//    }
}
