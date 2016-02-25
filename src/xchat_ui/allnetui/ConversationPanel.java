package allnetui;

import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.LineBorder;
import utils.HtmlLabel;
import utils.RoundedBorder;
import utils.ScrollPaneResizeAdapter;

/**
 *
 * @author Henry
 */
class ConversationPanel extends JPanel {

    // just to avoid a warning
    private static final long serialVersionUID = 1L;
    //
    // define this panel's command here; later we should move all commands to one place
    public static final String SEND_COMMAND = "SEND";
    public static final String CLOSE_COMMAND = "CLOSE";
    public static final String CONTACTS_COMMAND = "CONTACTS";
    public static final String EXCHANGE_KEYS_COMMAND = "EXCHANGE_KEYS";
    //
    private static final long DAY = 86400 * 1000;
    //
    // message bubble border params
    private int borderWidth = 1;
    private int borderRadius = 10;
    private int borderInset = 8;
    private Color borderColor = Color.BLACK;
    //
    private String contactName;
    private JPanel messagePanel;
    private HtmlLabel topLabel;
    private JScrollPane scrollPane;
    private boolean scrollToBottom;
    private JTextField msgField;
    // the buttons
    private JButton send;
    // the command prefix will identify which instance of the Class is sending the event
    private String commandPrefix;
    // default colors to use
    private static Color background = Color.GRAY, foreground = Color.WHITE;
    private static Color broadcastColor = Color.LIGHT_GRAY;
    private static Color ackedColor = Color.GREEN;
    private static Color newColor = Color.CYAN;
    // everything needed to turn messages green once they are acked
    private java.util.LinkedList<Message> unackedM = null;
    private java.util.LinkedList<JPanel> unackedP = null;
    private java.util.LinkedList<java.util.Vector<JLabel>> unackedL = null;

    ConversationPanel(String info, String commandPrefix, String contactName,
            boolean createDialogBox) {
        this.commandPrefix = commandPrefix;
        this.contactName = contactName;
        setBackground(background);
        // make the info label for the top of the panel
        topLabel = new HtmlLabel(info);
        topLabel.setOpaque(true);
        topLabel.setBackground(foreground);
        topLabel.setLineBorder(Color.BLACK, 1, false);

        // make the panel to hold the messages
        messagePanel = makeMessagePanel(background);
        scrollPane = new JScrollPane(messagePanel,
                ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
                ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        // must set a min and preferred size for the scroll pane
        // Dimension scrDim = new Dimension(250, 250);
        Dimension scrDim = new Dimension(1, 1);
        scrollPane.setMinimumSize(scrDim);
        scrollPane.setPreferredSize(scrDim);
        // so why not set max as well...
        scrollPane.setMaximumSize(scrDim);
        // don't want a border around it
        scrollPane.setBorder(BorderFactory.createEmptyBorder());
        // set it so the scroll wheel scrolls substantially
        scrollPane.getVerticalScrollBar().setUnitIncrement(10);
        // make it scroll to the bottom when we add something
        scrollPane.getVerticalScrollBar().addAdjustmentListener(
                new MyAdjustmentListener());
        // make it scroll to the bottom when resized
        scrollPane.getVerticalScrollBar().addComponentListener(
                new ScrollPaneResizeAdapter(scrollPane, true));
        //
        unackedM = new java.util.LinkedList<Message>();
        unackedP = new java.util.LinkedList<JPanel>();
        unackedL = new java.util.LinkedList<java.util.Vector<JLabel>>();
        // make the text input components
        msgField = new JTextField();
        msgField.setActionCommand(commandPrefix + ":" + SEND_COMMAND);
        send = makeButton("Send", SEND_COMMAND);
        // now add these components to our panel
        setLayout(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        // gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.PAGE_START;
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridheight = 1;
        gbc.gridwidth = 3;
        add(topLabel, gbc);
        gbc.anchor = GridBagConstraints.CENTER;
        gbc.gridx = 0;
        gbc.gridy++;
        gbc.weighty = 1.0;
        gbc.anchor = GridBagConstraints.PAGE_START;
        add(scrollPane, gbc);
        if (createDialogBox) {
            gbc.anchor = GridBagConstraints.CENTER;
            gbc.gridy++;
            gbc.weighty = 0.0;
            gbc.weightx = 1.0;
            gbc.gridwidth = 2;
            add(msgField, gbc);
            gbc.gridwidth = 1;
            gbc.gridx = 2;
            gbc.weightx = 0.0;
            add(send, gbc);
        }
    }

    public String getContactName() {
        return contactName;
    }

    // this provides the title on the conversation tab
    public String getTitle() {
        int idx = contactName.indexOf("@");
        if (idx < 1) {
            return contactName;
        }
        else {
            return (contactName.substring(0, idx));
        }
    }

    public String getMsgToSend() {
        String msg = msgField.getText();
        msgField.setText("");
        return (msg);
    }

    static void setDefaultColors(Color background, Color foreground,
            Color broadcastColor, Color ackedColor) {
        ConversationPanel.background = background;
        ConversationPanel.foreground = foreground;
        ConversationPanel.broadcastColor = broadcastColor;
        ConversationPanel.ackedColor = ackedColor;
    }

    void setListener(ActionListener listener) {
        send.addActionListener(listener);
        // send event when return key is entered
        msgField.addActionListener(listener);
    }

    private JButton makeButton(String text, String command) {
        JButton button = new JButton(text);
        button.setActionCommand(commandPrefix + ":" + command);
        return (button);
    }

    private JPanel makeMessagePanel(Color background) {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBackground(background);
        return (panel);
    }

    public void addMsg(String text, Message msg) {
        boolean isReceived = msg.to.equals(Message.SELF);
        boolean broadcast = msg.isBroadcast();
        boolean acked = msg.acked();
        boolean isNew = (msg.isNewMessage() ||
                         (isReceived &&
                          msg.receivedAt() + DAY > System.currentTimeMillis()));
        String[] lines = text.split("\n");
        Color bg = broadcast ? broadcastColor : acked ? ackedColor
                : isNew ? newColor : Color.WHITE;
        java.util.LinkedList<java.util.Vector<JLabel>> labels = null;
        if (!acked) {
            labels = unackedL;
        }

        JPanel bubble = makeBubble(isReceived, bg, labels, lines);
        JPanel inner = new JPanel();
        inner.setBackground(background);
        inner.setLayout(new BoxLayout(inner, BoxLayout.X_AXIS));
        if (isReceived) {
            inner.add(bubble);
            inner.add(Box.createHorizontalGlue());
        }
        else {
            inner.add(Box.createHorizontalGlue());
            inner.add(bubble);
        }
        if (!acked) {  // should parallel what happens in makeBubble
            // i.e. only add if not acked
            unackedM.addFirst(msg);
            unackedP.addFirst(bubble);
        }
        messagePanel.add(inner);
        messagePanel.add(Box.createRigidArea(new Dimension(0, 4)));
        // tell scroll panel to scroll to the bottom the next time it adjusts,
        // which will be triggered right now when it validates.  there is 
        // apparently no other way to do this 
        scrollToBottom = true;
        messagePanel.revalidate();
    }

    void ackMsg(Message msg) {
        for (int i = 0; i < unackedM.size(); i++) {
            if (unackedM.get(i).equals(msg)) {
                unackedP.get(i).setBackground(ackedColor);
                for (JLabel label : unackedL.get(i)) {
                    label.setBackground(ackedColor);
                }
                unackedM.remove(i);
                unackedP.remove(i);
                unackedL.remove(i);
                return;
            }
        }
        messagePanel.revalidate();
    }

    private JPanel makeBubble(boolean leftJustified, Color color,
            java.util.LinkedList<java.util.Vector<JLabel>> labels,
            String... lines) {
        JPanel panel = new JPanel();
        panel.setBackground(color);
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        JLabel label;
        java.util.Vector<JLabel> labelv = new java.util.Vector<JLabel>();
        for (int i = 0; i < lines.length; i++) {
            label = new JLabel(lines[i]);
            label.setOpaque(true);
            label.setBackground(color);
            if (leftJustified) {
                label.setAlignmentX(Component.LEFT_ALIGNMENT);
            }
            else {
                label.setAlignmentX(Component.RIGHT_ALIGNMENT);
            }
            panel.add(label);
            if (labels != null) {
                labelv.add(label);
            }
        }
        if (labels != null) {
            labels.addFirst(labelv);
        }
        // Border compound = BorderFactory.createCompoundBorder(new LineBorder(Color.BLACK, 1, true), new LineBorder(color, 2, true));
        // panel.setBorder(new LineBorder(Color.BLACK, 1, true));
        // panel.setBorder(compound);
        panel.setBorder(new RoundedBorder(borderColor, borderWidth, borderRadius, borderInset));
        return (panel);
    }

    // not used: text area doesn't size correctly inside a scroll pane
    private JTextArea makeBubble1(String... lines) {
        JTextArea panel = new JTextArea();
        panel.setBackground(Color.WHITE);
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        JLabel label;
        for (int i = 0; i < lines.length; i++) {
            label = new JLabel(lines[i]);
            label.setOpaque(true);
            label.setBackground(Color.WHITE);
            panel.add(label);
        }
        Border compound = BorderFactory.createCompoundBorder(new LineBorder(Color.BLACK, 1, true), new LineBorder(Color.WHITE, 2, true));
        panel.setBorder(compound);
        return (panel);
    }

    public void clearMsgs() {
        messagePanel.removeAll();
        messagePanel.validate();
    }

    void removeAllMsgs() {
        messagePanel.removeAll();
        validate();
    }

    void setTopLabelText(String... lines) {
        topLabel.setText(lines);
    }

    private class MyAdjustmentListener implements AdjustmentListener {

        private MyAdjustmentListener() {
        }

        @Override
        public void adjustmentValueChanged(AdjustmentEvent e) {
            if (scrollToBottom) {
                scrollToBottom = false;
                e.getAdjustable().setValue(e.getAdjustable().getMaximum());
            }
        }
    }

}
