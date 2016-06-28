package allnetui;

import java.awt.*;
import java.awt.event.*;
import java.util.ArrayList;
import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.text.AbstractDocument;
import javax.swing.text.AttributeSet;
import javax.swing.text.BadLocationException;
import javax.swing.text.DocumentFilter;
import utils.HtmlLabel;
import utils.MessageBubble;
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
    // max height of input area
    private static final int MAX_LINES = 10;
    // assume that N chars will wrap around (a little rough I guess)
    private static final int CHARS_PER_LINE = 40;
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
    private JTextArea inputArea;
    // the buttons
    private JButton sendButton;
    // the command prefix will identify which instance of the Class is sending the event
    private String commandPrefix;
    // default colors to use
    private static Color background = Color.GRAY, foreground = Color.WHITE;
    private static Color broadcastColor = Color.LIGHT_GRAY;
    private static Color ackedColor = Color.GREEN;
    private static Color newColor = Color.CYAN;
    // keep list of the message bubbles that have yet to be acked
    private ArrayList<MessageBubble<Message>> unackedBubbles;

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
        unackedBubbles = new ArrayList<>();
        //
        // make the text input stuff
        // set default height to one line
        inputArea = new JTextArea(1, 10);
        // wrap text
        inputArea.setWrapStyleWord(true);
        inputArea.setLineWrap(true);
        // limit number of lines 
        MyDocumentFilter filter = new MyDocumentFilter(CHARS_PER_LINE, MAX_LINES, true);
        AbstractDocument doc = (AbstractDocument) inputArea.getDocument();
        doc.setDocumentFilter(filter);
        Border inner = BorderFactory.createLineBorder(Color.WHITE, 4);
        Border outer = BorderFactory.createLineBorder(Color.BLACK, 1);
        Border textAreaBorder = BorderFactory.createCompoundBorder(outer, inner);
        inputArea.setBorder(textAreaBorder);
        //
        sendButton = makeButton("Send", SEND_COMMAND);
        JPanel sendPanel = new JPanel();
        sendPanel.setOpaque(true);
        sendPanel.setBackground(background);
        sendPanel.setLayout(new BoxLayout(sendPanel, BoxLayout.Y_AXIS));
        sendPanel.add(Box.createVerticalGlue());
        sendPanel.add(sendButton);
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
            add(inputArea, gbc);
            gbc.gridwidth = 1;
            gbc.gridx = 2;
            gbc.weightx = 0.0;
            add(sendPanel, gbc);
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
        String msg = inputArea.getText();
        inputArea.setText("");
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
        sendButton.addActionListener(listener);
        // no longer want to send event when return key is entered
        // msgField.addActionListener(listener);
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

    private Color getMsgColor(Message msg, boolean isReceived) {
        if (msg.acked()) {
            return ackedColor;
        }
        if (msg.isBroadcast()) {
            return broadcastColor;
        }
        if (msg.isNewMessage()) {
            return newColor;
        }
        if (isReceived) {
            long now = System.currentTimeMillis();
            if (msg.receivedAt() + DAY > now) {
                double scale = ((double) (msg.receivedAt() + DAY - now)) / DAY;
                float r = (float) (newColor.getRed() / 255.0);
                float g = (float) (newColor.getGreen() / 255.0);
                float b = (float) (newColor.getBlue() / 255.0);
                float a = (float) (newColor.getAlpha() / 255.0);
                r = (float) (1.0 - ((1.0 - r) * scale));
                g = (float) (1.0 - ((1.0 - g) * scale));
                b = (float) (1.0 - ((1.0 - b) * scale));
                return new Color(r, g, b, a);
            }
        }
        return Color.WHITE;
    }

    public void addMsg(String text, Message msg) {
        boolean isReceived = msg.to.equals(Message.SELF);
        boolean broadcast = msg.isBroadcast();
        boolean acked = msg.acked();
        boolean isNew = (msg.isNewMessage()
            || (isReceived && (msg.receivedAt() + DAY > System.currentTimeMillis())));
        String[] lines = text.split("\n");

        Color bg = getMsgColor(msg, isReceived);

        // Color bg = broadcast ? broadcastColor : acked ? ackedColor
        //    : isNew ? newColor : Color.WHITE;
//
        MessageBubble<Message> bubble = new MessageBubble<>(msg, isReceived, bg, lines);
        bubble.setBorder(new RoundedBorder(borderColor, borderWidth, borderRadius, borderInset));
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
        messagePanel.add(inner);
        messagePanel.add(Box.createRigidArea(new Dimension(0, 4)));
        // tell scroll panel to scroll to the bottom the next time it adjusts,
        // which will be triggered right now when it validates.  there is 
        // apparently no other way to do this 
        scrollToBottom = true;
        messagePanel.revalidate();
        //
        // update ack tracking
        if (!acked) {
            // i.e. only add if not acked
            unackedBubbles.add(bubble);
        }
    }
 
    void ackMsg(Message msg) {
        for (MessageBubble<Message> bubble : unackedBubbles) {
            if (bubble.getMessage().equals(msg)) {
                unackedBubbles.remove(bubble);
                bubble.setBubbleBackground(ackedColor);
                break;
            }
        }
        messagePanel.revalidate();
    }

    public void clearMsgs() {
        messagePanel.removeAll();
        messagePanel.validate();
        unackedBubbles.clear();
    }

    void setTopLabelText(String... lines) {
        topLabel.setText(lines);
    }

    // used to make scroll pane scroll to the bottom on changes
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

    // used to limit the growth of the inputArea
    private class MyDocumentFilter extends DocumentFilter {

        private int charsPerLine, maxLines;
        private boolean beep;

        private MyDocumentFilter(int charsPerLine, int maxLines, boolean beep) {
            this.charsPerLine = charsPerLine;
            this.maxLines = maxLines;
            this.beep = beep;
        }

        @Override
        public void insertString(DocumentFilter.FilterBypass fb, int offs,
            String str, AttributeSet a)
            throws BadLocationException {
            // construct the new text, and then test it
            String text = fb.getDocument().getText(0, fb.getDocument().getLength());
            if (offs == 0) {
                text = str + text;
            }
            else if (offs == text.length()) {
                text = text + str;
            }
            else {
                text = text.substring(0, offs) + str + text.substring(offs, text.length());
            }

            if (goNoGo(text)) {
                super.insertString(fb, offs, str, a);
            }
            else if (beep) {
                Toolkit.getDefaultToolkit().beep();
            }
        }

        @Override
        public void replace(DocumentFilter.FilterBypass fb, int offs,
            int length,
            String str, AttributeSet a)
            throws BadLocationException {
            // construct the new text, and then test it
            String text = fb.getDocument().getText(0, fb.getDocument().getLength());
            if (offs == 0) {
                text = str + text;
            }
            else if (offs == text.length()) {
                text = text + str;
            }
            else {
                text = text.substring(0, offs) + str + text.substring(offs + length, text.length());
            }
            // System.out.println(text);
            if (goNoGo(text)) {
                super.replace(fb, offs, length, str, a);
            }
            else if (beep) {
                Toolkit.getDefaultToolkit().beep();
            }
        }

        private boolean goNoGo(String text) {
            int lines = 1;
            int ptr = 0;
            int charCount = 0;
            while (ptr < text.length()) {
                if (text.charAt(ptr) == '\n') {
                    lines++;
                    charCount = 0;
                }
                else {
                    charCount++;
                    if (charCount >= charsPerLine) {
                        lines++;
                        charCount = 0;
                    }
                }
                ptr++;
            }
            return (lines <= maxLines);
        }
    }

}
