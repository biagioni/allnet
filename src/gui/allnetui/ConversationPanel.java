package allnetui;

import java.awt.*;
import java.awt.event.*;
import java.util.ArrayList;
import javax.swing.*;
import javax.swing.border.Border;
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
class ConversationPanel extends JPanel implements ComponentListener {

    // just to avoid a warning
    private static final long serialVersionUID = 1L;
    //
    // define this panel's command here; later we should move all commands to one place
    public static final String SEND_COMMAND = "SEND";
    public static final String CLOSE_COMMAND = "CLOSE";
    public static final String CONTACTS_COMMAND = "CONTACTS";
    public static final String EXCHANGE_KEYS_COMMAND = "EXCHANGE_KEYS";
    public static final String DISPLAY_MORE_MSGS_COMMAND = "DISPLAY_MORE_MSGS_COMMAND";
    //
    private static final long DAY = 86400 * 1000;
    //
    // max height of input area
    // private static final int MAX_LINES = 10;
    // assume that N chars will wrap around (a little rough I guess)
    // private static final int CHARS_PER_LINE = 40;
    //
    // how many msgs to display
    private static final int DEFAULT_NUM_MSGS_TO_DISPLAY = 20;
    private int numMsgsToDisplay = DEFAULT_NUM_MSGS_TO_DISPLAY;
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
    private boolean scrollToBottom, scrollToTop;
    private JTextArea inputArea;
    // the buttons
    private JButton sendButton, moreMsgsButton;
    // morePanel holds moreMsgs button, need ref here for when we make new message panels
    private JPanel morePanel;
    // the command prefix will identify which instance of the Class is sending the event
    private String commandPrefix;
    // default colors to use
    private static Color backgroundColor = Color.GRAY, foregroundColor = Color.WHITE;
    private static Color broadcastColor = Color.LIGHT_GRAY;
    private static Color missingColor = Color.RED;
    private static Color ackedColor = Color.GREEN;
    private static Color newColor = Color.CYAN;
    //
    // keep list of the message bubbles that have yet to be acked
    private ArrayList<MessageBubble<Message>> unackedBubbles;
    private long lastReceived;  // used by caller
    // Component used for tracking / triggering resizing
    private Component resizingKey;
    // width of resizingKey when we last layed out message bubbles
    private int lastResizingWidth;
    // list of msg bubbles (so we can resize them when indicated
    private ArrayList<MessageBubble<Message>> bubbles;

    ConversationPanel(String info, String commandPrefix, String contactName,
        boolean createDialogBox, Component resizingKey) {
        this.commandPrefix = commandPrefix;
        this.contactName = contactName;
        //
        this.resizingKey = resizingKey;
        resizingKey.addComponentListener(this);
        lastResizingWidth = resizingKey.getWidth();
        //
        setBackground(backgroundColor);
        //
        // make the info label for the top of the panel
        topLabel = new HtmlLabel(info);
        topLabel.setOpaque(true);
        topLabel.setBackground(foregroundColor);
        topLabel.setLineBorder(Color.BLACK, 1, false);
        //
        // make morePanel before call to makeMessagePanel()
        moreMsgsButton = makeButton("Display More Messages", DISPLAY_MORE_MSGS_COMMAND);
        morePanel = new JPanel();
        morePanel.setBackground(backgroundColor);
        morePanel.setLayout(new BoxLayout(morePanel, BoxLayout.X_AXIS));
        morePanel.add(Box.createHorizontalGlue());
        morePanel.add(moreMsgsButton);
        morePanel.add(Box.createHorizontalGlue());
        // make the panel to hold the messages
        messagePanel = makeMessagePanel();
        scrollPane = new JScrollPane(messagePanel,
            ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
            ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        // must set a min and preferred size for the scroll pane
        Dimension scrDim = new Dimension(1, 1);
        scrollPane.setMinimumSize(scrDim);
        scrollPane.setPreferredSize(scrDim);
        // so why not set max as well...
        scrollPane.setMaximumSize(scrDim);
        // don't want a border around it
        scrollPane.setBorder(BorderFactory.createEmptyBorder());
        // set it so the scroll wheel scrolls substantially
        scrollPane.getVerticalScrollBar().setUnitIncrement(10);
        //
        // make it scroll to the bottom when we add something
        scrollPane.getVerticalScrollBar().addAdjustmentListener(
            new MyAdjustmentListener());
        // make it scroll to the bottom automatically when the scroll 
        // pane contents are resized
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
        // MyDocumentFilter filter = new MyDocumentFilter(CHARS_PER_LINE, MAX_LINES, true);
        // AbstractDocument doc = (AbstractDocument) inputArea.getDocument();
        // doc.setDocumentFilter(filter);
        Border inner = BorderFactory.createLineBorder(Color.WHITE, 4);
        Border outer = BorderFactory.createLineBorder(Color.BLACK, 1);
        Border textAreaBorder = BorderFactory.createCompoundBorder(outer, inner);
        inputArea.setBorder(textAreaBorder);
        //
        // make "sendPanel"
        JPanel sendPanel = new JPanel();
        sendPanel.setOpaque(true);
        sendPanel.setBackground(backgroundColor);
        sendPanel.setLayout(new BoxLayout(sendPanel, BoxLayout.Y_AXIS));
        sendPanel.add(Box.createVerticalGlue());
        sendButton = makeButton("Send", SEND_COMMAND);
        sendPanel.add(sendButton);
        //
        // now add all these components to our main panel
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
        // for resize/relayout of message bubbles when panel is resized
        bubbles = new ArrayList<>();
        // for tracking missing msgs
        lastReceived = -1;
    }

    public static int getDefaultNumMsgsToDisplay() {
        return DEFAULT_NUM_MSGS_TO_DISPLAY;
    }

    public int getNumMsgsToDisplay() {
        return numMsgsToDisplay;
    }

    public void disableMoreMsgsButton() {
        moreMsgsButton.setEnabled(false);
    }
    
    public void enableMoreMsgsButton() {
        moreMsgsButton.setEnabled(true);
    }
    
    public void setNumMsgsToDisplay(int numMsgsToDisplay) {
        this.numMsgsToDisplay = numMsgsToDisplay;
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

    static void setDefaultColors(Color backgroundColor, Color foregroundColor,
        Color broadcastColor, Color ackedColor) {
        ConversationPanel.backgroundColor = backgroundColor;
        ConversationPanel.foregroundColor = foregroundColor;
        ConversationPanel.broadcastColor = broadcastColor;
        ConversationPanel.ackedColor = ackedColor;
    }

    void setListener(ActionListener listener) {
        sendButton.addActionListener(listener);
        moreMsgsButton.addActionListener(listener);
        // no longer want to send event when return key is entered
        // msgField.addActionListener(listener);
    }

    private JButton makeButton(String text, String command) {
        JButton button = new JButton(text);
        button.setActionCommand(commandPrefix + ":" + command);
        return (button);
    }

    private JPanel makeMessagePanel() {
        JPanel panel = new JPanel();
        panel.setBackground(backgroundColor);
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.add(Box.createRigidArea(new Dimension(0, 10)));
        panel.add(morePanel);
        panel.add(Box.createRigidArea(new Dimension(0, 10)));
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
                if (scale > 1.0) // if we get messages from the future
                {
                    scale = 1.0;
                }
                if (scale < 0.0) // not likely
                {
                    scale = 0.0;
                }
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

    public void validateToBottom() {
        // tell scroll panel to scroll to the bottom the next time it adjusts,
        // which will be triggered right now when it validates.  there is 
        // apparently no other way to do this 
        scrollToBottom = true;
        messagePanel.revalidate();
    }

    public void validateToTop() {
        // tell scroll panel to scroll to the top the next time it adjusts,
        // which will be triggered right now when it validates.  there is 
        // apparently no other way to do this 
        scrollToTop = true;
        messagePanel.revalidate();
    }

    private void addBubble(MessageBubble<Message> bubble, boolean initial) {
        Message message = bubble.getMessage();
        boolean left = true;
        if (message != null) {
            left = message.to.equals(Message.SELF);
        }
        if (initial) {
            // make bubble (obviously)
            bubble.setBorder(new RoundedBorder(borderColor, borderWidth,
                borderRadius, borderInset));
            // save for resizing
            bubbles.add(bubble);
        }
        //
        JPanel inner = new JPanel();
        inner.setBackground(backgroundColor);
        inner.setLayout(new BoxLayout(inner, BoxLayout.X_AXIS));
        if (left) {
            inner.add(bubble);
            inner.add(Box.createHorizontalGlue());
        }
        else {
            inner.add(Box.createHorizontalGlue());
            inner.add(bubble);
        }
        messagePanel.add(inner);
        messagePanel.add(Box.createRigidArea(new Dimension(0, 4)));
    }

    public void addMissing(long numMissing) {
        String line = (numMissing + " messages missing");
        if (numMissing == 1) {
            line = "1 message missing";
        }
        Color bg = missingColor;
        MessageBubble<Message> bubble
            = new MessageBubble<>(null, true, bg, line, messagePanel);
        addBubble(bubble, true);
    }

    public void addMsg(String text, Message msg, JComponent container) {
        boolean isReceived = msg.to.equals(Message.SELF);
        // boolean broadcast = msg.isBroadcast();
        boolean acked = msg.acked();
        // boolean isNew = ((msg.isNewMessage() ||
        //                 (isReceived &&
        //                  (msg.receivedAt() + DAY >
        //                      System.currentTimeMillis()))));
        // String[] lines = text.split("\n");
        Color bg = getMsgColor(msg, isReceived);
        MessageBubble<Message> bubble
            = new MessageBubble<>(msg, isReceived, bg, text, container);
        addBubble(bubble, true);
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
        unackedBubbles.clear();
        bubbles.clear();
        // must restore the more msgs button at top of panel 
        messagePanel.add(Box.createRigidArea(new Dimension(0, 10)));
        messagePanel.add(morePanel);
        messagePanel.add(Box.createRigidArea(new Dimension(0, 10)));
        messagePanel.validate();
        lastReceived = -1;
    }

    void setTopLabelText(String... lines) {
        topLabel.setText(lines);
    }

    @Override
    public void componentResized(ComponentEvent e) {
        if (e.getComponent() == resizingKey) {
            int width = e.getComponent().getWidth();
            if (Math.abs(width - lastResizingWidth) / (1.0 * width) < 0.10) {
                return;
            }
            lastResizingWidth = width;
            messagePanel = makeMessagePanel();
            // force it to recalc chars per line
            MessageBubble.setEstimatedCharsPerLine(0);
            for (MessageBubble<Message> b : bubbles) {
                b.resizeBubble(width);
                addBubble(b, false);
            }
            scrollPane.setViewportView(messagePanel);
            messagePanel.addComponentListener(this);
            validateToBottom();
        }
        else if (e.getComponent() == messagePanel) {
            validateToBottom();
        }
    }

    @Override
    public void componentMoved(ComponentEvent e) {
    }

    @Override
    public void componentShown(ComponentEvent e) {
        // this seems never to be called so can't use it
    }

    @Override
    public void componentHidden(ComponentEvent e) {
    }

    // used to make scroll pane scroll to the bottom on changes
    private class MyAdjustmentListener implements AdjustmentListener {

        private MyAdjustmentListener() {
        }

        @Override
        public void adjustmentValueChanged(final AdjustmentEvent e) {
            Runnable r = new Runnable() {
                @Override
                public void run() {
                    if (scrollToBottom) {
                        scrollToBottom = false;
                        e.getAdjustable().setValue(e.getAdjustable().getMaximum());
                    }
                    if (scrollToTop) {
                        scrollToTop = false;
                        e.getAdjustable().setValue(e.getAdjustable().getMinimum());
                    }
                }
            };
            // schedule it in the event disp thread, but don't wait for it to execute
            SwingUtilities.invokeLater(r);
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
                text = text.substring(0, offs) + str
                    + text.substring(offs + length, text.length());
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

    // kind of a hack, but useful to track missing messages
    public long getLastReceived() {
        return this.lastReceived;
    }

    public void setLastReceived(long value) {
        this.lastReceived = value;
    }

}
