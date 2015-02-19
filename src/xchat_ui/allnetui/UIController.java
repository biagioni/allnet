package allnetui;

import java.awt.Component;
import java.awt.event.ActionEvent;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import javax.swing.SwingUtilities;
import utils.ApplicationFrame;
import utils.ControllerInterface;
import utils.tabbedpane.MyTabbedPane;

/**
 * The C of MVC.  Receives and processes UI and application events.  The idea
 * is to put all UI logic (and sometimes application logic, when feasible) in
 * one place.
 * 
 *   M <=> C <=> V
 *         |
 *    Application
 * 
 * 
 * @author Henry
 */
class UIController implements ControllerInterface, UIAPI {

    // for formatting message times
    private static SimpleDateFormat formatter =
            //          new SimpleDateFormat("yyyy/MM/dd  HH:mm:ss z");
            new SimpleDateFormat("yyyy/MM/dd  HH:mm:ss");
    //
    // reference to the swing Frame in which the ui is running 
    private ApplicationFrame frame;
    //
    // will need a references to the ui panels
    private ContactsPanel contactsPanel;
    private NewContactPanel newContactPanel;
    private MyTabbedPane myTabbedPane;
    // need to keep client data (contacts, keys, conversations, etc.)
    private ClientData clientData;
    // for formatting text messages 
    private int maxLineLength = 30;

    // constructor
    UIController(ClientData clientData) {
        this.clientData = clientData;
    }

    //-----------------------------------------
    //
    //  public API methods follow
    //
    //-----------------------------------------
    // the application should call this method after a valid message is received
    @Override
    public void messageReceived(final String from, final long sentTime, final String text, final boolean broadcast) {
        Runnable r = new Runnable() {

            Message message = new Message(from, Message.SELF, sentTime, text, broadcast);

            @Override
            public void run() {
// System.out.println("processing received message " + message.toString());
                processReceivedMessage(message);
            }
        };
        // schedule it in the event disp thread, but don't wait for it to execute
        SwingUtilities.invokeLater(r);
    }

    // initialization should call this method at startup with older messages
    @Override
    public void savedMessages(final Message[] messages) {
        Runnable r = new Runnable() {

            @Override
            public void run() {
                for (Message message : messages) {
                    if (message.sentNotReceived) {
                        displaySentMessage(message);
                    }
                    else {
                        processReceivedMessage(message);
                    }
                }
            }
        };
        // schedule it in the event disp thread, but don't wait for it to execute
        SwingUtilities.invokeLater(r);
    }

    // the application should call this method after a message has been successfully sent
    @Override
    public void messageSent(final String to, final long sentTime, final String text) {
        Runnable r = new Runnable() {

            Message message = new Message(Message.SELF, to, sentTime, text, false);

            @Override
            public void run() {
                displaySentMessage(message);
            }
        };
        // schedule it in the event disp thread, but don't wait for it to execute
        SwingUtilities.invokeLater(r);
    }

    // the application should call this method to tell the UI about a new contact
    @Override
    public void contactCreated(final String contactName,
            final boolean isBroadcast) {
        Runnable r = new Runnable() {

            @Override
            public void run() {
                clientData.createContact(contactName, isBroadcast);
                updateContactsPanel(contactName, isBroadcast);
                KeyExchangePanel kep = getKeyExchangePanel(contactName);
                if (kep != null) {
                    showKeyExchangeSuccess(kep, contactName);
                }
            }
        };
        // schedule it in the event disp thread, but don't wait for it to execute
        SwingUtilities.invokeLater(r);
    }

    @Override
    public void contactCreated(final String contactName) {
        contactCreated(contactName, false);
    }

    @Override
    public void broadcastContactCreated(final String contactName) {
        contactCreated(contactName, true);
    }

    // the application should call this method to tell the UI to remove a contact
    @Override
    public void contactDeleted(final String contactName) {
        Runnable r = new Runnable() {

            @Override
            public void run() {
                clientData.removeContact(contactName);
                contactsPanel.removeName(contactName);
                myTabbedPane.removeTab(contactName);
            }
        };
        // schedule it in the event disp thread, but don't wait for it to execute
        SwingUtilities.invokeLater(r);
    }

//    // the application should call this method to update a user's key
//    @Override
//    public void updateKey(final String contactName, final String key) {
//        Runnable r = new Runnable() {
//
//            @Override
//            public void run() {
//                clientData.setKey(contactName, key);
//            }
//        };
//        // schedule it in the event disp thread, but don't wait for it to execute
//        SwingUtilities.invokeLater(r);
//    }
    //-----------------------------------------
    //
    //  end of public API methods
    //
    //-----------------------------------------
    // setters
    void setContactsPanel(ContactsPanel contactsPanel) {
        this.contactsPanel = contactsPanel;
        // add all contacts to the contacts panel
        Iterator<String> it = clientData.getContactIterator();
        String contactName;
        while (it.hasNext()) {
            contactName = it.next();
            updateContactsPanel(contactName, clientData.isBroadcast(contactName));
        }
        contactsPanel.setActionListener(this);
    }

    void setNewContactPanel(NewContactPanel newContactPanel) {
        this.newContactPanel = newContactPanel;
        newContactPanel.setActionListener(this);
    }

    void setMyTabbedPane(MyTabbedPane myTabbedPane) {
        this.myTabbedPane = myTabbedPane;
    }

    void setMaxLineLength(int maxLineLength) {
        this.maxLineLength = maxLineLength;
    }

    // allow us to get a ConversationPanel by name.  need this when we receive
    // an event from a conv panel
    ConversationPanel getConversationPanel(String contactName) {
        Component c = myTabbedPane.getTabContent(contactName);
        if (c instanceof ConversationPanel) {
            return ((ConversationPanel) c);
        }
        else {
            return (null);
        }
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        // print events as received for debug
        if (UI.debug) {
            System.out.println(e.getActionCommand());
        }
        String[] actionCommand = e.getActionCommand().split(":");
        // must have at least a source name at index 0, and a command at index 1
        if (actionCommand.length < 2) {
            // indicates a programming error
            throw new RuntimeException("bad command received: " + e.getActionCommand());
        }
        // process the event/command, depending on the source name
        if (actionCommand[0].equalsIgnoreCase(contactsPanel.getCommandPrefix())) {
            // from the contacts panel
            processContactsEvent(actionCommand[1]);
        }
        else if (actionCommand[0].equalsIgnoreCase(newContactPanel.getCommandPrefix())) {
            // from the new contact panel
            processNewContactEvent(actionCommand[1]);
        }
        else if (actionCommand[0].equalsIgnoreCase(myTabbedPane.getCommandPrefix())) {
            // from the tabbed pane
            processTabEvent(actionCommand[1]);
        }
        else if (actionCommand[0].startsWith(UI.KEY_EXCHANGE_PANEL_ID)) {
            // from the tabbed pane
            processKeyExchangePanelEvent(actionCommand);
        }
        else {
            // must be from a conversation panel
            processConversationPanelEvent(actionCommand);
        }
    }

    private String getContactFromWindow(KeyExchangePanel kep) {
        String contact = kep.getText(0);
        contact = contact.replace("exchanging keys with", "");
        contact = contact.replaceFirst("^\\s*", "");
        contact = contact.replaceFirst("\\s*$", "");
        contact = contact.replaceAll("\\n", "");
        return contact;
    }

    private void resendKey(KeyExchangePanel kep) {
// get the contact and the secrets from the text displayed in the window.
// this is kind of backwards -- really they should be saved somewhere
        String contact = getContactFromWindow(kep);
        String [] secretsText = kep.getTextLines(1);
        String secret1 = null;
        String secret2 = null;
        for (String s: secretsText) {
            s = s.replaceAll("^\\s*", "");
            s = s.replaceAll("\\s*$", "");
            if ((s.length() > 0) &&
                (! (s.contains("!"))) &&
                (! (s.contains(":")))) {
                if (secret1 == null)
                    secret1 = s;
                else if (secret2 == null)
                    secret2 = s;
                else
                    System.out.println ("secrets " + secret1 +  ", " + 
                                        secret2 + ", found " + s);
            }
        }
        int hops = 1;
        if ((secret1 != null) && (secret1.length() >= 14))
            hops = 6;
        if (XchatSocket.sendKeyRequest(contact, secret1, secret2, hops))
            System.out.println("resent key request");
        if (secret2 == null) {
//          System.out.println ("resend key, contact '" + contact + 
//                              "', secret " + secret1);
            kep.setText(1, " Resend Key button pressed !!!", "",
                        " Shared secret:", " " + secret1);
        } else {
//          System.out.println ("resend key, contact '" + contact + 
//                              "', secrets " + secret1 +
//                              " and " + secret2);
            kep.setText(1, " Resend Key button pressed !!!", "",
                        " Shared secret:", " " + secret1, " or:",
                        " " + secret2, " ");
        }
    }

    private void processKeyExchangePanelEvent(String[] actionCommand) {
        switch (actionCommand[1]) {
            case KeyExchangePanel.CLOSE_COMMAND:
                myTabbedPane.removeTab(actionCommand[0]);
                myTabbedPane.setSelected(UI.CONTACTS_PANEL_ID);
                break;
            case KeyExchangePanel.CANCEL_COMMAND:
                myTabbedPane.removeTab(actionCommand[0]);
                myTabbedPane.setSelected(UI.CONTACTS_PANEL_ID);
                break;
            case KeyExchangePanel.RESEND_KEY_COMMAND:
                resendKey((KeyExchangePanel) myTabbedPane.getTabContent(actionCommand[0]));
                break;
        }
    }

    // update the ContactsPanel with the info related to this contact 
    private void updateContactsPanel(String contact, boolean broadcast) {
        Conversation conv = clientData.getConversation(contact);
        if (conv == null) {
            throw new RuntimeException("tried to update contacts panel for invalid contact name: " + contact);
        }
        int unreadCount = conv.getNumNewMsgs();
        if (unreadCount > 0) {
            String s = (unreadCount == 1) ? "" : "s";
            contactsPanel.placeInTop(contact, pad(contact, " ", 12) + " " + unreadCount + "  new message" + s, broadcast);
        }
        else {
            String timeText;
            long lastMsgTime = conv.getLastRxMessageTime();
            if (lastMsgTime != 0) {
                // other constructors are deprecated
                Date date = new Date();
                date.setTime(lastMsgTime);
                timeText = formatter.format(date);
            }
            else {
                timeText = "";
            }
            contactsPanel.placeInBottom(contact, pad(contact, " ", 12) + " " + timeText, broadcast);
        }
        // and finally, update the info at the top of the panel
        updateContactsPanelStatus();
    }

//    private void updateContactsPanel(String contactName, boolean broadcast) {
//        updateContactsPanel(contactName, broadcast);
//    }
//    private void updateContactsPanelBC(String contact) {
//        updateContactsPanel(contact, true);
//    }
    // give method package access so that it can be called at startup
    void updateContactsPanelStatus() {
        int n = clientData.getNumContacts();
        int m = clientData.getNumContactsWithNewMsgs();
        String line1 = " " + m + " contact";
        if (m != 1) {
            line1 = line1 + "s";
        }
        line1 = line1 + " with new messages";
        String line2 = " " + n + " contact";
        if (n != 1) {
            line2 = line2 + "s";
        }
        line2 = line2 + " total";
        contactsPanel.setTopLabelText(line1, line2);
    }

    // pad a String to a fixed length
    private String pad(String src, String pad, int length) {
        StringBuilder sb = new StringBuilder(src);
        while (sb.length() < length) {
            sb.append(pad);
        }
        return (sb.toString());
    }

    private void processTabEvent(String contactName) {
        // make sure we're talking about the tab just selected (not the deselected one)
        if (!contactName.equals(myTabbedPane.getSelectedID())) {
            return;
        }
        // assume the conversation tab name is the same as the respective contact 
        if (!clientData.contactExists(contactName)) {
            // not a conversation tab; no action to take
            return;
        }
        // it's a conversation tab. 
        Conversation conv = clientData.getConversation(contactName);
        if (conv == null) {
            throw new RuntimeException("no Conversation Object for contact: " + contactName);
        }
        conv.setReadAll();
        updateContactsPanel(contactName, clientData.isBroadcast(contactName));
        updateConversationPanels();
    }

    private void processContactsEvent(String contactName) {
        // see if there is a tab open for this conversation
        ConversationPanel cp = (ConversationPanel) myTabbedPane.getTabContent(contactName);
        if (cp == null) {
            // no such tab, so make the conversation panel
            // (the contact's name is also the command prefix)
            if (!clientData.isBroadcast(contactName)) {
                cp = new ConversationPanel(" conversation with " + contactName, contactName, contactName);
            }
            else {
                cp = new ConversationPanel(" broadcast from " + contactName, contactName, contactName);
            }
            cp.setName(contactName);
            cp.setListener(this);
            // display the conversation on the new panel
            Conversation conv = clientData.getConversation(contactName);
            Iterator<Message> it = conv.getIterator();
            Message msg;
            while (it.hasNext()) {
                msg = it.next();
                cp.addMsg(formatMessage(msg, maxLineLength), msg.to.equals(Message.SELF), msg.broadcast);
            }
            myTabbedPane.addTabWithClose(contactName, cp.getTitle(), cp, ConversationPanel.CLOSE_COMMAND);
            myTabbedPane.setSelected(cp);
        }
        else {
            // already exists, so select it
            // myTabbedPane.setSelectedIndex(i);
            myTabbedPane.setSelected(contactName);
        }
        // it's a conversation tab, so update the contacts panel
        updateContactsPanel(contactName, clientData.isBroadcast(contactName));
        // update the stats at top of all conversation panels
        updateConversationPanels();
    }

    private String[] makeMiddlePanel(boolean useLongSecret) {
        String secret = newContactPanel.getMySecretShort();
        int minLength = 6;
        if (useLongSecret) {
            secret = newContactPanel.getMySecretLong();
            minLength = 14;
        }
        String entered = newContactPanel.getVariableInput();
        if (entered.length() >= minLength) {
            return new String[]{
                        " Shared secret:",
                        " " + secret,
                        " or:",
                        " " + newContactPanel.getVariableInput()
                    };
        }
        else {
            return new String[]{
                        " Shared secret:",
                        " " + secret
                    };
        }
    }

    private void processNewContactEvent(String command) {
        // here we can use newContactPanel's getter methods to grab
        // the user's input and send it to the application
//        System.out.println("UIController.java: pNCE " + command);
        KeyExchangePanel kep;
        if (command.equals("go")) {
            String contact = newContactPanel.getInputName();
            int button = newContactPanel.getSelectedButton();
            switch (button) {
                case -1:
                    System.out.println("UIController.java: new contact " + contact
                            + ", no button selected");
                    break;
                case 0:

                    System.out.println("new 1-hop contact " + contact + ", "
                            + ", secret "
                            + newContactPanel.getVariableInput() + "/"
                            + newContactPanel.getMySecretShort());
                    // create the key exchange panel if it doesn't already exist
                    kep = getKeyExchangePanel(contact);
                    if (kep == null) {
                        // now put up a key exchange panel
                        String[] middlePanelMsg = makeMiddlePanel(false);
                        String[] bottomPanelMsg = new String[]{
                            " Key exchange in progress",
                            " Sent your key",
                            " Waiting for key from " + contact
                        };
                        createKeyExchangePanel(contact, middlePanelMsg,
                                bottomPanelMsg, true);
                    }
                    if (XchatSocket.sendKeyRequest(contact,
                            newContactPanel.getMySecretShort(),
                            newContactPanel.getVariableInput(), 1)) {
                        System.out.println("sent direct wireless key request");
                        newContactPanel.setMySecret();
                    }
                    else {
                        System.out.println("unable to send direct key request");
                    }
                    break;
                case 1:
                    System.out.println("new long-distance contact " + contact
                            + ", secret "
                            + newContactPanel.getVariableInput() + "/"
                            + newContactPanel.getMySecretLong());
                    kep = getKeyExchangePanel(contact);
                    if (kep == null) {
                        // now put up a key exchange panel
                        String[] middlePanelMsg = makeMiddlePanel(true);
                        String[] bottomPanelMsg = new String[]{
                            " Key exchange in progress",
                            " Sent your key",
                            " Waiting for key from " + contact
                        };
                        createKeyExchangePanel(contact, middlePanelMsg,
                                bottomPanelMsg, true);
                    }
                    //
                    if (XchatSocket.sendKeyRequest(contact, newContactPanel.getMySecretLong(),
                            newContactPanel.getVariableInput(), 6)) {
                        System.out.println("sent key request with 6 hops");
                        newContactPanel.setMySecret();
                    }
                    else {
                        System.out.println("unable to send key request");
                    }
                    break;
                case 2:
                    System.out.println("new ahra contact " + contact + ", "
                            + newContactPanel.getVariableInput());
                    String ahra = newContactPanel.getVariableInput();
                    if ((ahra == null) || (ahra.indexOf('@') < 0)) {
                        ahra = contact;
                    }
                    if ((ahra == null) || (ahra.indexOf('@') < 0)) {
                        System.out.println("new ahra contact " + contact
                                + " must contain '@' sign");
                    }
                    else if (XchatSocket.sendSubscription(ahra)) {
                        System.out.println("sent ahra subscription");
                    }
                    else {
                        System.out.println("unable to send ahra subscription");
                    }
                    break;
//                case 3:
//                    System.out.println("new common contact for " + contact + " is "
//                            + newContactPanel.getVariableInput());
//                    System.out.println("  (not implemented)");
//                    break;
                default:
                    System.out.println("UIController.java: unknown button "
                            + button + " for contact " + contact);
                    break;
            }
        }
    }

    private void processConversationPanelEvent(String[] actionCommand) {
        String contactName = actionCommand[0];
        String buttonName = actionCommand[1];
        ConversationPanel cp = getConversationPanel(contactName);
        if (cp == null) {
            // should never happen
            throw new RuntimeException("event from unknown ConversationPanel: " + contactName);
        }
        switch (buttonName) {
            case ConversationPanel.SEND_COMMAND:
                // here we yank the message data from the ConversationPanel and 
                // send it to the application to be sent
                String msgText = cp.getMsgToSend();
                String peer = cp.getContactName();
                long sentTime = XchatSocket.sendToPeer(peer, msgText);
                if (sentTime > 0) {
                    messageSent(peer, sentTime, msgText);
//                  System.out.println("UIController.java: sent to " + peer +
//                                     ": " + msgText);
                }
                break;
            case ConversationPanel.EXCHANGE_KEYS_COMMAND:
                // here we yank the message data from the ConversationPanel and 
                // send it to the application
                String contact = cp.getContactName();
                System.out.println("UIController.java: exchange " + contact);
                break;
            case ConversationPanel.CLOSE_COMMAND:
                myTabbedPane.removeTab(contactName);
                myTabbedPane.setSelected(UI.CONTACTS_PANEL_ID);
                break;
            case ConversationPanel.CONTACTS_COMMAND:
                System.out.println("UIController.java: contacts");
                myTabbedPane.setSelected(UI.CONTACTS_PANEL_ID);

        }
    }

    // called from the event disp thread, so can do what we want with the UI
    // in this method
    private void processReceivedMessage(Message msg) {
        if (!clientData.contactExists(msg.from)) {
            // maybe should throw Exception here, in production code 
            System.out.println("got message from unknown contact " + msg.from);
            return;
        }
        Conversation conv = clientData.getConversation(msg.from);
        conv.add(msg);
        // see if there is a tab open for this conversation
        ConversationPanel cp = (ConversationPanel) myTabbedPane.getTabContent(msg.from);
        if (cp != null) {
            // add the message to it
            cp.addMsg(formatMessage(msg, maxLineLength), msg.to.equals(Message.SELF), msg.broadcast);
            // if the tab is currently selected, then mark message as read
            String selectedName = myTabbedPane.getSelectedID();
            if (selectedName.equals(msg.from)) {
                msg.setRead();
            }
        }
        // finally, update the contacts panel 
        // (new messages or time of last msg for this contact)
        updateContactsPanel(msg.from, clientData.isBroadcast(msg.from));
        updateConversationPanels();
    }

    private void updateConversationPanels() {
        Iterator<String> it = clientData.getContactIterator();
        String contact;
        ConversationPanel panel;
        while (it.hasNext()) {
            contact = it.next();
            panel = getConversationPanel(contact);
            if (panel == null) {
                // panel is not open
                continue;
            }
            updateConversationPanel(contact, panel);
        }
    }

    private void updateConversationPanel(String contact,
            ConversationPanel panel) {
        String line1 = " conversation with " + contact;
        if (clientData.isBroadcast(contact)) {
            int pos = contact.indexOf("@");
            if (pos > 0) {   // put spaces around @ so will wrap lines
                String id = contact.substring(0, pos);
                String security = contact.substring(pos + 1);
                contact = id + " @ " + security;
            }
            line1 = "broadcast from " + contact;
        }
        int m = clientData.getNumContactsWithNewMsgs();
        String line2;
        if (m == 0) {
            line2 = " no unread messages";
        }
        else {
            line2 = " unread messages from " + m + " contact";
            if (m != 1) {
                line2 = line2 + "s";
            }
        }
        panel.setTopLabelText(line1, line2);
    }

    // convert a message to text form for display on conversation panel
    // add a line at top for the date/time, and enforce a max line length
    private String formatMessage(Message msg, int maxChars) {
        String[] lines = msg.text.split("\n");
        ArrayList<String> list = new ArrayList<>();
        for (String line : lines) {
            if (line.length() <= maxChars) {
                list.add(line);
            }
            else {
                list.addAll(splitUpLine(line, maxChars));
            }
        }
        Date date = new Date();
        date.setTime(msg.sentTime);
        String timeText = formatter.format(date);
        StringBuilder sb = new StringBuilder(timeText);
        for (String line : list) {
            sb.append("\n");
            sb.append(line);
        }
        return (sb.toString());
    }

    // chop a line up into pieces <= max length
    private ArrayList<String> splitUpLine(String oldLine, int maxChars) {
        ArrayList<String> lines = new ArrayList<>();
        String[] darkSpace = oldLine.split("\\s+");
        int i = 0;
        String next;
        StringBuilder sb = new StringBuilder();
        while (i < darkSpace.length) {
            // if next String fits on this line, then add it and continue
            next = darkSpace[i];
            if ((sb.length() + 1 + next.length()) <= maxChars) {
                if (sb.length() > 0) {
                    sb.append(" ");
                }
                sb.append(darkSpace[i]);
                i++;
                continue;
            }
            else if (next.length() <= maxChars) {
                // next String does not fit, but by itself, it's less than max
                lines.add(sb.toString());
                sb = new StringBuilder(darkSpace[i]);
                i++;
                continue;
            }
            else {
                // nextLen > maxChars
                if (sb.length() > 0) {
                    // flush anything in the buffer
                    lines.add(sb.toString());
                    sb = new StringBuilder();
                }
                lines.add(darkSpace[i].substring(0, maxChars));
                darkSpace[i] = darkSpace[i].substring(maxChars);
                continue;
            }
        }
        if (sb.length() != 0) {
            lines.add(sb.toString());
        }
        return (lines);
    }

    // called from the event disp thread, so can do what we want with the UI
    // in this method
    private void displaySentMessage(Message msg) {
        if (!clientData.contactExists(msg.to)) {
            return;
        }
        Conversation conv = clientData.getConversation(msg.to);
        conv.add(msg);
        // see if there is a tab open for this conversation
        ConversationPanel cp = (ConversationPanel) myTabbedPane.getTabContent(msg.to);
        if (cp != null) {
            // add the message to it
            cp.addMsg(formatMessage(msg, maxLineLength), msg.to.equals(Message.SELF), msg.broadcast);
            // mark the message as read, even though this is not checked at present
            msg.setRead();
        }
    }

    private void showKeyExchangeSuccess(KeyExchangePanel kep, String contactName) {
        // for debug
        // if (contactName.equals("Bob"))
        //    return;
        kep.setSuccess(contactName);
    }

    private KeyExchangePanel getKeyExchangePanel(String contactName) {
        String id = UI.KEY_EXCHANGE_PANEL_ID + "_" + contactName;
        KeyExchangePanel kep = (KeyExchangePanel) myTabbedPane.getTabContent(id);
        return (kep);
    }

    private void createKeyExchangePanel(String contactName, String[] middlePanelText, String[] bottomPanelText, boolean selectIt) {
        KeyExchangePanel keyExchangePanel = new KeyExchangePanel(contactName, new int[]{2, 6, 4});
        keyExchangePanel.setText(1, middlePanelText);
        keyExchangePanel.setText(2, bottomPanelText);
        keyExchangePanel.setListener(this);
        myTabbedPane.addTabWithCloseRight(keyExchangePanel.getCommandPrefix(),
                "key exchange", keyExchangePanel, KeyExchangePanel.CLOSE_COMMAND);
        if (selectIt) {
            myTabbedPane.setSelected(keyExchangePanel);
        }
    }

    // ---------------------------
    // ControllerInterface methods
    // ---------------------------
    @Override
    public void exit() {
        // do any housekeeping needed to close the application
        // and then exit
        System.exit(0);
    }

    @Override
    public void setFrame(ApplicationFrame frame) {
        this.frame = frame;
    }

    static void main(String... args) {
        UIController c = new UIController(null);
        String test = "abc defghi j k l m n o p q";
        ArrayList<String> list = c.splitUpLine(test, 4);
        for (String line : list) {
            System.out.println(line);
        }
    }
}
