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
 * The C of MVC. Receives and processes UI and application events. The idea is
 * to put all UI logic (and sometimes application logic, when feasible) in one
 * place.
 *
 * M <=> C <=> V | Application
 *
 *
 * @author Henry
 */
class UIController implements ControllerInterface, UIAPI {

    // min lengths for shared secrets
    public final int MIN_LENGTH_SHORT = 6;
    public final int MIN_LENGTH_LONG = 14;
    // number of hops
    public final int HOPS_LOCAL = 1;
    public final int HOPS_REMOTE = 6;
    // for formatting message times
    private static SimpleDateFormat formatter
        = //          new SimpleDateFormat("yyyy/MM/dd  HH:mm:ss z");
        new SimpleDateFormat("yyyy/MM/dd  HH:mm:ss");
    //
    // reference to the swing Frame in which the ui is running 
    private ApplicationFrame frame;
    //
    // will need a references to the ui panels
    private ContactsPanel contactsPanel;
    private ContactConfigPanel contactConfigPanel;
    private NewContactPanel newContactPanel;
    private MorePanel morePanel;
    private MyTabbedPane myTabbedPane;
    private CoreAPI coreAPI;
    // need to keep client data (contacts, keys, conversations, etc.)
    private ContactData contactData;
    // keep track of the current trace, only accept responses for the same ID
    private byte[] traceID = null;

    // constructor
    UIController(ContactData contactData) {
        this.contactData = contactData;
    }

    //-----------------------------------------
    //
    //  public API methods follow
    //
    //-----------------------------------------
    // the application should call this method after a valid message is received
    @Override
    public void messageReceived(final String from, final long sentTime,
        final long seq, final String text, final boolean broadcast) {
        Runnable r = new Runnable() {
            long rcvdTime = java.util.Calendar.getInstance().getTimeInMillis();
            Message message = new Message(from, Message.SELF, sentTime,
                rcvdTime, seq, text, broadcast, true);

            @Override
            public void run() {
                // System.out.println("processing received message " + message.toString());
                processReceivedMessage(message, true);
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
                        processReceivedMessage(message, false);
                    }
                }
            }
        };
        // schedule it in the event disp thread, but don't wait for it to execute
        SwingUtilities.invokeLater(r);
    }

    // the application should call this method after all messages have
    // been read from files and the UI should display the results
    @Override
    public void initializationComplete() {
        Runnable r = new Runnable() {
            @Override
            public void run() {
                Iterator<String> it = contactData.getContactIterator();
                while (it.hasNext()) {
                    String contactName = it.next();
                    boolean bc = contactData.isBroadcast(contactName);
                    updateContactsPanel(contactName, bc);
                }
                updateConversationPanels();
            }
        };
        // schedule it in the event dispatch thread,
        // but don't wait for it to execute
        SwingUtilities.invokeLater(r);
    }

    // the application should call this method after a message has been successfully sent
    @Override
    public void messageSent(final String to, final long sentTime,
        final long seq, final String text) {
        Runnable r = new Runnable() {

            Message message = new Message(Message.SELF, to, sentTime, seq,
                text, null);

            @Override
            public void run() {
                displaySentMessage(message);
            }
        };
        // schedule it in the event disp thread, but don't wait for it to execute
        SwingUtilities.invokeLater(r);
    }

    // the application should call this method after a message is acked
    public void messageAcked(final String peer, final long seq) {
        Runnable r = new Runnable() {

            @Override
            public void run() {
                ackMessage(peer, seq);
            }
        };
        // schedule it in the event disp thread, but don't wait
        SwingUtilities.invokeLater(r);
    }

    // tell the UI about a new contact
    private void contactCreated(final String contactName,
                                final boolean isBroadcast) {
        Runnable r = new Runnable() {

            @Override
            public void run() {
                contactData.createContact(contactName,
                    isBroadcast ? ContactType.BROADCAST : ContactType.PERSONAL);
                updateContactsPanel(contactName, isBroadcast);
                contactConfigPanel.update();
                KeyExchangePanel kep = getKeyExchangePanel(contactName);
                switch (AllNetContacts.contactComplete(contactName)) {
                    case COMPLETE:
                        if (kep != null) {  /* get rid of Key Exchange panel */

                            System.out.println("kep is not null, "
                                + "please report to maintainer(s)");
                        }
                        break;
                    case INCOMPLETE_NO_KEY:
                    case INCOMPLETE_WITH_KEY:
                        if (kep == null) {
                            int hops
                                = AllNetContacts.exchangeHopCount(contactName);
                            if (hops > 0) {   // valid exchange file
                                int button = 1;   // multi-hop exchange
                                if (hops == 1) {
                                    button = 0;     // 1-hop exchange
                                }
                                String firstSecret
                                    = AllNetContacts.firstSecret(contactName);
                                String secondSecret
                                    = AllNetContacts.secondSecret(contactName);
                                // now put up a key exchange panel
                                String[] middlePanelMsg
                                    = makeMiddlePanel(firstSecret, secondSecret);
                                String[] bottomPanelMsg = new String[]{
                                    " Key exchange in progress",
                                    " Sent your key",
                                    " Waiting for key from " + contactName
                                };
                                kep = createKeyExchangePanel(contactName,
                                    middlePanelMsg, bottomPanelMsg, true, true);
                                kep.setButtonState(button);
                                kep.setSecret(firstSecret);
                                if (secondSecret == null) {
                                    secondSecret = "";
                                }
                                kep.setVariableInput(secondSecret);
                            }
                        }
                        if (AllNetContacts.contactComplete(contactName)
                            == AllNetContacts.keyExchangeComplete.INCOMPLETE_WITH_KEY) {
                            showKeyExchangeSuccess(kep, contactName);
                        }
                }
            }
        };
        // schedule it in the event disp thread, but don't wait for it to execute
        SwingUtilities.invokeLater(r);
    }

    // the application calls this method to tell the UI about a new contact
    @Override
    public void contactCreated(final String contactName) {
        contactCreated(contactName, false);
    }

    // the application calls this method to tell the UI about a new contact
    @Override
    public void subscriptionComplete(final String contactName) {
        contactCreated(contactName, true);
    }

    // the application should call this method to tell the UI to remove a contact
    @Override
    public void contactDeleted(final String contactName) {
        Runnable r = new Runnable() {

            @Override
            public void run() {
                AllNetContacts.deleteEntireContact(contactName);
                contactsPanel.removeName(contactName);
                contactData.removeContact(contactName);
                contactConfigPanel.update();
                myTabbedPane.removeTab(contactName);
            }
        };
        // schedule it in the event disp thread, but don't wait for it to execute
        SwingUtilities.invokeLater(r);
    }

    // the application should call this method to tell the UI that contact has been modified
    @Override
    public void contactModified(final String contactName) {
        Runnable r = new Runnable() {

            @Override
            public void run() {
                contactsPanel.updateButtonsPanel();
                if (!contactData.isVisible(contactName)) {
                    myTabbedPane.removeTab(contactName);
                }
            }
        };
        // schedule it in the event disp thread, but don't wait for it to execute
        SwingUtilities.invokeLater(r);
    }

    // the application should call this method to tell the UI to clear a conversation
    @Override
    public void clearConversation(final String contactName) {
        Runnable r = new Runnable() {

            @Override
            public void run() {
                AllNetContacts.clearConversation(contactName);
                contactData.clearConversation(contactName);
                updateContactsPanel(contactName, false);
                // clear it in the conversation panel
                ConversationPanel cp = (ConversationPanel) myTabbedPane.getTabContent(contactName);
                if (cp != null) {
                    cp.clearMsgs();
                }
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
//                contactData.setKey(contactName, key);
//            }
//        };
//        // schedule it in the event disp thread, but don't wait for it to execute
//        SwingUtilities.invokeLater(r);
//    }
    @Override
    // if a trace response is received, call this method
    public void traceReceived(final byte[] receivedTraceID,
                              final String traceMessageNarrow,
                              final String traceMessageWide) {
        Runnable r = new Runnable() {

            @Override
            public void run() {
                    morePanel.addTraceText(traceMessageWide);
            }
        };
        // schedule it in the event disp thread, but don't wait for it to execute
        if (SocketUtils.sameTraceID(this.traceID, receivedTraceID)) {
            SwingUtilities.invokeLater(r);
        }
    }

    //-----------------------------------------
    //
    //  end of public API methods
    //
    //-----------------------------------------
    // setters
    void setContactsPanel(ContactsPanel contactsPanel) {
        this.contactsPanel = contactsPanel;
        // add all contacts to the contacts panel
        Iterator<String> it = contactData.getContactIterator();
        while (it.hasNext()) {
            String contactName = it.next();
            boolean bc = contactData.isBroadcast(contactName);
            updateContactsPanel(contactName, bc);
        }
        contactsPanel.setActionListener(this);
    }

    public void setContactConfigPanel(ContactConfigPanel contactConfigPanel) {
        this.contactConfigPanel = contactConfigPanel;
    }

    void setNewContactPanel(NewContactPanel newContactPanel) {
        this.newContactPanel = newContactPanel;
        newContactPanel.setActionListener(this);
    }

    void setMyTabbedPane(MyTabbedPane myTabbedPane) {
        this.myTabbedPane = myTabbedPane;
    }

    void setCore(CoreAPI coreAPI) {
        this.coreAPI = coreAPI;
    }

    void setMorePanel(MorePanel morePanel) {
        this.morePanel = morePanel;
        morePanel.setActionListener(this);
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
        else if (actionCommand[0].startsWith(UI.MORE_PANEL_ID)) {
            // from the more panel
            processMorePanelEvent(actionCommand);
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
        int hops = HOPS_LOCAL;
        switch (kep.getButtonState()) {
            case 0:
            case 1:
                int min = MIN_LENGTH_SHORT;
                if (kep.getButtonState() == 1) {
                    hops = HOPS_REMOTE;
                    min = MIN_LENGTH_LONG;
                }
                String variableInput = kep.getVariableInput();
                if ((variableInput == null) || (variableInput.isEmpty())
                    || (variableInput.length() < min)) {
                    kep.setText(1, " Resend Key button pressed !!!", "",
                        " Shared secret:", " " + kep.getSecret());
                }
                else {
                    kep.setText(1, " Resend Key button pressed !!!", "",
                        " Shared secret:", " " + kep.getSecret(), " or:",
                        " " + variableInput, " ");
                }
                if (coreAPI.initKeyExchange(kep.getContactName(),
                    kep.getSecret(),
                    kep.getVariableInput(), hops)) {
                    System.out.println("resent key request");
                }
                break;
            case 2:
                String ahra = kep.getVariableInput();
                kep.setText(1, " Resent subscription request",
                    " requesting authentication for: " + ahra);
                System.out.println("resending subscription for " + ahra);
                if ((ahra != null) && (coreAPI.initSubscription(ahra))) {
                    System.out.println("sent ahra subscription");
                }
                else {
                    System.out.println("unable to resend ahra subscription");
                }
                break;
            default:
                return;
        }
    }

    private void processKeyExchangePanelEvent(String[] actionCommand) {
        String contact = getContactFromKeyExchangePanelId(actionCommand[0]);
        switch (actionCommand[1]) {
            case KeyExchangePanel.CLOSE_COMMAND:
                myTabbedPane.removeTab(actionCommand[0]);
                myTabbedPane.setSelected(UI.CONTACTS_PANEL_ID);
                AllNetContacts.completeExchange(contact);
                break;
            case KeyExchangePanel.CANCEL_COMMAND:
                myTabbedPane.removeTab(actionCommand[0]);
                myTabbedPane.setSelected(UI.CONTACTS_PANEL_ID);
                contactDeleted(contact);
                break;
            case KeyExchangePanel.RESEND_KEY_COMMAND:
                resendKey((KeyExchangePanel) myTabbedPane.getTabContent(actionCommand[0]));
                break;
        }
    }

    private void processMorePanelEvent(String[] actionCommand) {
        switch (actionCommand[1]) {
            case MorePanel.CLOSE_COMMAND:
                myTabbedPane.removeTab(actionCommand[0]);
                myTabbedPane.setSelected(UI.CONTACTS_PANEL_ID);
                break;
            case MorePanel.TRACE_COMMAND:
//              System.out.println ("trace command called");
                morePanel.setTraceText("");
                this.traceID = coreAPI.initTrace(5, null, 0, false);
                if (this.traceID != null) {
//                  System.out.println("sent trace request");
                }
                break;
        }
    }

    // update the ContactsPanel with the info related to this contact 
    private void updateContactsPanel(String contact, boolean broadcast) {
        if (contact == null) {
            return;
            // throw new RuntimeException("tried to update contacts panel for null contact name");
        }
        Conversation conv = contactData.getConversation(contact);
        if (conv == null) {
            return;   // there is no conversation, that's OK
            // throw new RuntimeException("tried to update contacts panel for invalid contact name: " + contact);
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

    // give method package access so that it can be called at startup
    void updateContactsPanelStatus() {
        int n = contactData.getNumContacts();
        int m = contactData.getNumContactsWithNewMsgs();
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
        String tabTitle = "Contacts";
        if (m > 0) {
//            tabTitle = "Contacts (" 
//                     + contactsWithNewMessages + "/" + newMessages + ")";
            tabTitle = "Contacts (" + m + "/"
                + contactData.getTotalNewMsgs() + ")";
        }
        myTabbedPane.setTitle(UI.CONTACTS_PANEL_ID, tabTitle);
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
        if (!contactData.contactExists(contactName)) {
            // not a conversation tab; no action to take
            return;
        }
        // it's a conversation tab. 
        Conversation conv = contactData.getConversation(contactName);
        if (conv == null) {
            throw new RuntimeException("no Conversation Object for contact: " + contactName);
        }
        conv.setReadAll();
        updateContactsPanel(contactName, contactData.isBroadcast(contactName));
        updateConversationPanels();
        AllNetContacts.messagesHaveBeenRead(contactName);
    }

    private void processContactsEvent(String contactName) {
        // see if there is a tab open for this conversation
        ConversationPanel cp = (ConversationPanel) myTabbedPane.getTabContent(contactName);
        if (cp == null) {
            // no such tab, so make the conversation panel
            // (the contact's name is also the command prefix)
            if (!contactData.isBroadcast(contactName)) {
                cp = new ConversationPanel(" conversation with " + contactName, contactName, contactName, true);
            }
            else {
                cp = new ConversationPanel(" broadcast from " + contactName, contactName, contactName, false);
            }
            cp.setName(contactName);
            cp.setListener(this);
            // display the conversation on the new panel
            Conversation conv = contactData.getConversation(contactName);
            // add before init with conversation, so message bubbles' size calc is right
            myTabbedPane.addTabWithClose(contactName, cp.getTitle(), cp, ConversationPanel.CLOSE_COMMAND);
            // add msg bubbles
            initializeConversation(cp, conv, true);
            // now select and make visible
            myTabbedPane.addTabWithClose(contactName, cp.getTitle(), cp, ConversationPanel.CLOSE_COMMAND);
            myTabbedPane.setSelected(cp);
        }
        else {
            // already exists, so select it
            // myTabbedPane.setSelectedIndex(i);
            myTabbedPane.setSelected(contactName);
        }
        // it's a conversation tab, so update the contacts panel
        updateContactsPanel(contactName, contactData.isBroadcast(contactName));
        // update the stats at top of all conversation panels
        updateConversationPanels();
    }

    private String[] makeMiddlePanel(String firstSecret,
        String secondSecret) {
        if (secondSecret != null) {
            return new String[]{
                " Shared secret:",
                " " + firstSecret,
                " or:",
                " " + secondSecret
            };
        }
        else {
            return new String[]{
                " Shared secret:",
                " " + firstSecret
            };
        }
    }

    private String[] makeMiddlePanel(boolean useLongSecret,
        String variableInput) {
        String secret = newContactPanel.getMySecretShort();
        int minLength = MIN_LENGTH_SHORT;
        if (useLongSecret) {
            secret = newContactPanel.getMySecretLong();
            minLength = MIN_LENGTH_LONG;
        }
        if (variableInput.length() < minLength) {
            return makeMiddlePanel(secret, null);
        }
        else {
            return makeMiddlePanel(secret, variableInput);
        }
    }

    private void processNewContactEvent(String command) {
        // here we can use newContactPanel's getter methods to grab
        // the user's input and send it to the application
        // System.out.println("UIController.java: pNCE " + command);
        KeyExchangePanel kep;
        if (command.equals("go")) {
            String contact = newContactPanel.getInputName();
            if (contact.equals("")) {
                System.out.println("UIController.java: new contact name is empty");
                return;
            }
            int button = newContactPanel.getSelectedButton();
            String variableInput = newContactPanel.getVariableInput();
            if (variableInput == null) {
                variableInput = "";
            }
            String secret;
            switch (button) {
                case -1:
                    System.out.println("UIController.java: new contact " + contact
                        + ", no button selected");
                    break;
                case 0:
                    secret = newContactPanel.getMySecretShort();
                    if (variableInput.length() < MIN_LENGTH_SHORT) {
                        variableInput = "";
                    }
                    System.out.println("new 1-hop contact " + contact + ", "
                        + ", secret " + variableInput + "/" + secret);
                    // create the key exchange panel if it doesn't already exist
                    kep = getKeyExchangePanel(contact);
                    if (kep == null) {
                        // now put up a key exchange panel
                        String[] middlePanelMsg
                            = makeMiddlePanel(false, variableInput);
                        String[] bottomPanelMsg = new String[]{
                            " Key exchange in progress",
                            " Sent your key",
                            " Waiting for key from " + contact
                        };
                        kep = createKeyExchangePanel(contact, middlePanelMsg,
                            bottomPanelMsg, true, true);
                        kep.setButtonState(button);
                        kep.setSecret(secret);
                        kep.setVariableInput(variableInput);
                    }
                    if (coreAPI.initKeyExchange(contact,
                        secret, variableInput, HOPS_LOCAL)) {
                        System.out.println("sent direct wireless key request");
                        newContactPanel.setMySecret();
                    }
                    else {
                        System.out.println("unable to send direct key request");
                    }
                    break;
                case 1:
                    secret = newContactPanel.getMySecretLong();
                    if (variableInput.length() < MIN_LENGTH_LONG) {
                        variableInput = "";
                    }
                    System.out.println("new long-distance contact " + contact
                        + ", secret " + variableInput + "/" + secret);
                    kep = getKeyExchangePanel(contact);
                    if (kep == null) {
                        // now put up a key exchange panel
                        String[] middlePanelMsg
                            = makeMiddlePanel(true, variableInput);
                        String[] bottomPanelMsg = new String[]{
                            " Key exchange in progress",
                            " Sent your key",
                            " Waiting for key from " + contact
                        };
                        kep = createKeyExchangePanel(contact, middlePanelMsg,
                            bottomPanelMsg, true, true);
                        kep.setButtonState(button);
                        kep.setSecret(secret);
                        kep.setVariableInput(variableInput);
                    }
                    //
                    if (coreAPI.initKeyExchange(contact,
                        newContactPanel.getMySecretLong(),
                        newContactPanel.getVariableInput(), HOPS_REMOTE)) {
                        System.out.println("sent key request with 6 hops");
                        newContactPanel.setMySecret();
                    }
                    else {
                        System.out.println("unable to send key request");
                    }
                    break;
                case 2:
                    String ahra = newContactPanel.getVariableInput();
                    System.out.println("new ahra contact " + contact + ", "
                        + ahra);
                    if ((ahra == null) || (ahra.indexOf('@') < 0)) {
                        ahra = contact;
                    }
                    if ((ahra == null) || (ahra.indexOf('@') < 0)) {
                        System.out.println("new ahra contact " + contact
                            + " must contain '@' sign");
                    }
                    else {
                        kep = getKeyExchangePanel(contact);
                        if (kep == null) {
                            // now put up a key exchange panel
                            String[] middlePanelMsg
                                = {"requesting authentication for: " + contact};
                            String[] bottomPanelMsg = new String[]{
                                " authentication in progress",
                                " Sent your your request",
                                " Waiting for key matching " + contact
                            };
                            kep = createKeyExchangePanel(contact,
                                middlePanelMsg,
                                bottomPanelMsg,
                                true, false);
                            kep.setButtonState(button);
                            kep.setVariableInput(ahra);
                        }
                        if (coreAPI.initSubscription(ahra)) {
                            System.out.println("sent ahra subscription");
                        }
                        else {
                            System.out.println("unable to send ahra request");
                        }
                    }
                    break;
                case 3:
                    System.out.println("create new group " + contact);
                    System.out.println("  (not implemented)");
                    break;
//                case 4:
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
            case ConversationPanel.DISPLAY_MORE_MSGS_COMMAND:
                // fetch the number to display, and increment it
                int currentNum = cp.getNumMsgsToDisplay();
                // currentNum += ConversationPanel.getDefaultNumMsgsToDisplay();
                // exponential growth gets us there faster if we want to
                // go back a large number of messages
                currentNum *= 2;
                cp.setNumMsgsToDisplay(currentNum);
                Conversation conv = contactData.getConversation(cp.getContactName());
                initializeConversation(cp, conv, false);
                break;
            case ConversationPanel.SEND_COMMAND:
                // here we yank the message data from the ConversationPanel and 
                // send it to the application to be sent
                String msgText = cp.getMsgToSend();
                if (msgText.length() <= 0) {
                    break;
                }
                String peer = cp.getContactName();
                long seq = coreAPI.sendMessage(peer, msgText);
                if (seq > 0) {
                    long sentTime = new java.util.Date().getTime();
                    messageSent(peer, sentTime, seq, msgText);
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
                break;
        }
    }

    // called from the event disp thread, so can do what we want with the UI
    // in this method
    private void processReceivedMessage(Message msg, boolean isNew) {
        String contactName = msg.from;
        if (!contactData.contactExists(contactName)) {
            // maybe should throw Exception here, in production code?
            System.out.println("got message from unknown contact "
                + contactName + " (self is " + Message.SELF + ")");
            return;
        }
        Conversation conv = contactData.getConversation(contactName);
        boolean addedAtEnd = conv.add(msg);
        // see if there is a tab open for this conversation
        ConversationPanel cp
            = (ConversationPanel) myTabbedPane.getTabContent(contactName);
        if (cp != null) {
            if (addedAtEnd) {
                if (msg.isReceivedMessage()) {
                    long lastReceived = cp.getLastReceived();
                    if ((lastReceived >= 0)
                        && (msg.sequence() > lastReceived + 1)) {
                        cp.addMissing(msg.sequence() - (lastReceived + 1));
                    }
                    cp.setLastReceived(msg.sequence());
                }
                cp.addMsg(formatMessage(msg), msg);
                cp.validateToBottom();
            }
            else {
                // out of order, so delete everything, then add everything back
                // System.out.println ("received out-of-order message");
                initializeConversation(cp, conv, true);
            }
            // if the tab is currently selected, then mark message as read
            String selectedName = myTabbedPane.getSelectedID();
            if (selectedName.equals(contactName)) {
                msg.setRead();
                AllNetContacts.messagesHaveBeenRead(contactName);
            }
        }
        // finally, update the contacts panel 
        // (new messages or time of last msg for this contact)
        if (isNew) {  // don't update during initialization
            boolean isBroadcast = contactData.isBroadcast(contactName);
            updateContactsPanel(contactName, isBroadcast);
            updateConversationPanels();
        }
    }

    private void initializeConversation(ConversationPanel cp,
        Conversation conv,
        boolean scrollToBottom) {
        cp.clearMsgs();
        ArrayList<Message> msgs = conv.getMessages();
        int numToDisplay = cp.getNumMsgsToDisplay();
        int startIdx = Math.max(0, msgs.size() - numToDisplay);
        // find earliest unread msg
        int earliest = Integer.MAX_VALUE;
        for (int i = 0; i < msgs.size(); i++) {
            if (msgs.get(i).isNewMessage()) {
                earliest = i;
                break;
            }
        }
        startIdx = Math.min(startIdx, earliest);
        long lastReceived = -1;  // needed to mark missing messages
        for (int i = startIdx; i < msgs.size(); i++) {
            Message savedMsg = msgs.get(i);
            if (savedMsg.isReceivedMessage()) {
                if ((lastReceived >= 0)
                    && (savedMsg.sequence() > lastReceived + 1)) {
                    cp.addMissing(savedMsg.sequence() - (lastReceived + 1));
                }
                lastReceived = savedMsg.sequence();
            }
            cp.addMsg(formatMessage(savedMsg), savedMsg);
        }
        cp.setLastReceived(lastReceived);
        if (scrollToBottom) {
            cp.validateToBottom();
        }
        else {
            cp.validateToTop();
        }
    }

    private void updateConversationPanels() {
        Iterator<String> it = contactData.getContactIterator();
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
        if (contactData.isBroadcast(contact)) {
            int pos = contact.indexOf("@");
            if (pos > 0) {   // put spaces around @ so will wrap lines
                String id = contact.substring(0, pos);
                String security = contact.substring(pos + 1);
                contact = id + " @ " + security;
            }
            line1 = "broadcast from " + contact;
        }
        int m = contactData.getNumContactsWithNewMsgs();
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

    // add a line at top for the date/time, clear out html tags
    private String formatMessage(Message msg) {
        Date date = new Date();
        date.setTime(msg.sentTime);
        String timeText = formatter.format(date);
        StringBuilder sb = new StringBuilder(timeText);
        sb.append("\n");
        sb.append(msg.text);
        return (SocketUtils.sanitizeForHtml(sb.toString()));
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
        if (!contactData.contactExists(msg.to)) {
            return;
        }
        Conversation conv = contactData.getConversation(msg.to);
        conv.add(msg);
        // see if there is a tab open for this conversation
        ConversationPanel cp = (ConversationPanel) myTabbedPane.getTabContent(msg.to);
        if (cp != null) {
            // add the message to it
            cp.addMsg(formatMessage(msg), msg);
            cp.validateToBottom();
            // mark the message as read, even though this is not checked at present
            msg.setRead();
        }
    }

    // called from the event disp thread, so can do what we want with the UI
    // in this method
    private void ackMessage(String peer, long seq) {
        if (!contactData.contactExists(peer)) {
            return;
        }
        Conversation conv = contactData.getConversation(peer);
        // see if there is a tab open for this conversation
        Iterator<Message> it = conv.getIterator();
        while (it.hasNext()) {
            Message msg = it.next();
            if (msg.setAcked(seq)) {  // set ack flag if this is the right seq
System.out.println("set acked for message " + msg);
                ConversationPanel cp
                    = (ConversationPanel) myTabbedPane.getTabContent(peer);
                if (cp != null) {
                    cp.ackMsg(msg);
                }
            }
        }
    }

    private void showKeyExchangeSuccess(KeyExchangePanel kep, String contactName) {
        // for debug
        // if (contactName.equals("Bob"))
        //    return;
        kep.setSuccess(contactName);
        AllNetContacts.unhideContact(contactName);  // make the contact visible
    }

    private KeyExchangePanel getKeyExchangePanel(String contactName) {
        String id = UI.KEY_EXCHANGE_PANEL_ID + "_" + contactName;
        KeyExchangePanel kep = (KeyExchangePanel) myTabbedPane.getTabContent(id);
        return (kep);
    }

    private String getContactFromKeyExchangePanelId(String panelId) {
        if (panelId.startsWith(UI.KEY_EXCHANGE_PANEL_ID)) {
            return panelId.substring(UI.KEY_EXCHANGE_PANEL_ID.length() + 1);
        }
        return null;
    }

    private KeyExchangePanel createKeyExchangePanel(
        String contactName, String[] middlePanelText,
        String[] bottomPanelText, boolean selectIt,
        boolean isKeyExchange) {
        KeyExchangePanel keyExchangePanel
            = new KeyExchangePanel(contactName, new int[]{2, 6, 4},
                isKeyExchange);
        if (middlePanelText != null) {
            keyExchangePanel.setText(1, middlePanelText);
        }
        else {
            keyExchangePanel.setText(1, new String[0]);
        }
        keyExchangePanel.setText(2, bottomPanelText);
        keyExchangePanel.setListener(this);
        myTabbedPane.addTabWithCloseRight(keyExchangePanel.getCommandPrefix(),
            "key exchange", keyExchangePanel, KeyExchangePanel.CLOSE_COMMAND);
        if (selectIt) {
            myTabbedPane.setSelected(keyExchangePanel);
        }
        return (keyExchangePanel);
    }

    // ---------------------------
    // ControllerInterface methods
    // ---------------------------
    @Override
    public void exit() {
        // do any housekeeping needed to close the application
        // and then exit
        try {   // if on windows, show the hidden console so user can close it
            Runtime.getRuntime().exec("showConsole.exe");
            // } // not needed in production code
            //  catch(IOException iOException)        {
            //  iOException.printStackTrace();
        }
        catch (Exception e) {  // ignore, especially on non-windows systems
        }
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
