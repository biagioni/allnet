
package allnetui;

/**
 * This class implements the AllNet API methods for the UI client by 
 * communicating with the AllNet daemon
 * 
 * @author Henry
 * @author Edoardo Biagioni, esb@hawaii.edu
 */
public class CoreConnect extends Thread implements CoreAPI {

    // from lib/packet.h
    static final int allNetMTU = 12288;
    static final int xchatSocketPort = 41244; // 0xA11C, ALLnet Chat
    static final int allnetY2kSecondsInUnix = 946720800;

    UIAPI handlers = null;
    java.net.Socket sock;
    java.io.DataInputStream sockIn;
    java.io.DataOutputStream sockOut;
    byte[] bufferedResponse = null;
    // mutex is used to serialize access to bufferedResponse and sockIn
    private final Object mutex = new Object();

    static final byte guiContacts = 1;
    static final byte guiSubscriptions = 2;
    static final byte guiContactExists = 3;
    static final byte guiContactIsGroup = 4;
    static final byte guiHasPeerKey = 5;

    static final byte guiCreateGroup = 10;
    static final byte guiMembers = 11;
    static final byte guiMembersRecursive = 12;
    static final byte guiMemberOfGroups = 13;
    static final byte guiMemberOfGroupsRecursive = 14;

    static final byte guiRenameContact = 20;
    static final byte guiDeleteContact = 21;

    static final byte guiQueryVariable = 30;
    static final byte guiSetVariable = 31;
    static final byte guiUnsetVariable = 32;

    // the variables that can be queried, set, or unset
    static final byte guiVariableVisible = 1;
    static final byte guiVariableNotify = 2;
    static final byte guiVariableSavingMessages = 3;
    static final byte guiVariableComplete = 4;  // no unsetComplete

    static final byte guiGetMessages = 40;
    static final byte guiSendMessage = 41;
    static final byte guiSendBroadcast = 42;

    static final byte guiKeyExchange = 50;
    static final byte guiSubscribe = 51;
    static final byte guiTrace = 52;

    static final byte guiBusyWait = 60;

    // callbacks from the core to the GUI, with no response
    static final byte guiCallbackMessageReceived      = 70;
    static final byte guiCallbackMessageAcked         = 71;
    static final byte guiCallbackContactCreated       = 72;
    static final byte guiCallbackSubscriptionComplete = 73;
    static final byte guiCallbackTraceResponse        = 74;

    // design principle: this API provides access to allnet lib and xchat
    // methods needed to implement the functionality of the user interface.
    public CoreConnect(UIAPI handlers) {
        super ();   // initialize thread
        this.handlers = handlers;
        try {
            this.sock = new java.net.Socket("127.0.0.1", xchatSocketPort);
            this.sockIn =
                new java.io.DataInputStream(this.sock.getInputStream());
            this.sockOut =
                new java.io.DataOutputStream(this.sock.getOutputStream());
        } catch (java.lang.Exception e) {
            System.out.println("exception " + e + " creating socket");
        }
    }

    private void callbackMessageReceived(byte[] value) {
        assert(value.length > 18);
        boolean isBroadcast = (value[1] != 0);
        long seq = SocketUtils.b64(value, 2);
        // for the time, convert to the unix epoch and seconds to milliseconds
        long time = (SocketUtils.b64(value, 10) + allnetY2kSecondsInUnix)
                  * 1000;
        String peer = SocketUtils.bString(value, 18);
        int peerEnd = 18 + peer.length() + 1;
        String message = SocketUtils.bString(value, peerEnd);
        int messageEnd = peerEnd + message.length() + 1;
        String desc = SocketUtils.bString(value, messageEnd);
        int descEnd = messageEnd + desc.length() + 1;
        assert(descEnd == value.length);
        String dm = desc + "\n" + message;
        handlers.messageReceived(peer, time, seq, message, isBroadcast);
    }

    private void callbackMessageAcked(byte[] value) {
        assert(value.length > 9);
        long ack = SocketUtils.b64(value, 1);
        String peer = SocketUtils.bString(value, 9);
        handlers.messageAcked(peer, ack);
    }

    private void callbackContactCreated(byte[] value) {
        assert(value.length > 2);
        cachedContacts = null;   // reset the cache
        String peer = SocketUtils.bString(value, 1);
        handlers.contactCreated(peer);
    }

    private void callbackSubscriptionComplete(byte[] value) {
        assert(value.length > 2);
        String sender = SocketUtils.bString(value, 1);
        handlers.subscriptionComplete(sender);
    }

    private void callbackTraceResponse(byte[] value) {
        assert(value.length >= 19);
        assert(((value.length - 19) % 27) == 0);
        boolean intermediate = (value[1] != 0);
        int numEntries = convertFromByte(value[2]);
        byte[] traceID = new byte[16];
        System.arraycopy(value, 3, traceID, 0, 16);
        int index = 19;
        long timestamp = 0;
        int hops = -1;
        byte[] address = new byte[8];
        int nbits = -1;
        for (int i = 0; i < numEntries; i++) {
            int precision = convertFromByte(value[index    ]);
            nbits         = convertFromByte(value[index + 1]);
            hops          = convertFromByte(value[index + 2]);
            long seconds  = SocketUtils.b64(value, index + 3);
            long fraction = SocketUtils.b64(value, index + 3 + 8);
            System.arraycopy(value, index + 3 + 8 + 8, address, 0, 8);
            long millis = 0;
            if (precision > 64) {  // decimal precision
                millis = fraction * 100;  // correct if precision is 65
                while (precision > 65) {
                    millis = millis / 10;
                    precision --;
                }
            } else {  // ignore the precision
                millis = fraction / 18446744073709551L;
                if (millis < 0) {
                    millis = millis + 1000;
                }
            }
            final long y2kSecondsInUnix = 946720800;
            timestamp = ((seconds + y2kSecondsInUnix) * 1000) + millis;
            index += 27;
        }
        if (numEntries > 0) {
            handlers.traceReceived(traceID, timestamp, hops, address, nbits);
        } else {
            System.out.println ("error: trace response with " +
                                numEntries + " entries");
        }
    }

    // send callbacks to the right place
    // if it is not a callback, returns false
    private boolean dispatch(byte[] value) {
        switch(value[0]) {
        case guiCallbackMessageReceived:
            callbackMessageReceived(value);
            return true;
        case guiCallbackMessageAcked:
            callbackMessageAcked(value);
            return true;
        case guiCallbackContactCreated:
            callbackContactCreated(value);
            return true;
        case guiCallbackSubscriptionComplete:
            callbackSubscriptionComplete(value);
            return true;
        case guiCallbackTraceResponse:
            callbackTraceResponse(value);
            return true;
        default:
            return false;
        }
    }

    // send-and received and the synchronization codea are inspired by:
    // https://stackoverflow.com/questions/1176135/java-socket-send-receive-byte-array and
    // http://docs.oracle.com/javase/tutorial/essential/concurrency/syncrgb.html

    // send and receive are synchronized separately for multiple reasons:
    // 1. it's OK to send while receiving, there is no conflict
    // 2. if the CoreConnect thread is stuck on receiving, we want it
    //    to complete the receive and save the buffer

    // synchronized, so nobody else gets to send on the same socket
    // until we are done
    private synchronized void sendRPC(byte[] arg) {
        try {
            this.sockOut.writeLong(arg.length);
            this.sockOut.write(arg);
        } catch (java.lang.Exception e) {
            System.out.println("exception " + e + " writing to socket");
            System.exit(0);
        }
    }

    // synchronized by the caller
    private byte[] receiveBuffer() {
        if (this.bufferedResponse != null) {
            byte[] result = this.bufferedResponse;
            this.bufferedResponse = null;
            return result;
        }
        try {
            long length = this.sockIn.readLong();
            if (length > 0) {
                    byte[] result = new byte[(int)length];
                    this.sockIn.readFully(result, 0, result.length);
                    return result;
            }
        } catch (java.io.EOFException e) {
            System.out.println("exception " + e + " reading from socket");
            System.exit(1);  // the socket is closed
        } catch (java.lang.Exception e) {
            System.out.println("exception " + e + " reading from socket");
        }
        return null;
    }

    // synchronized by the caller
    private boolean saveBuffer(byte[] buffer) {
        if (this.bufferedResponse == null) {
            this.bufferedResponse = buffer;
            return true;
        } else {
            System.out.println("saveBuffer discarding " + buffer.length +
                               "-byte buffer with code " + buffer[0]);
        }
        return false;
    }

    // code is 0 to loop forever, just dispatching and/or saving the buffer
    // multiple threads may call this at the same time, only one of them
    // at a time should proceed through the synchronized block
    private byte[] receiveRPC(byte code) {
        while(true) {  // repeat until we get our match
            boolean sleep = false;
            synchronized (this.mutex) {
                byte[] result = receiveBuffer();
                if (result != null) {
System.out.println ("receiveRPC (" + code + ") got " + result.length + " bytes, code " + result[0]);
                    if ((code != 0) && (result[0] == code))   // rpc complete
                        return result;
                    if (! dispatch(result)) { // not a dispatch, save buffer
                        saveBuffer(result);
                        sleep = true;
                    }
                }
            }
            if (sleep) {
                try {  // let somebody else run
                    Thread.sleep(100);
                } catch (Exception e) {} // ignore InterruptedException
            }
        }
    }

    private byte[] doRPC(byte[] arg) {
        sendRPC(arg);
        byte[] result = receiveRPC(arg[0]);
        return result;
    }

    // from lib/keys.h

    // to refill the cache when something changes, just set it back to null
    java.util.ArrayList<String> cachedContacts = null;

    // return all the contacts, including all the groups
    public String[] contacts() {
        String[] result = null;
        if (cachedContacts == null) {
            byte[] request = new byte[1];
            request[0] = guiContacts;
            byte[] response = doRPC(request);
            long count = SocketUtils.b64(response, 1); 
            result = SocketUtils.bStringArray(response, 9, count);
            cachedContacts = new java.util.ArrayList<String>();
            for (String contact: result) {
                cachedContacts.add(contact);
            }
        } else {
           result = cachedContacts.toArray(new String[0]);
        }
        return result;
    } 

    // return all the senders we subscribe to
    public String[] subscriptions() {
        byte[] request = new byte[1];
        request[0] = guiSubscriptions;
        byte[] response = doRPC(request);
        long count = SocketUtils.b64(response, 1); 
        String[] result = SocketUtils.bStringArray(response, 9, count);
        return result;
    } 

    public boolean contactExists(String contact) { 
        boolean result = false;
        if (contact != null) {
            if (cachedContacts != null) {
                result = cachedContacts.contains(contact); 
            } else {
                for (String existingContact: contacts()) {
                    if (contact.equals (existingContact)) {
                        result = true;
                    }
                }
            }
        }
        return result;
    } 

    public boolean contactIsGroup(String contact) {
        if (! contactExists(contact)) {
            return false;  // false if contact does not exist
        }
        byte[] request = new byte[1 + contact.length() + 1];
        request[0] = guiContactIsGroup;
        SocketUtils.wString(request, 1, contact); 
        byte[] response = doRPC(request);
        return (response [1] != 0);
    }

    // newly created contacts may not have the peer's key
    public boolean contactHasPeerKey(String contact) {
        if (! contactExists(contact)) {
            return false;  // false if contact does not exist
        }
        byte[] request = new byte[1 + contact.length() + 1];
        request[0] = guiHasPeerKey;
        SocketUtils.wString(request, 1, contact); 
        byte[] response = doRPC(request);
        return (response [1] != 0);
    }

// not obviously useful for now
//    // each contact may have 0, 1, or multiple keys.
//    // Groups in particular will often have multiple keys, but may have 0 or 1
//    // @return null if the contact does not exist or has no keys
//    public int[] keys(String contact) { return null; }
//    public boolean validKey(String contact, int key) { return false; }

    // @return true if was able to create the group
    public boolean createGroup(String name) {
        cachedContacts = null;   // reset the cache
        System.out.println ("createGroup not implemented yet");
        return false;
    }
    // @return the members of this group, null if group does not exist
    public String[] members(String group) {
        System.out.println ("members not implemented yet");
        return null;
    }
    // @return the members of this group and recursively any subgroups
    //         in other words, all contacts returned are
    //         individual contacts, not groups
    public String[] membersRecursive(String group) {
        System.out.println ("membersRecursive not implemented yet");
        return null;
    }
    // @return the groups of which this contact is a member
    public String[] memberOfGroups(String contact) {
        System.out.println ("memberOfGroups not implemented yet");
        return null;
    }
    public String[] memberOfGroupsRecursive(String contact) {
        System.out.println ("memberOfGroupsRecursive not implemented yet");
        return null;
    }

    // @return true if was able to rename the contact
    public boolean renameContact(String oldName, String newName) {
        cachedContacts = null;   // reset the cache
        byte[] request = new byte[1 + oldName.length() + newName.length() + 2];
        request[0] = guiRenameContact;
        SocketUtils.wString(request, 1, oldName); 
        SocketUtils.wString(request, 1 + oldName.length() + 1, newName); 
        byte[] response = doRPC(request);
        return (response [1] != 0);
    }

    // @return true if the contact existed, and now no longer does
    public boolean deleteEntireContact(String contact) {
        cachedContacts = null;   // reset the cache
        byte[] request = new byte[1 + contact.length() + 1];
        request[0] = guiDeleteContact;
        SocketUtils.wString(request, 1, contact); 
        byte[] response = doRPC(request);
System.out.println ("deleting contact " + contact + " gave " + response[1]);
        return (response [1] != 0);
    }

    public boolean isVisible(String contact) {
        return ! AllNetContacts.isHiddenContact(contact);
    }
    public void setVisible(String contact) {
        AllNetContacts.unhideContact(contact);
    }
    public void unsetVisible(String contact) {  // make not visible
        AllNetContacts.hideContact(contact);
    }

    public boolean isNotify(String contact) {
        System.out.println("isNotify not implemented yet");
        return false;
    }
    public void setNotify(String contact) { 
        System.out.println("setNotify not implemented yet");
    }
    public void unsetNotify(String contact) { 
        System.out.println("unsetNotify not implemented yet");
    }

    public boolean isSavingMessages(String contact) { 
        System.out.println("isSavingMessages not implemented yet");
        return ! contactIsGroup(contact);  // reasonable default
    }
    public void setSavingMessages(String contact) { 
        System.out.println("setSavingMessages not implemented yet");
    }
    public void unsetSavingMessages(String contact) { 
        System.out.println("unsetSavingMessages not implemented yet");
    }

    // a key exchange is only complete once
    // (a) the user says so, or (b) we receive messages from the contact
    public boolean isComplete(String contact) {
        return (AllNetContacts.contactComplete(contact) ==
                AllNetContacts.keyExchangeComplete.COMPLETE);
    }
    public void setComplete(String contact) {
        AllNetContacts.completeExchange(contact);
    }

    // ultimately from xchat/store.h

    // @return up to the max latest saved messages to/from this contact
    //         a negative value of max requests all messages
    public Message[] getMessages(String contact, int max) {
        if (max < 0) {
            return ConversationData.getAll(contact);
        }
        return ConversationData.get(contact, max);
    }

    // ultimately from xchat/xcommon.h

    // @return sequence number
    public long sendMessage(String contact, String text) {
System.out.println("sendMessage called");
        int length = 1 + contact.length() + 1 + text.length() + 1;
        byte[] request = new byte[length];
        request[0] = guiSendMessage;
        int endContact = SocketUtils.wString (request, 1, contact);
        int endText = SocketUtils.wString (request, endContact, text);
        assert(endText == length);
        byte[] response = doRPC(request);
        long seq = SocketUtils.b64(response, 1);
        return seq;
    }

    public void sendBroadcast(String myAhra, String text) {
        System.out.println("sendBroadcast not implemented yet");
    }

    // called to take care of any background tasks (so we don't
    // have to create background threads -- caller may of course
    // use threads)
    public void busyWait() {
        System.out.println("busyWait not implemented yet");
    }

    // unsigned conversion
    private static byte convertToByte(int n) {
        byte result = 0;
        if (n > 255) {
            result = (byte)255;
        } else if (n <= 0) {
            result = 0;
        } else {
            result = (byte)n;
        }
        return result;
    }

    // unsigned conversion
    private static int convertFromByte(byte n) {
        if (n >= 0)
            return (int)n;
        return 256 + (int)n;
    }

    // creates the contact -- 1 or 2 secrets may be specified
    //    (secret2 is null if only one secret is specified)
    // if the contact already exists, returns without doing anything
    public boolean initKeyExchange(String contact, String secret1,
                                   String secret2, int hops) {
System.out.println("initKeyExchange called");
        int length = 1 + 1 + contact.length() + 1 + secret1.length() + 1;
        if ((secret2 != null) && (secret2.length() > 0))
            length += secret2.length() + 1;
        byte[] request = new byte[length];
        request[0] = guiKeyExchange;
        request[1] = convertToByte(hops);
        int endContact = SocketUtils.wString (request, 2, contact);
        int endSecret1 = SocketUtils.wString (request, endContact, secret1);
        int endSecret2 = endSecret1;
        if ((secret2 != null) && (secret2.length() > 0))
            endSecret2 = SocketUtils.wString (request, endSecret1, secret2);
        assert(endSecret2 == length);
        byte[] response = doRPC(request);
        if (response[1] == 0) {
            System.out.println("initKeyExchange returned failure");
            return false;
        }
        return true;
    }

    // address is an AllNet human-readable address, or ahra/AHRA
    // it has the form myString@some_set.of_wordpair
    // it must match the ahra created by the broadcaster, except
    //    it may have fewer (or no) word pairs
    public boolean initSubscription(String address) {
System.out.println("initSubscription called");
        int length = 1 + address.length() + 1;
        byte[] request = new byte[length];
        request[0] = guiSubscribe;
        int endAddress = SocketUtils.wString (request, 1, address);
        assert(endAddress == length);
        byte[] response = doRPC(request);
        if (response[1] == 0) {
            System.out.println("initSubscription returned failure");
            return false;
        }
        return true;
    }

    // from lib/trace_util.h
    // @return a trace ID
    public byte[] initTrace(int nhops, byte[] addr, int abits,
                            boolean recordIntermediates) {
System.out.println("initTrace called");
        int length = 1 + 1 + 1 + 1 + 8;
        byte[] request = new byte[length];
        request[0] = guiTrace;
        request[1] = convertToByte(nhops);
        request[2] = convertToByte(abits);
        if (recordIntermediates)
            request[3] = 1;
        else
            request[3] = 0;
        SocketUtils.setZeros(request, 4);
        if (addr != null)
            System.arraycopy(addr, 0, request, 4, addr.length);
        assert(12 == length);
        byte[] response = doRPC(request);
        assert(17 == response.length);
        if (SocketUtils.allZeros(response, 1)) {
            return null;
        } else {
            byte[] traceID = new byte[16];
            System.arraycopy(response, 1, traceID, 0, 16);
            return traceID;
        }
    }

    public void run() {
        // System.out.println("AllNetConnect thread running");
        for (String contact: contacts()) {
            this.handlers.contactCreated(contact);
            Message[] msgs = getMessages(contact, -1);  // get all
            this.handlers.savedMessages(msgs);
        }
        for (String sender: subscriptions()) {
            this.handlers.subscriptionComplete(sender);
        }
        this.handlers.initializationComplete();
        receiveRPC((byte)0);  // loop forever
    }
}
