
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
    static public final int allnetY2kSecondsInUnix = 946684800;

    UIAPI handlers = null;
    java.net.Socket sock;
    java.io.DataInputStream sockIn;
    java.io.DataOutputStream sockOut;
    byte[] bufferedResponse = null;
    // mutex is used to serialize access to bufferedResponse and sockIn
    private final Object mutex = new Object();
    // only deliver callbacks after all contacts have been loaded
    private boolean readyForCallbacks = false;
    private java.util.LinkedList<byte []>
	pendingCallbacks = new java.util.LinkedList<byte []>();
    private java.util.Set<ContactSequence>
	allContactSeq = new java.util.HashSet<ContactSequence>();

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
    static final byte guiClearConversation = 22;

    static final byte guiQueryVariable = 30;
    static final byte guiSetVariable = 31;
    static final byte guiUnsetVariable = 32;

    // the variables that can be queried, set, or unset
    static final byte guiVariableVisible = 1;
    static final byte guiVariableNotify = 2;
    static final byte guiVariableSavingMessages = 3;
    static final byte guiVariableComplete = 4;  // no unsetComplete
    static final byte guiVariableReadTime = 5;  // only setReadTime
    static final byte guiVariableHopCount = 6;  // only query
    static final byte guiVariableSecret = 7;    // only query

    static final byte guiGetMessages = 40;
    static final byte guiSendMessage = 41;
    static final byte guiSendBroadcast = 42;

    static final byte guiKeyExchange = 50;
    static final byte guiSubscribe = 51;
    static final byte guiTrace = 52;

    static final byte guiBusyWait = 60;

    // callbacks from the core to the GUI, with no response
    static final byte guiCallbackMessageReceived      = 70;
    static final byte guiCallbackMessageAcked	 = 71;
    static final byte guiCallbackContactCreated       = 72;
    static final byte guiCallbackSubscriptionComplete = 73;
    static final byte guiCallbackTraceResponse	= 74;

    // to refill these caches when something changes, just set them to null
    java.util.Collection<String> cachedContacts = null;
    java.util.Map<String, Boolean> cachedVisibleContacts = null;
    java.util.Map<String, Boolean> cachedNotifyContacts = null;
    java.util.Map<String, Boolean> cachedSaveContacts = null;
    java.util.Map<String, Boolean> cachedIsGroup = null;

    private void clearCaches() {
	cachedContacts = null;
	cachedVisibleContacts = null;
	cachedNotifyContacts = null;
	cachedSaveContacts = null;
	cachedIsGroup = null;
    }

    // subscriptions are separate from contacts, no need to put them together
    java.util.Collection<String> cachedSubscriptions = null;

    // list of incomplete contacts, so we don't always have to check back
    java.util.Collection<String> incompletes = new java.util.HashSet<String>();

    // design principle: this API provides access to allnet lib and xchat
    // methods needed to implement the functionality of the user interface.
    public CoreConnect(UIAPI handlers) {
	super ();   // initialize thread
	this.handlers = handlers;
	this.incompletes = new java.util.HashSet<String>();
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

    // calls SocketUtils.bString, but never returns null
    private static String stringFromBytes(byte[] data, int start) {
	String result = SocketUtils.bString(data, start);
	if (result == null)
	    result = new String("");
	return result;
    }

    private void callbackMessageReceived(byte[] value) {
	assert(value.length > 32);
	boolean isBroadcast = (value[1] != 0);
	long seq = SocketUtils.b64(value, 2);
	// for the time, convert to the unix epoch and seconds to milliseconds
	long time = (SocketUtils.b64(value, 10) + allnetY2kSecondsInUnix)
		  * 1000;
	long prevMissing = SocketUtils.b64(value, 18);
	String peer = stringFromBytes(value, 26);
	int peerEnd = 26 + peer.length() + 1;
	String message = stringFromBytes(value, peerEnd);
	int messageEnd = peerEnd + message.length() + 1;
	String desc = stringFromBytes(value, messageEnd);
	int descEnd = messageEnd + desc.length() + 1;
	assert(descEnd == value.length);
	String dm = ((desc.length() > 0) ? (desc + "\n" + message) : message);
	if (allContactSeq.contains(new ContactSequence(peer, seq))) {
	    System.out.println ("pending message for " + peer + ", seq" + seq +
				" was also in the messages we got");
	    return;
	}
	if (incompletes.contains(peer)) {   // complete the exchange
	    setComplete(peer);
	    setVisible(peer);
	}
	handlers.messageReceived(peer, time, seq, message, isBroadcast,
				 prevMissing);
    }

    private void callbackMessageAcked(byte[] value) {
	assert(value.length > 9);
	long ack = SocketUtils.b64(value, 1);
	String peer = stringFromBytes(value, 9);
	handlers.messageAcked(peer, ack);
    }

    private void callbackContactCreated(byte[] value) {
	assert(value.length > 2);
	clearCaches();
	String peer = stringFromBytes(value, 1);
	handlers.contactCreated(peer);
    }

    private void callbackSubscriptionComplete(byte[] value) {
	assert(value.length > 2);
	cachedSubscriptions = null;   // reset the cache
	String sender = stringFromBytes(value, 1);
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
	    nbits	 = convertFromByte(value[index + 1]);
	    hops	  = convertFromByte(value[index + 2]);
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
	    timestamp = ((seconds + allnetY2kSecondsInUnix) * 1000) + millis;
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
	    if (readyForCallbacks) {
		callbackMessageReceived(value);
	    } else {
		pendingCallbacks.add(value);
	    }
	    return true;
	case guiCallbackMessageAcked:
	    if (readyForCallbacks) {
		callbackMessageAcked(value);
	    } else {
		pendingCallbacks.add(value);
	    }
	    return true;
	case guiCallbackContactCreated:
	    if (readyForCallbacks) {
		callbackContactCreated(value);
	    } else {
		pendingCallbacks.add(value);
	    }
	    return true;
	case guiCallbackSubscriptionComplete:
	    if (readyForCallbacks) {
		callbackSubscriptionComplete(value);
	    } else {
		pendingCallbacks.add(value);
	    }
	    return true;
	case guiCallbackTraceResponse:
	    if (readyForCallbacks) {
		callbackTraceResponse(value);
	    } else {
		pendingCallbacks.add(value);
	    }
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
//	  System.out.println("exception " + e + " reading from socket");
	    System.exit(1);  // the socket is closed
	} catch (java.lang.Exception e) {
	    System.out.println("exception " + e + " reading from socket");
	    e.printStackTrace();
	    System.exit(1);
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
		    // System.out.println ("receiveRPC (" + code + ") got " + result.length + " bytes, code " + result[0]);
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
		    Thread.sleep(1);
		} catch (Exception e) {} // ignore InterruptedException
	    }
	}
    }

    private synchronized byte[] doRPC(byte[] arg) {
	sendRPC(arg);
	byte[] result = receiveRPC(arg[0]);
	return result;
    }

    // from lib/keys.h

    // return all the contacts, including all the groups
    public String[] contacts() {
	String[] result = null;
	if (cachedContacts == null) {
	    byte[] request = new byte[1];
	    request[0] = guiContacts;
	    byte[] response = doRPC(request);
	    long count = SocketUtils.b64(response, 1); 
	    result = SocketUtils.bStringArray(response, 9 + (int)count, count);
	    cachedContacts = new java.util.HashSet<String>();
	    for (String contact: result) {
		cachedContacts.add(contact);
	    }
	    cachedVisibleContacts = new java.util.HashMap<String, Boolean>();
	    cachedNotifyContacts = new java.util.HashMap<String, Boolean>();
	    cachedSaveContacts = new java.util.HashMap<String, Boolean>();
	    cachedIsGroup = new java.util.HashMap<String, Boolean>();
	    for (int i = 0; i < count; i++) {
	      byte b = response [i + 9];
	      cachedVisibleContacts.put(result[i], (b & 1) != 0);
	      cachedNotifyContacts.put(result[i], (b & 2) != 0);
	      cachedSaveContacts.put(result[i], (b & 4) != 0);
	      cachedIsGroup.put(result[i], (b & 8) != 0);
	    }
	} else {
	   result = cachedContacts.toArray(new String[0]);
	}
	return result;
    } 

    // return all the senders we subscribe to
    public String[] subscriptions() {
	String[] result = null;
	if (cachedSubscriptions == null) {
	    byte[] request = new byte[1];
	    request[0] = guiSubscriptions;
	    byte[] response = doRPC(request);
	    long count = SocketUtils.b64(response, 1); 
	    result = SocketUtils.bStringArray(response, 9, count);
	    cachedSubscriptions = new java.util.HashSet<String>();
	    for (String sub: result) {
		cachedSubscriptions.add(sub);
	    }
	} else {
	   result = cachedSubscriptions.toArray(new String[0]);
	}
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

    public boolean subscriptionExists(String sub) { 
	boolean result = false;
	if (sub != null) {
	    if (cachedSubscriptions != null) {
		result = cachedSubscriptions.contains(sub); 
	    } else {
		for (String existingSub: subscriptions()) {
		    if (sub.equals (existingSub)) {
			result = true;
		    }
		}
	    }
	}
	return result;
    } 

    // shall we bother to do an RPC on this name?
    private boolean isValid(String name) { 
	return(contactExists(name) || subscriptionExists(name));
    }

    private byte[] doRPCWithCode(byte code, String contact) {
	byte[] request = new byte[1 + SocketUtils.numBytes(contact) + 1];
	request[0] = code;
	SocketUtils.wString(request, 1, contact); 
	return doRPC(request);
    }

    private boolean doRPCWithCodeNonZero(byte code, String contact) {
	if (! isValid(contact)) {
	    return false;
	}
	byte[] response = doRPCWithCode (code, contact);
	return (response [1] != 0);
    }

    private byte[] doRPCWithCodeOp(byte code, byte op, String contact) {
	byte[] request = new byte[1 + 1 + SocketUtils.numBytes(contact) + 1];
	request[0] = code;
	request[1] = op;
	SocketUtils.wString(request, 2, contact); 
	return doRPC(request);
    }

    private boolean doRPCWithCodeOpNonZero(byte code, byte op, String contact) {
	if (! isValid(contact)) {
	    return false;
	}
	byte[] response = doRPCWithCodeOp (code, op, contact);
	return (response [1] != 0);
    }

    public boolean contactIsGroup(String contact) {
	if (cachedIsGroup != null) {
	    Boolean v = cachedIsGroup.get(contact);
	    if (v != null)
		return v;
	} else {
	    cachedIsGroup = new java.util.HashMap<String, Boolean>();
	}
	boolean v = doRPCWithCodeNonZero (guiContactIsGroup, contact);
	cachedIsGroup.put (contact, v);
	return v;
    }

    // newly created contacts may not have the peer's key
    public boolean contactHasPeerKey(String contact) {
	return doRPCWithCodeNonZero (guiHasPeerKey, contact);
    }

// not obviously useful for now
//    // each contact may have 0, 1, or multiple keys.
//    // Groups in particular will often have multiple keys, but may have 0 or 1
//    // @return null if the contact does not exist or has no keys
//    public int[] keys(String contact) { return null; }
//    public boolean validKey(String contact, int key) { return false; }

    // @return true if was able to create the group
    public boolean createGroup(String name) {
	byte[] result = doRPCWithCode(guiCreateGroup, name);
	clearCaches();
	boolean r = (result[1] != 0);
	System.out.println ("createGroup => " + (r ? "true" : "false"));
	return r;
    }

    // @return the members of this group, null if group does not exist
    // @todo if used, add same caching as memberOfGroupsRecursive
    public String[] members(String group) {
	if (! contactIsGroup(group))
	    return null;
	byte[] result = doRPCWithCode(guiMembers, group);
	long count = SocketUtils.b64(result, 1); 
	String[] mem = SocketUtils.bStringArray(result, 9, count);
System.out.print("members of " + group + " are");
for (String s: mem) System.out.print(", " + s); System.out.println("");
	return mem;
    }

    private String membersRecursiveCachedGroup = null;
    private String[] membersRecursiveCachedMembers = null;
    // @return the members of this group and recursively any subgroups
    //	 in other words, all contacts returned are
    //	 individual contacts, not groups
    public String[] membersRecursive(String group) {
	if (! contactIsGroup(group))
	    return null;
	if ((membersRecursiveCachedGroup == null) ||
	    (! membersRecursiveCachedGroup.equals(group))) {
	    byte[] result = doRPCWithCode(guiMembersRecursive, group);
	    long count = SocketUtils.b64(result, 1); 
	    String[] mem = SocketUtils.bStringArray(result, 9, count);
	    membersRecursiveCachedGroup = group;
	    membersRecursiveCachedMembers = mem;
	}
	return membersRecursiveCachedMembers;
    }

    // @return the groups of which this contact is a member
    // @todo if used, add same caching as memberOfGroupsRecursive
    public String[] memberOfGroups(String contact) {
	byte[] result = doRPCWithCode(guiMemberOfGroups, contact);
	long count = SocketUtils.b64(result, 1); 
	String[] groups = SocketUtils.bStringArray(result, 9, count);
	System.out.println ("memberOfGroups not implemented yet");
	return groups;
    }

    private String memberOfGroupsRecursiveCachedContact = null;
    private String[] memberOfGroupsRecursiveCachedGroups = null;
    public String[] memberOfGroupsRecursive(String contact) {
	if ((memberOfGroupsRecursiveCachedContact == null) ||
	    (! memberOfGroupsRecursiveCachedContact.equals(contact))) {
	    byte[] result = doRPCWithCode(guiMemberOfGroupsRecursive, contact);
	    long count = SocketUtils.b64(result, 1); 
	    String[] groups = SocketUtils.bStringArray(result, 9, count);
	    memberOfGroupsRecursiveCachedContact = contact;
	    memberOfGroupsRecursiveCachedGroups = groups;
	}
	return memberOfGroupsRecursiveCachedGroups;
    }

    // @return true if was able to rename the contact
    public boolean renameContact(String oldName, String newName) {
	clearCaches();
	byte[] request = new byte[1 + 1 + SocketUtils.numBytes(oldName) +
				  SocketUtils.numBytes(newName) + 2];
	request[0] = guiRenameContact;
	int index = SocketUtils.wString(request, 1, oldName); 
	SocketUtils.wString(request, index, newName); 
	byte[] response = doRPC(request);
	return (response [1] != 0);
    }

    // @return true if the contact existed, and now its conversation is empty
    public boolean clearConversation(String contact) {
	return doRPCWithCodeNonZero (guiClearConversation, contact);
    }

    // @return true if the contact existed, and now no longer does
    public boolean deleteEntireContact(String contact) {
	if (isVisible(contact)) {
	    System.out.println("cannot delete a contact that is still visible");
	    System.out.println("deleting " + contact + " failed");
	    return false;
	}
	clearCaches();
	return doRPCWithCodeNonZero (guiDeleteContact, contact);
    }

    private boolean cacheValue (java.util.Map<String, Boolean> cache,
				byte var, String contact) {
	boolean v = doRPCWithCodeOpNonZero (guiQueryVariable, var, contact);
	cache.put (contact, v);
	return v;
    }

    public boolean isVisible(String contact) {
	if (cachedVisibleContacts != null) {
	    Boolean v = cachedVisibleContacts.get(contact);
	    if (v != null)
		return v;
	} else {
	    cachedVisibleContacts = new java.util.HashMap<String, Boolean>();
	}
	return cacheValue(cachedVisibleContacts, guiVariableVisible, contact);
    }
    public void setVisible(String contact) {
	byte [] response = doRPCWithCodeOp (guiSetVariable, guiVariableVisible,
					    contact);
	clearCaches();
    }
    public void unsetVisible(String contact) {  // make not visible
	byte [] response = doRPCWithCodeOp (guiUnsetVariable,
					    guiVariableVisible, contact);
	clearCaches();
    }

    public boolean isNotify(String contact) {
	if (cachedNotifyContacts != null) {
	    Boolean v = cachedNotifyContacts.get(contact);
	    if (v != null)
		return v;
	} else {
	    cachedNotifyContacts = new java.util.HashMap<String, Boolean>();
	}
	return cacheValue(cachedNotifyContacts, guiVariableNotify, contact);
    }
    public void setNotify(String contact) { 
	byte [] response = doRPCWithCodeOp (guiSetVariable, guiVariableNotify,
					    contact);
	clearCaches();
    }
    public void unsetNotify(String contact) { 
	byte [] response = doRPCWithCodeOp (guiUnsetVariable, guiVariableNotify,
					    contact);
	clearCaches();
    }

    public boolean isSavingMessages(String contact) { 
	if (cachedSaveContacts != null) {
	    Boolean v = cachedSaveContacts.get(contact);
	    if (v != null)
		return v;
	} else {
	    cachedSaveContacts = new java.util.HashMap<String, Boolean>();
	}
	return cacheValue(cachedSaveContacts,
			  guiVariableSavingMessages, contact);
    }
    public void setSavingMessages(String contact) { 
	byte [] response = doRPCWithCodeOp (guiSetVariable,
					    guiVariableSavingMessages, contact);
	clearCaches();
    }
    public void unsetSavingMessages(String contact) { 
	byte [] response = doRPCWithCodeOp (guiUnsetVariable,
					    guiVariableSavingMessages, contact);
	clearCaches();
    }

    // a key exchange is only complete once
    // (a) the user says so, or (b) we receive messages from the contact
    public boolean isComplete(String contact) {
	return doRPCWithCodeOpNonZero (guiQueryVariable,
				       guiVariableComplete, contact);
    }

    public void setComplete(String contact) {
	byte[] response = doRPCWithCodeOp (guiSetVariable,
					   guiVariableComplete, contact);
	if (response [1] == 0) {
//	    System.out.println ("failed to make " + contact + " complete");
	} else {
	    while (incompletes.remove (contact))
		;
	}
    }

    public int incompleteHopCount(String contact) {
	byte[] response = doRPCWithCodeOp (guiQueryVariable,
					   guiVariableHopCount, contact);
	if (response [1] <= 0)
	    return -1;
	return response[1];
    }

    public String incompleteSecret(String contact) {
	byte[] response = doRPCWithCodeOp (guiQueryVariable,
					   guiVariableSecret, contact);
	if (response [1] <= 0)
	    return null;
	return stringFromBytes(response, 2);
    }

    // ultimately from xchat/store.h

    // @return up to the max latest saved messages to/from this contact
    //	 a negative value of max requests all messages
    public Message[] getMessages(String contact, int max) {
	Message[] result = null;
	if (! isValid(contact))
	    return result;
	if (max == 0)
	    return result;
	if (max < 0)
	    max = 0;  /* in gui_get_messages, 0 means all */
	byte[] request = new byte[9 + SocketUtils.numBytes(contact) + 1];
	request[0] = guiGetMessages;
	SocketUtils.w64(request, 1, max); 
	SocketUtils.wString(request, 9, contact); 
	byte[] response = doRPC(request);
	long count = SocketUtils.b64(response, 1); 
	result = SocketUtils.bMessages(response, 9, count, contact, false);
	return result;
    }

    // set that the contact was read now
    public void setReadTime(String contact) {
	if (isValid(contact)) {
	    doRPCWithCodeOp (guiSetVariable, guiVariableReadTime, contact);
	    // ignore the response from the doRPC
	}
    }

    // ultimately from xchat/xcommon.h

    // @return sequence number
    public long sendMessage(String contact, String text) {
	int length = 1 + SocketUtils.numBytes(contact) + 1 +
		     SocketUtils.numBytes(text) + 1;
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
    // returns an array of the normalized secret(s), or [] for failure
    public String[] initKeyExchange(String contact, String secret1,
				    String secret2, int hops) {
	int length = 1 + 1 + SocketUtils.numBytes(contact) + 1 +
		     SocketUtils.numBytes(secret1) + 1;
	if ((secret2 != null) && (secret2.length() > 0))
	    length += SocketUtils.numBytes(secret2) + 1;
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
	incompletes.add(contact);
	clearCaches();
	if (response[1] == 0) {
	    System.out.println("initKeyExchange returned failure");
	    return new String[0];
	}
	String [] result = SocketUtils.bStringArray (response, 2, 2);
	return result;
    }

    // address is an AllNet human-readable address, or ahra/AHRA
    // it has the form myString@some_set.of_wordpair
    // it must match the ahra created by the broadcaster, except
    //    it may have fewer (or no) word pairs
    public boolean initSubscription(String address) {
	int length = 1 + SocketUtils.numBytes(address) + 1;
	byte[] request = new byte[length];
	request[0] = guiSubscribe;
	int endAddress = SocketUtils.wString (request, 1, address);
	assert(endAddress == length);
	byte[] response = doRPC(request);
	cachedSubscriptions = null;   // reset the cache
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

    private class ContactSequence {
	String contact = null;
	long seq = -1;
	public ContactSequence(String c, long s) {
	    contact = c;
	    seq = s;
	}
	@Override
	public boolean equals(Object o) {
	    try {
		ContactSequence cs = (ContactSequence) o;
	    	return (contact.equals(cs.contact) && (seq == cs.seq));
	    } catch (Exception e) {  // null pointer or class mismatch
		System.out.println ("equals " + this + " == " + o +
				    " threw exception " + e);
		return false;
	    }
	}
	@Override
	public String toString() {
	    return "cs: " + contact + "/" + seq;
	}
	@Override
	public int hashCode() {
	    return contact.hashCode() + (int)(seq % Integer.MAX_VALUE);
	}
    }

    public void run() {
	// System.out.println("AllNetConnect thread running");
	for (String contact: contacts()) {
	    this.handlers.contactCreated(contact);
	}
	for (String contact: contacts()) {
	    if (! contactIsGroup(contact)) {
		Message[] msgs = getMessages(contact, -1);  // get all
		this.handlers.savedMessages(msgs);
		for (Message m: msgs) {
		    if (m.received) {
			ContactSequence cs =
			    new ContactSequence(m.from, m.sequence);
		    	if (! allContactSeq.add(cs)) {
// System.out.println ("for contact " + m.from + ", duplicate " + m.sequence);
			}
		    }
		}
	    }
	}
	// System.out.println("AllNetConnect thread got saved messages, contact/seq are " + allContactSeq);
	for (String sender: subscriptions()) {
	    this.handlers.subscriptionComplete(sender);
	}
	this.handlers.initializationComplete();
	if (! readyForCallbacks) {
	    // System.out.println("AllNetConnect thread ready for " + pendingCallbacks.size() + " callbacks");
	    readyForCallbacks = true;
	    for (byte [] c: pendingCallbacks) {
		dispatch (c);
	    }
	    pendingCallbacks.clear(); // recycle the space
	    allContactSeq.clear();    // recycle the space
	} else {
	    System.out.println ("CoreConnect.run error: ready for callbacks");
	    // throw some exception?
	}
	receiveRPC((byte)0);  // loop forever
    }
}
