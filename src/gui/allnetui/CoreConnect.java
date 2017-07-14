
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
    
    UIAPI handlers = null;

    // track pending key exchanges?
//    String[] keyExchangeContacts = null;
//    String[] keyExchangeSecret1 = null;
//    String[] keyExchangeSecret2 = null;
//    int[] keyExchangehops = null;

    // design principle: this API provides access to allnet lib and xchat
    // methods needed to implement the functionality of the user interface.
    public CoreConnect(UIAPI handlers) {
        super ();   // initialize thread
        this.handlers = handlers;
        // to do: initialize socket to communicate with C code
    }

    // from lib/keys.h

    // return all the contacts, including all the groups
    public String[] contacts() { return AllNetContacts.get(); } 

    public boolean contactExists(String contact) { 
        if (contact == null)
            return false;
        for (String existingContact: contacts()) {
            if (contact.equals (existingContact)) {
                return true;
            }
        }
        return false;
    } 

    public boolean contactIsGroup(String contact) {
       if (! contactExists(contact)) {
           return false;  // false if contact does not exist
       }
       return AllNetContacts.fileExists(contact, "members");
    }

    // newly created contacts may not have the peer's key
    public boolean contactHasPeerKey(String contact) {
        AllNetContacts.keyExchangeComplete status =
            AllNetContacts.contactComplete(contact);
        return ((status ==
                     AllNetContacts.keyExchangeComplete.INCOMPLETE_WITH_KEY) ||
                (status == AllNetContacts.keyExchangeComplete.COMPLETE));
    }

// not obviously useful for now
//    // each contact may have 0, 1, or multiple keys.
//    // Groups in particular will often have multiple keys, but may have 0 or 1
//    // @return null if the contact does not exist or has no keys
//    public int[] keys(String contact) { return null; }
//    public boolean validKey(String contact, int key) { return false; }

    // @return true if was able to create the group
    public boolean createGroup(String name) {
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
        System.out.println ("renameContact not implemented yet");
        return false;
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
        return ConversationData.get(contact, max);
    }

    // ultimately from xchat/xcommon.h

    // @return sequence number
    public long sendMessage(String contact, String text) {
        return XchatSocket.sendToPeer(contact, text);
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

    // creates the contact -- 1 or 2 secrets may be specified
    //    (secret2 is null if only one secret is specified)
    // if the contact already exists, returns without doing anything
    public void initKeyExchange(String contact, String secret1,
                                String secret2, int hops) {
        XchatSocket.sendKeyRequest(contact, secret1, secret2, hops);
        System.out.println("initKeyExchange: should we save params?");
    }

    // address is an AllNet human-readable address, or ahra/AHRA
    // it has the form myString@some_set.of_wordpair
    // it must match the ahra created by the broadcaster, except
    //    it may have fewer (or no) word pairs
    public void initSubscription(String address) {
        XchatSocket.sendSubscription(address);
    }

    // from lib/trace_util.h
    // @return a trace ID
    public String initTrace(int nhops, byte[] addr, int abits,
                     boolean recordIntermediates,
                     boolean onlyMatchingAddressesOnly) {
        System.out.println("initTrace not implemented yet");
        return "foo.bar";
    }

    public void run() {
        System.out.println("AllNetConnect thread running");
    // to do: connect socket, read from socket and write to socket
    }
}
