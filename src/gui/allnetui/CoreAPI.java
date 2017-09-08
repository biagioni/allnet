
package allnetui;


/**
 * This interface defines the public API methods for the UI client to 
 * communicate with the AllNet daemon
 * 
 * @author Henry
 * @author Edoardo Biagioni, esb@hawaii.edu
 */
public interface CoreAPI {

    // design principle: this API provides access to allnet lib and xchat
    // methods needed to implement the functionality of the user interface.

    // from lib/packet.h
    static final int allNetMTU = 12288;

    // from lib/keys.h

    // return all the contacts, including all the groups
    String[] contacts();
    String[] subscriptions();  // contacts whose broadcast we subscribe to
    boolean contactExists(String contact);
    boolean contactIsGroup(String contact);  // false if contact does not exist
    // newly created contacts may not have the peer's key
    boolean contactHasPeerKey(String contact);

// not obviously useful
//    // each contact may have 0, 1, or multiple keys.
//    // Groups in particular will often have multiple keys, but may have 0 or 1
//    // @return null if the contact does not exist or has no keys
//    int[] keys(String contact);
//    boolean validKey(String contact, int key);

    // @return true if was able to create the group
    boolean createGroup(String name);
    // @return the members of this group, null if group does not exist
    String[] members(String group);
    // @return the members of this group and recursively any subgroups
    //         in other words, all contacts returned are
    //         individual contacts, not groups
    String[] membersRecursive(String group);
    // @return the groups of which this contact is a member
    String[] memberOfGroups(String contact);
    String[] memberOfGroupsRecursive(String contact);

    // @return true if was able to rename the contact
    boolean renameContact(String oldName, String newName);

    boolean isVisible(String contact);
    void setVisible(String contact);
    void unsetVisible(String contact);  // make not visible

    boolean isNotify(String contact);
    void setNotify(String contact);
    void unsetNotify(String contact);

    boolean isSavingMessages(String contact);
    void setSavingMessages(String contact);
    void unsetSavingMessages(String contact);

    // a key exchange is only complete once
    // (a) the user says so, or (b) we receive messages from the contact
    boolean isComplete(String contact);
    void setComplete(String contact);

    // incomplete key exchanges have a hop count and a secret
    // complete key exchanges return -1 and null, respectively
    int incompleteHopCount(String contact);
    String incompleteSecret(String contact);

    // ultimately from xchat/store.h

    // @return up to the max latest saved messages to/from this contact
    //         a negative value of max requests all messages
    Message[] getMessages(String contact, int max);

    // set that the contact was read now
    void setReadTime(String contact);

    // combines lib/keys.h and xchat/store.h

    // @return true if the contact existed, and now its conversation is empty
    boolean clearConversation(String contact);
    // @return true if the contact existed, and now no longer does
    boolean deleteEntireContact(String contact);

    // ultimately from xchat/xcommon.h

    // @return sequence number
    public long sendMessage(String contact, String text);

    public void sendBroadcast(String myAhra, String text);

    // called to take care of any background tasks (so we don't
    // have to create background threads -- caller may of course
    // use threads)
    void busyWait();

    // creates the contact -- 1 or 2 secrets may be specified
    //    (secret2 is null if only one secret is specified)
    // if the contact already exists, returns without doing anything
    boolean initKeyExchange(String contact, String secret1, String secret2,
                            int hops);

    // address is an AllNet human-readable address, or ahra/AHRA
    // it has the form myString@some_set.of_wordpair
    // it must match the ahra created by the broadcaster, except
    //    it may have fewer (or no) word pairs
    boolean initSubscription(String address);

    // from lib/trace_util.h
    // @return a trace ID
    byte[] initTrace(int nhops, byte[] addr, int abits,
                     boolean recordIntermediates);
}
