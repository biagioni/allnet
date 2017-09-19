package allnetui;

/**
 * Implement the CoreAPI in a dummy class for use in debug mode
 *
 * @author Henry
 * @author Edoardo Biagioni, esb@hawaii.edu
 */
public class CoreDebug implements CoreAPI {

    public CoreDebug() {
    }

    // design principle: this API provides access to allnet lib and xchat
    // methods needed to implement the functionality of the user interface.
    // from lib/packet.h
    // static final int allNetMTU = 12288;
    // from lib/keys.h
    // return all the contacts, including all the groups
    public String[] contacts() {
        return (new String[0]);
    }

    public String[] subscriptions() {
        return (new String[0]);
    }

    public boolean contactExists(String contact) {
        return (true);
    }

    public boolean contactIsGroup(String contact) {
        return (false);
    }

    public boolean contactHasPeerKey(String contact) {
        return (false);
    }

    public boolean createGroup(String name) {
        return (true);
    }

    // @return the members of this group, null if group does not exist
    public String[] members(String group) {
        return (new String[0]);
    }

    // @return the members of this group and recursively any subgroups
    //         in other words, all contacts returned are
    //         individual contacts, not groups
    public String[] membersRecursive(String group) {
        return (new String[0]);
    }

    // @return the groups of which this contact is a member
    public String[] memberOfGroups(String contact) {
        return (new String[0]);
    }

    public String[] memberOfGroupsRecursive(String contact) {
        return (new String[0]);
    }

    // @return true if was able to rename the contact
    public boolean renameContact(String oldName, String newName) {
        return (true);
    }

    public boolean isVisible(String contact) {
        return (true);
    }

    public void setVisible(String contact) {
    }

    public void unsetVisible(String contact) {
    }  // make not visible

    public boolean isNotify(String contact) {
        return (true);
    }

    public void setNotify(String contact) {
    }

    public void unsetNotify(String contact) {
    }

    public boolean isSavingMessages(String contact) {
        return (true);
    }

    public void setSavingMessages(String contact) {
    }

    public void unsetSavingMessages(String contact) {
    }

    // a key exchange is only complete once
    // (a) the user says so, or (b) we receive messages from the contact
    public boolean isComplete(String contact) {
        return (true);
    }

    public void setComplete(String contact) {
    }

    // incomplete key exchanges have a hop count and a secret
    // complete key exchanges return -1 and null, respectively
    public int incompleteHopCount(String contact) {
        return (99);
    }

    public String incompleteSecret(String contact) {
        return ("incompleteSecret");
    }

    // ultimately from xchat/store.h
    // @return up to the max latest saved messages to/from this contact
    //         a negative value of max requests all messages
    public Message[] getMessages(String contact, int max) {
        return (new Message[0]);
    }

    // set that the contact was read now
    public void setReadTime(String contact) {
    }

    // combines lib/keys.h and xchat/store.h
    // @return true if the contact existed, and now its conversation is empty
    public boolean clearConversation(String contact) {
        return (true);
    }

    // @return true if the contact existed, and now no longer does
    public boolean deleteEntireContact(String contact) {
        return (true);
    }

    // ultimately from xchat/xcommon.h
    // @return sequence number
    public long sendMessage(String contact, String text) {
        return (1L);
    }

    public void sendBroadcast(String myAhra, String text) {
    }

    // called to take care of any background tasks (so we don't
    // have to create background threads -- caller may of course
    // use threads)
    public void busyWait() {
    }

    // creates the contact -- 1 or 2 secrets may be specified
    //    (secret2 is null if only one secret is specified)
    // if the contact already exists, returns without doing anything
    public boolean initKeyExchange(String contact, String secret1, String secret2,
        int hops) {
        return (true);
    }

    // address is an AllNet human-readable address, or ahra/AHRA
    // it has the form myString@some_set.of_wordpair
    // it must match the ahra created by the broadcaster, except
    //    it may have fewer (or no) word pairs
    public boolean initSubscription(String address) {
        return (true);
    }

    // from lib/trace_util.h
    // @return a trace ID
    public byte[] initTrace(int nhops, byte[] addr, int abits,
        boolean recordIntermediates) {
        return (new byte[0]);
    }
}
