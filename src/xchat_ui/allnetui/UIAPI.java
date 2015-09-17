package allnetui;


/**
 * This interface defines the public API methods for the application to 
 * communicate with the UI client
 * 
 * @author Henry
 */
public interface UIAPI {
    
    // the application should call this method after a valid message
    // is received
    public void messageReceived(String from, long sentTime,
                                String text, boolean broadcast);
    // initialization should call this method at startup with older messages
    public void savedMessages(Message[] message);
    // the application should call this method after all messages have
    // been read from files and the UI should display the results
    public void initializationComplete();
    
    // the application should call this method after a message
    // has been successfully sent
    public void messageSent(String to, long sentTime, long seq, String text);
    // the application should call this method after a message is acked
    public void messageAcked(String to, long seq);
    
    // the application should call this method to tell the UI about
    // a new contact
    public void contactCreated(final String contactName, boolean isBroadcast);
    public void contactCreated(final String contactName);
    public void broadcastContactCreated(final String contactName);

    
    // the application should call this method to tell the UI to
    // remove a contact
    public void contactDeleted(String contactName);
    
//    // the application should call this method to update a user's key
//    public void updateKey(String contactName, String key);
    
}
