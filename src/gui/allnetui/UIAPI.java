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
    public void messageReceived(String from, long sentTime, long seq,
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
    public void contactCreated(final String contactName);
    public void subscriptionComplete(final String contactName);
 
    // the application should call this method to tell the UI to
    // remove a contact
    public void contactDeleted(String contactName);
    // re-read a contact
    public void contactModified(String contactName);

    // the application should call this method to tell the UI to
    // clear a conversation
    public void clearConversation(String contactName);
    
    // if a trace response is received, call this method
    public void traceReceived(byte[] traceID,
                              long timestamp, int hops,
                              byte[] address, int nbits);
    
}
