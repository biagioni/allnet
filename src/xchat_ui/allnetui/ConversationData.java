// return a list of current contacts

package allnetui;

public class ConversationData {

  // messages sent by me have from equal ""
  // received messages have to equal ""
  // the latest (or all) messages are returned, in order of latest first
  public static Message[] get(String contact, int max)
  {
    if (max <= 0)
      return new Message[0];
    return getLatest(contact, true, max);
  }

  public static Message [] getAll(String contact)
  {
    return getLatest(contact, false, 0);
  }

  // if limit is false, returns all messages.  Otherwise, returns at
  // most max messages.
  private static Message[] getLatest(String contact, boolean limit, int max)
  {
    Message[] emptyResult = new Message[0];
    java.nio.file.Path chatDir = getContactChatDir(contact);
    if (chatDir == null) {
// no need to print -- this can happen if users exchanged keys
// but have not exchanged any messages.
//    System.out.println("ConversationData.getLatest() unable to find contact "
//                       + contact);
      return emptyResult;
    }
    java.util.Vector<java.nio.file.Path> paths =
      new java.util.Vector<java.nio.file.Path>(10000, 10000);
    // try-with-resources automatically closes dirIter at the end of the loop
    try (java.nio.file.DirectoryStream<java.nio.file.Path> dirIter =
           java.nio.file.Files.newDirectoryStream(chatDir, "????????")) {
              // only match files with YYYYMMDD
      for (java.nio.file.Path p: dirIter)
        paths.add(p);
    } catch (java.io.IOException e) {
      System.out.println ("IO exception " + e +
                          " iterating over directory " + chatDir +
                          ", aborting search for contact " + contact);
      return emptyResult;
    }
    java.util.Collections.sort(paths);
    java.util.ListIterator<java.nio.file.Path> pathIter =
      paths.listIterator(paths.size());

    // specify a large capacityIncrement in case we do get past the initial
    // capacity
    java.util.Vector<Message> messages =
      new java.util.Vector<Message>(200, 10000);
    java.util.Vector<String> acks = new java.util.Vector<String>(200, 10000);
//    System.out.println ("paths has " + paths.size() + " paths");
    while(pathIter.hasPrevious()) {
      java.nio.file.Path p = pathIter.previous();
//      System.out.println ("searching path " + p);
      Message[] fileContents = readMessages(contact, p, acks);
//      System.out.println ("file has " + fileContents.length + " messages");
      int maxCopy = fileContents.length;
      if ((limit) && (maxCopy > (max - messages.size()))) {
        maxCopy = max - messages.size();
        if (maxCopy <= 0)   // finished, no point in reading more files
          break;
      }
      for (int i = 0; i < maxCopy; i++)
        for (String s: acks)
          fileContents[fileContents.length - i - 1].setAcked(s);
      for (int i = 0; i < maxCopy; i++)
        messages.add(fileContents[fileContents.length - i - 1]);
      if ((limit) && (messages.size() >= max))
        break;
    }
    java.util.Collections.sort(messages);
    Message[] result = new Message[0];    // needed to correctly set the type
    return messages.toArray(result);
  }

  private static java.nio.file.Path getContactChatDir(String contact)
  {
    String home = System.getenv ("HOME");
    if (home == null) {
      System.out.println ("ConversationData: no home directory");
      return null;
    }
    String search = home + "/.allnet/contacts/";
//    System.out.println ("search directory is " + search);
    java.nio.file.Path path =
      java.nio.file.FileSystems.getDefault().getPath(search);
    if (! java.nio.file.Files.isDirectory(path)) {
      System.out.println ("ConversationData: " + search +
                          " is not a directory");
      return null;
    }
    java.nio.file.Path result = null;
    // try-with-resources automatically closes dirIter at the end of the loop
    try (java.nio.file.DirectoryStream<java.nio.file.Path> dirIter =
           java.nio.file.Files.newDirectoryStream(path,
                                                  "??????????????")) {
              // only match files with YYYYMMDDhhmmss
      for (java.nio.file.Path p: dirIter) {
//        System.out.println ("looking at path " + p);
        if (java.nio.file.Files.isDirectory(p)) {
          java.nio.file.Path name =
            java.nio.file.FileSystems.getDefault().getPath(p + "/name");
//          System.out.println ("looking at file " + name);
          java.nio.charset.Charset charset =
            java.nio.charset.Charset.forName("UTF-8");
          java.io.BufferedReader in =
            java.nio.file.Files.newBufferedReader(name, charset);
          String candidate = in.readLine();
          int newLinePos = ((candidate == null) ? -1 : candidate.indexOf("\n"));
          if (newLinePos >= 0)
            candidate = candidate.substring(0, newLinePos);
          if (contact.equals(candidate)) {  // found!
            String contactsPathName = p.toString();
            final String replace = "contacts";
            final String with = "xchat";
            int contactsPos = contactsPathName.indexOf(replace);
            if (contactsPos >= 0) {
              String xchatPathName =
                contactsPathName.substring(0, contactsPos) + "xchat" +
                contactsPathName.substring(contactsPos + replace.length());
//              System.out.println ("replacing contacts with xchat in '" +
//                                  contactsPathName + "' gives '" +
//                                  xchatPathName + "'");
              result =
                java.nio.file.FileSystems.getDefault().getPath(xchatPathName);
              if (java.nio.file.Files.isDirectory(result)) {
//                System.out.println ("found chat directory " + result);
                break;
              }
              else  // reset result
                result = null;
            }
          }
        }
      }
    } catch (java.io.IOException e) {
      System.out.println ("ConversationData: IO exception " + e +
                          " iterating over directory " + search + ", aborting");
      return null;
    }
    return result;
  }

  private static Message[] readMessages(String contact,
                                        java.nio.file.Path path,
                                        java.util.Vector<String> acks)
  {
    try {
      java.nio.charset.Charset charset =
        java.nio.charset.Charset.forName("UTF-8");
      java.io.BufferedReader in =
        java.nio.file.Files.newBufferedReader(path, charset);
      java.util.Vector<Message> messages =
        new java.util.Vector<Message>(10000, 10000);
      long fileSize = java.nio.file.Files.size(path);
      int maxLine = ((fileSize > Integer.MAX_VALUE) ? Integer.MAX_VALUE :
                     ((int) fileSize));
      Message newMessage = readMessage(contact, in, acks, maxLine);
      while (newMessage != null) {
        messages.add(newMessage);
        newMessage = readMessage(contact, in, acks, maxLine);
      }
      Message[] result = new Message[0];    // needed to correctly set the type
      return messages.toArray(result);
    } catch (java.io.IOException e) {
      return new Message[0];
    }
  }

  // returns null if unable to read a message
  private static Message readMessage(String contact, java.io.BufferedReader in,
                                     java.util.Vector<String> acks,
                                     int maxLine)
  {
    try {
      String firstLine = in.readLine();
      if ((firstLine == null) || (firstLine.length() < 10))
        return null;
      String start = firstLine.substring(0, 8);
      if (start.equals("got ack:")) {  
        acks.add(firstLine.substring(9));
        return readMessage(contact, in, acks, maxLine);
      }   // there should be three or more lines for either sent or rcvd
      String messageId = firstLine.substring(9);
      boolean sentMessage = start.equals ("sent id:");
      String secondLine = in.readLine();
      if ((secondLine == null) || (secondLine.length() < 46))
        return null;
      final String sequence = "sequence ";
      String secondLineSeq = secondLine.substring(sequence.length());
      long seq = 0;
      int seqPos = secondLineSeq.indexOf(", ");
      if (seqPos <= 0) {
        System.out.println ("no sequence number in " + secondLine);
        return null;
      }
      try {
        seq = Long.parseLong(secondLineSeq.substring(0, seqPos));
      } catch (java.lang.NumberFormatException e) {
        System.out.println ("no valid sequence number in " + secondLine);
        return null;
      }
      int timePos = secondLine.indexOf ("(") + 1;
      if ((timePos <= 0) || (timePos + 9 > secondLine.length())) {
        System.out.println ("no time in " + secondLine);
        return null;
      }
      String timeStr = secondLine.substring(timePos);
      int timeEnd = timeStr.indexOf (" ");
      long time = 0;
      final long y2kSecondsInUnix = 946720800;
      try {
        time = Long.parseLong(timeStr.substring(0, timeEnd)) + y2kSecondsInUnix;
      } catch (java.lang.NumberFormatException e) {
        System.out.println ("no valid time in " + timeStr + "/" + secondLine);
        return null;
      }
      String text = "";
      in.mark(maxLine);  // if this is not a text line, we will reset
      try {
        String textLine = in.readLine();
        while ((textLine != null) && (textLine.length() > 0) &&
               (textLine.charAt(0) == ' ')) {
          text = text + textLine.substring(1);  // get rid of the initial blank
          in.mark(maxLine);
          textLine = in.readLine();
        }
        // found a line that is not a text line
        in.reset();
      } catch (java.io.IOException e) {   // reached end of file, text is good
      }
      if (sentMessage)
        return new Message(Message.SELF, contact, time * 1000, seq, text,
                           messageId);
      else
        return new Message(contact, Message.SELF, time * 1000, text,
                           false, false);
    } catch (java.io.IOException e) {
      System.out.println ("I/O error " + e + " in ReadMessage");
      return null;
    }
  }
};
