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
        return getLatest(contact, true, max, false);
    }

    public static Message [] getAll(String contact)
    {
        return getLatest(contact, false, 0, false);
    }

    // gets any messages that are more recent than the last_read file
    // if there is no last_read file, same as getAll
    public static Message [] getUnread(String contact)
    {
        // Message[] debug = getLatest(contact, false, 0, true);
        return getLatest(contact, false, 0, true);
    }

    // returns all messages such that:
    // if (limit), number of messages <= max, and
    // if (unreadOnly), message time is newer than last_read time
    private static Message[] getLatest(String contact, boolean limit, int max,
                                       boolean unreadOnly)
    {
        Message[] emptyResult = new Message[0];
        java.nio.file.Path chatDir = getContactChatDir(contact);
        if (chatDir == null) {
// this can happen if users exchanged keys but have not exchanged any messages.
            return emptyResult;
        }
        java.util.Vector<java.nio.file.Path> paths =
            new java.util.Vector<java.nio.file.Path>(10000, 10000);
        // try-with-resources automatically closes dirIter at end of loop
        try (java.nio.file.DirectoryStream<java.nio.file.Path> dirIter =
                 java.nio.file.Files.newDirectoryStream(chatDir, "????????")) {
                      // only match files with YYYYMMDD
            for (java.nio.file.Path p: dirIter)
                paths.add(p);
        } catch (java.io.IOException e) {
            System.out.println ("ConversationData.java: IO exception x " + e +
                                  " iterating over directory " + chatDir +
                                  ", aborting search for contact " + contact);
            return emptyResult;
        }
        try (java.nio.file.DirectoryStream<java.nio.file.Path> dirIter =
                 java.nio.file.Files.newDirectoryStream(chatDir,
                                                        "????????.txt")) {
                      // only match files with YYYYMMDD.txt
            for (java.nio.file.Path p: dirIter)
                paths.add(p);  // ignore .txt
        } catch (java.io.IOException e) {
            System.out.println ("ConversationData.java: IO exception " + e +
                                  " iterating over directory " + chatDir +
                                  ", aborting search for contact " + contact);
            return emptyResult;
        }
        java.util.Collections.sort(paths);
        java.nio.file.attribute.FileTime lastRead = getContactLastRead(contact);
        if (unreadOnly && (lastRead != null)) {
            String oldestPath = getFileTimeDate(lastRead);
            java.util.Iterator<java.nio.file.Path> pit = paths.iterator();
            while (pit.hasNext()) {
                java.nio.file.Path p = pit.next();
                String name = p.toString(); 
                if ((name.length() == 12) &&
                    (name.substring(8, 12).equals(".txt")))
                    name = name.substring(0, 8);
                if ((name.length() != 8) || (name.compareTo(oldestPath) < 0))
                    pit.remove();
            }
        }
        java.util.ListIterator<java.nio.file.Path> pathIter =
            paths.listIterator(paths.size());

        // specify a large capacityIncrement in case we do get past the initial
        // capacity
        java.util.Vector<Message> messages =
            new java.util.Vector<Message>(200, 10000);
        java.util.Vector<String> acks =
            new java.util.Vector<String>(200, 10000);
        while(pathIter.hasPrevious()) {
            java.nio.file.Path p = pathIter.previous();
            Message[] fileContents = readMessages(contact, p, acks,
                                                  unreadOnly, lastRead);
            int maxCopy = fileContents.length;
            if ((limit) && (maxCopy > (max - messages.size()))) {
                maxCopy = max - messages.size();
                if (maxCopy <= 0)   // finished, no point in reading more files
                  break;
            }
            for (int i = 0; i < maxCopy; i++)
                for (String s: acks)
                    fileContents[fileContents.length - i - 1].setAcked(s);
            for (int i = 0; i < maxCopy; i++) {
                Message newMessage = fileContents[fileContents.length - i - 1];
                if ((! unreadOnly) || (newMessage.isNewMessage()))
                    messages.add(newMessage);
            }
            if ((limit) && (messages.size() >= max))
                break;
        }
        java.util.Collections.sort(messages);
        Message[] result = new Message[0]; // needed to correctly set the type
        return messages.toArray(result);
    }

    private static java.nio.file.Path getContactChatDir(String contact)
    {
        String home = System.getenv ("HOME");
        String profile = System.getenv ("USERPROFILE");
        if (profile != null)
            home = profile;
        if (home == null) {
            System.out.println ("ConversationData: no home directory");
            return null;
        }
        String search = home + "/.allnet/contacts/";
        java.nio.file.Path path =
            java.nio.file.FileSystems.getDefault().getPath(search);
        if (! java.nio.file.Files.isDirectory(path)) {
            System.out.println ("ConversationData: " + search +
                                  " is not a directory");
            return null;
        }
        java.nio.file.Path result = null;
        java.io.BufferedReader inFile = null;
        // try-with-resources automatically closes dirIter at end of loop
        try (java.nio.file.DirectoryStream<java.nio.file.Path> dirIter =
                   java.nio.file.Files.newDirectoryStream(path,
                                                          "??????????????")) {
                      // only match files with YYYYMMDDhhmmss
            for (java.nio.file.Path p: dirIter) {
                if (java.nio.file.Files.isDirectory(p)) {
                  java.nio.file.Path name =
                    java.nio.file.FileSystems.getDefault().getPath(p + "/name");
                  java.nio.charset.Charset charset =
                    java.nio.charset.Charset.forName("UTF-8");
                  inFile = java.nio.file.Files.newBufferedReader(name, charset);
                  String candidate = inFile.readLine();
                  inFile.close();
                  inFile = null;
                  int newLinePos = ((candidate == null) ? -1 :
                                    candidate.indexOf("\n"));
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
                          contactsPathName.substring(contactsPos +
                                                     replace.length());
                        result =
                          java.nio.file.FileSystems.getDefault().
                            getPath(xchatPathName);
                      if (java.nio.file.Files.isDirectory(result)) {
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
                                " iterating over directory " + search +
                                " for contact " + contact + ", aborting");
            if (inFile != null)
                try { inFile.close(); } catch (java.io.IOException c) { }
            return null;
        }
        return result;
    }

    private static java.nio.file.attribute.FileTime 
        getContactLastRead(String contact)
    {
        try {
            java.nio.file.Path p = getContactChatDir(contact);
            if (p == null)
                return null;
            java.nio.file.Path last_read =
              java.nio.file.FileSystems.getDefault().getPath(p + "/last_read");
            if (last_read == null)
                return null;
            java.nio.file.attribute.FileTime mod =
                (java.nio.file.attribute.FileTime)
                    java.nio.file.Files.getAttribute(last_read,
                                                     "lastModifiedTime");
            return mod;
        } catch(java.nio.file.NoSuchFileException e) {
            return null;   // file not found, ignore
        } catch(Exception e) {
            System.out.println ("exception " + e + " in getContactLastRead");
            return null;
        }
    }

    private static String
        getFileTimeDate(java.nio.file.attribute.FileTime lastRead)
    {
        // YYYY-MM-DDThh:mm:ss[.s+]Z
        // 0123456789
        String yymmddetc = lastRead.toString();
        String result = yymmddetc.substring(0,4) + 
                        yymmddetc.substring(5,7) + 
                        yymmddetc.substring(8,10);
        // System.out.println ("getFileTimeDate(" + lastRead + " = " + result);
        return result;
    }

    private static Message[] readMessages(String contact,
                                          java.nio.file.Path path,
                                          java.util.Vector<String> acks,
                                          boolean unreadOnly,
                                          java.nio.file.attribute.FileTime lr)
    {
        // java.io.BufferedReader inFile = null;
        java.nio.charset.Charset charset =
            java.nio.charset.Charset.forName("UTF-8");
        java.util.Vector<Message> messages =
            new java.util.Vector<Message>(10000, 10000);
        try (java.io.BufferedReader inFile =
             java.nio.file.Files.newBufferedReader(path, charset)) {
        // try {
            long fileSize = java.nio.file.Files.size(path);
            int maxLine = ((fileSize > Integer.MAX_VALUE) ? Integer.MAX_VALUE :
                             ((int) fileSize));
            Message newMessage = readMessage(contact, inFile, acks, maxLine,
                                             unreadOnly, lr, path.toString());
            while (newMessage != null) {
                messages.add(newMessage);
                newMessage = readMessage(contact, inFile, acks, maxLine,
                                         unreadOnly, lr, path.toString());
            }
            inFile.close();
            // inFile = null;
            Message[] result = new Message[0];    // needed to set the type
            return messages.toArray(result);
        } catch (java.io.IOException e) {
            return new Message[0];
        }
    }

    private static String myReadLine(java.io.BufferedReader in)
    {
       String result = "";
       int c;
       try {
           while ((c = in.read()) >= 0) {
// next is ridiculous code required by Java's attempt to harmonize
// unicode and UTF-16
               char[] cs = new char[2];
               Character.toChars (c, cs, 0);
               if (cs [0] == '\n')
                   return result;
               result = result + cs[0];
           }
       } catch (java.io.IOException e) {   // reached EOF, text is good
System.out.println ("myReadLine exception " + e + ", already read " + result);
       }
       if (result.length() <= 0)
           return null;
       return result;
    }

    // returns null if unable to read a message
    private static Message readMessage(String contact,
                                       java.io.BufferedReader in,
                                       java.util.Vector<String> acks,
                                       int maxLine,
                                       boolean unreadOnly,
                                       java.nio.file.attribute.FileTime lr,
                                       String fname)  // fname for debugging
    {
        String firstLine = "no first line read yet";
        String secondLine = "no second line read yet";
        try {
            firstLine = in.readLine();
            // firstLine = myReadLine(in);
            if ((firstLine == null) || (firstLine.length() < 10))
                return null;
            String start = firstLine.substring(0, 8);
            if (start.equals("got ack:")) {  
                acks.add(firstLine.substring(9));
                return readMessage(contact, in, acks, maxLine,
                                   unreadOnly, lr, fname);
            }   // there should be three or more lines for either sent or rcvd
            String messageId = firstLine.substring(9);
            boolean sentMessage = start.equals ("sent id:");
            secondLine = in.readLine();
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
                System.out.println ("no valid seq number in " + secondLine);
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
                time = Long.parseLong(timeStr.substring(0, timeEnd))
                     + y2kSecondsInUnix;
            } catch (java.lang.NumberFormatException e) {
                System.out.println ("no valid time in " + timeStr +
                                    "/" + secondLine);
                return null;
            }
            long rcvdTime = time;
            int rcvdTimePos = secondLine.indexOf ("/") + 1;
            if (rcvdTimePos > 0) {
                String rcvdTimeStr = secondLine.substring(rcvdTimePos);
                rcvdTime = Long.parseLong(rcvdTimeStr) + y2kSecondsInUnix;
            }
            String text = "";
            in.mark(maxLine);  // if this is not a text line, we will reset
            try {
                String textLine = in.readLine();
                while ((textLine != null) && (textLine.length() > 0) &&
                       (textLine.charAt(0) == ' ')) {
                    // get rid of the initial blank
                    text = text + textLine.substring(1);
                    in.mark(maxLine);
                    textLine = in.readLine();
                }
                // found a line that is not a text line
                in.reset();
            } catch (java.io.IOException e) {   // reached EOF, text is good
            }
            long lastReadSecond = 0;
            if (lr != null)
                lastReadSecond = lr.to(java.util.concurrent.TimeUnit.SECONDS);
            boolean isUnread = ((lr == null) || (lastReadSecond < rcvdTime));
            // if unreadOnly is specified, ignore sent messages and any
            // messages that have been read already (aka not unread)
            if (unreadOnly) {
                if (sentMessage || (! isUnread))
                    return readMessage(contact, in, acks, maxLine,
                                       unreadOnly, lr, fname);
            }
            if (sentMessage)
                return new Message(Message.SELF, contact, time * 1000, seq,
                                   text, messageId);
            else  // received message
                return new Message(contact, Message.SELF, time * 1000,
                                   rcvdTime * 1000, text, false, isUnread);
        } catch (java.io.IOException e) {
            System.out.println ("I/O error " + e + " on file " + fname +
                                " in ReadMessage for contact " + contact);
            System.out.println ("line 1: " + firstLine);
            System.out.println ("line 2: " + secondLine);
            return null;
        }
    }
}
