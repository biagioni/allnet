// return a list of current contacts
package allnetui;

import java.nio.file.Path;

public class AllNetContacts {

    /* in the second case, we have the key, but the peer may not */
    public enum keyExchangeComplete {

        INCOMPLETE_NO_KEY,
        INCOMPLETE_WITH_KEY,
        COMPLETE
    };

    private static java.nio.file.Path getContactsDir(String dir) {
        String home = System.getenv("HOME");
        String profile = System.getenv("USERPROFILE");
        if (profile != null) {
            home = profile;
        }
        java.nio.file.Path nullResult = null;
        if (home == null) {
            System.out.println("AllNetContacts: no home directory");
            return nullResult;
        }
        String search = home + "/.allnet/" + dir + "/";
//      System.out.println ("search directory is " + search);
        java.nio.file.Path path
            = java.nio.file.FileSystems.getDefault().getPath(search);
        if (!java.nio.file.Files.isDirectory(path)) {
            System.out.println("AllNetContacts: " + search
                + " is not a directory");
            return nullResult;
        }
        return path;
    }

    public static String[] get() {
        java.nio.file.Path path = getContactsDir("contacts");
        String[] noResult = new String[0];
        if (path == null) {
            return noResult;
        }
        java.util.LinkedList<String> rlist = new java.util.LinkedList<>();
        try (java.nio.file.DirectoryStream<java.nio.file.Path> stream
            = java.nio.file.Files.newDirectoryStream(path)) {
            for (java.nio.file.Path p : stream) {
//              System.out.println ("looking at path " + p);
                if (java.nio.file.Files.isDirectory(p)) {
                    java.nio.file.Path name = null;
                    try {
                        name = java.nio.file.FileSystems.
                            getDefault().getPath(p + "/name");
//                      System.out.println ("looking at file " + name);
                        java.nio.charset.Charset charset
                            = java.nio.charset.Charset.forName("UTF-8");
                        java.util.List<String> names
                            = java.nio.file.Files.readAllLines(name, charset);
                        for (String s : names) {
                            rlist.add(s);
                        }
//                      System.out.println (in.readLine());
                    }
                    catch (java.io.IOException e) {
                        System.out.println("AllNetContacts: IO exception "
                            + e + " not found " + name
                            + ", ignoring");
                    }
                }
            }
        }
        catch (java.io.IOException e) {
            System.out.println("AllNetContacts.java: IO exception " + e
                + " iterating over directory " + path
                + ", aborting");
            return noResult;
        }
        return rlist.toArray(noResult);
    }

    public static String[] getBroadcast() {
        java.nio.file.Path path = getContactsDir("other_bc_keys");
        String[] noResult = new String[0];
        if (path == null) {
            return noResult;
        }
        java.util.LinkedList<String> rlist = new java.util.LinkedList<>();
        try (java.nio.file.DirectoryStream<java.nio.file.Path> stream
            = java.nio.file.Files.newDirectoryStream(path)) {
            for (java.nio.file.Path p : stream) {
//              System.out.println ("looking at path " + p);
                if (java.nio.file.Files.isRegularFile(p)) {
                    // java.nio.file.Path name = p.getName(p.getNameCount() - 1).toString();
                    String name = p.getName(p.getNameCount() - 1).toString();
//                  System.out.println ("looking at path " + p + ", file " + name);
                    int pos = name.indexOf("@");
                    if (pos > 0) {
//                      String id = name.substring(0, pos);
//                      String security = name.substring(pos + 1);
//                      String contact = id + " @ " + security;
//                      System.out.println ("contact name " + contact + ".");
                        rlist.add(name);
                    }
                }
            }
        }
        catch (java.io.IOException e) {
            System.out.println("AllNetContacts getBroadcast: IO exception "
                + e + " iterating over directory " + path
                + ", aborting");
            return noResult;
        }
        return rlist.toArray(noResult);
    }

    private static java.nio.file.Path chatTimeFile(String contact) {
        java.nio.file.Path cpath = getContactsDir("contacts");
        try (java.nio.file.DirectoryStream<java.nio.file.Path> stream
            = java.nio.file.Files.newDirectoryStream(cpath)) {
            for (java.nio.file.Path p : stream) {
//              System.out.println ("looking at path " + p);
                if (java.nio.file.Files.isDirectory(p)) {
                    java.nio.file.Path name
                        = java.nio.file.FileSystems.
                        getDefault().getPath(p + "/name");
//                  System.out.println ("looking at file " + name);
                    java.nio.charset.Charset charset
                        = java.nio.charset.Charset.forName("UTF-8");
                    java.util.List<String> names
                        = java.nio.file.Files.readAllLines(name, charset);
                    if ((names.size() > 0) && (contact.equals(names.get(0)))) {
                        String fname = p.toString().replace("contacts",
                            "xchat")
                            + "/last_read";
                        System.out.println("looking at file " + fname);
                        java.nio.file.Path result
                            = java.nio.file.FileSystems.getDefault().getPath(fname);
                        return result;
                    }
                }
            }
        }
        catch (java.io.IOException e) {
            System.out.println("AllNetContacts chatTimeFile: IO exception "
                + e + " iterating over directory " + cpath
                + ", aborting");
        }
        return null;
    }

    public static int numNewMessages(String contact) {
        Message[] messages = ConversationData.getUnread(contact);
        if (messages == null) {
            return 0;
        }
        return messages.length;
    }

    public static int totalNewMessages() {
        String[] contacts = get();
        String[] bc = getBroadcast();
        int count = 0;
        for (String s : contacts) {
            count += numNewMessages(s);
        }
        for (String s : bc) {
            count += numNewMessages(s);
        }
        return count;
    }

    public static int contactsWithNewMessages() {
        String[] contacts = get();
        String[] bc = getBroadcast();
        int count = 0;
        for (String s : contacts) {
            if (numNewMessages(s) > 0) {
                count++;
            }
        }
        for (String s : bc) {
            if (numNewMessages(s) > 0) {
                count++;
            }
        }
        return count;
    }

    private static void updateChatTime(java.nio.file.Path path) {
        String lr = path.toString().replace("contacts", "xchat") + "/last_read";
// System.out.println ("creating " + lr);
        try {
            java.nio.file.Path lrp
                = java.nio.file.FileSystems.getDefault().getPath(lr);
            try {
                java.nio.file.Files.deleteIfExists(lrp);
            }
            catch (java.nio.file.NoSuchFileException e) {
                // ignore, if it is not there, no need to delete
            }
            java.nio.file.Files.createFile(lrp);
        }
        catch (java.nio.file.NoSuchFileException e) { // no chat dir, ignore
        }
        catch (Exception e) {
            System.out.println("updateChatTime: exception " + e
                + " udpating " + lr);
        }
        // System.out.println ("updated time for file " + lr);
    }

    public static void messagesHaveBeenRead(String contact) {
//      System.out.println ("marking as read messages for " + contact);
        Path cpath = getContactsDir("contacts");
        try (java.nio.file.DirectoryStream<java.nio.file.Path> stream
            = java.nio.file.Files.newDirectoryStream(cpath)) {
            for (java.nio.file.Path p : stream) {
                if (java.nio.file.Files.isDirectory(p)) {
                    java.nio.file.Path name
                        = java.nio.file.FileSystems.
                        getDefault().getPath(p + "/name");
                    java.nio.charset.Charset charset
                        = java.nio.charset.Charset.forName("UTF-8");
                    java.util.List<String> names
                        = java.nio.file.Files.readAllLines(name, charset);
                    for (String s : names) {
                        if (contact.equals(s)) {
                            updateChatTime(p);
                            return;
                        }
                    }
                }
            }
        }
        catch (java.io.IOException e) {
            System.out.println("AllNetContacts messages: IO exception " + e
                + " iterating over directory " + cpath
                + ", aborting");
        }
    }

    // code largely copied from:
    // http://www.concretepage.com/java/jdk7/traverse-directory-structure-using-files-walkfiletree-java-nio2
    private static void deleteSubtree(final String contact, final String top,
        final java.nio.file.Path path,
        Boolean reportErrors) {
        try {
            java.nio.file.Files.walkFileTree(path,
                new java.nio.file.SimpleFileVisitor<java.nio.file.Path>() {
                    @Override
                    public java.nio.file.FileVisitResult
                    postVisitDirectory(java.nio.file.Path dir,
                        java.io.IOException e)
                    throws java.io.IOException {
                        if (e == null) {
                            System.out.println("deleting dir " + dir);
                            java.nio.file.Files.delete(dir);
                            return java.nio.file.FileVisitResult.CONTINUE;
                        }
                        else {
                            System.out.println("Exception while iterating directory.");
                            throw e;
                        }
                    }

                    @Override
                    public java.nio.file.FileVisitResult
                    visitFile(java.nio.file.Path file,
                        java.nio.file.attribute.BasicFileAttributes attrs)
                    throws java.io.IOException {
                        System.out.println("deleting " + file);
                        java.nio.file.Files.delete(file);
                        return java.nio.file.FileVisitResult.CONTINUE;
                    }
                });
            // System.out.println("Directory Structure Deleted.");
        }
        catch (java.io.IOException e) { // ignore
            if (reportErrors) {
                System.out.println("exception " + e + " deleting subtree");
            }
        }
    }

    private static java.nio.file.Path findCpath(String contact) {
        java.nio.file.Path top_path = getContactsDir("contacts");
        try (java.nio.file.DirectoryStream<java.nio.file.Path> stream
            = java.nio.file.Files.newDirectoryStream(top_path)) {
            for (java.nio.file.Path p : stream) {
                if (java.nio.file.Files.isDirectory(p)) {
                    java.nio.file.Path name
                        = java.nio.file.FileSystems.
                        getDefault().getPath(p + "/name");
                    java.nio.charset.Charset charset
                        = java.nio.charset.Charset.forName("UTF-8");
                    java.util.List<String> names
                        = java.nio.file.Files.readAllLines(name, charset);
                    for (String s : names) {
                        if (contact.equals(s)) {
                            return p;
                        }
                    }
                }
            }
        }
        catch (java.io.IOException e) {
            System.out.println("AllNetContacts messages: IO exception " + e
                + " finding path for contact " + contact
                + ", top path is " + top_path);
        }
        return null;
    }

    public static void clearConversation(String contact) {
System.out.println("clear conversation not implemented yet");
    }

    public static void deleteEntireContact(String contact) {
        java.nio.file.Path path = findCpath(contact);
        if (path == null) {
            return;
        }
        deleteSubtree(contact, "contacts", path, true);
        String xdir = path.toString().replace("contacts", "xchat");
        try {
            java.nio.file.Path xpath
                = java.nio.file.FileSystems.getDefault().getPath(xdir);
            if (xpath != null) {
                deleteSubtree(contact, "xchat", xpath, false);
            }
        }
        catch (java.lang.Exception e) { // silent, after done debugging
            System.out.println("AllNetContacts delete xchat exception " + e
                + ", contact " + contact
                + ", top path is " + path);
        }
    }

    public static void newUnreadMessage(String contact) {
        // this does nothing, because the message is saved in the
        // file system, and we detect that anyway.
    }

    private enum fileActions {

        EXISTS, // return non-null iff exists
        GET, // returns file contents if exists
        CREATE, // creates file, returns null
        DELETE
    };  // delete file if exists

    private static String fileAction(String contact, String fname,
        fileActions action) {
        String result = null;
        java.nio.file.Path cpath = getContactsDir("contacts");
        try (java.nio.file.DirectoryStream<java.nio.file.Path> stream
            = java.nio.file.Files.newDirectoryStream(cpath)) {
            for (java.nio.file.Path p : stream) {
                if (java.nio.file.Files.isDirectory(p)) {
                    java.nio.file.Path name
                        = java.nio.file.FileSystems.
                        getDefault().getPath(p + "/name");
                    java.nio.charset.Charset charset
                        = java.nio.charset.Charset.forName("UTF-8");
                    java.util.List<String> names
                        = java.nio.file.Files.readAllLines(name, charset);
                    for (String s : names) {
                        if (contact.equals(s)) {
                            java.nio.file.Path theFile
                                = java.nio.file.FileSystems.
                                getDefault().getPath(p + "/" + fname);
                            switch (action) {
                                case EXISTS:
                                    if (java.nio.file.Files.exists(theFile)) {
                                        return "exists";
                                    }
                                    break;
                                case GET:
                                    try {
                                        return new String(
                                            java.nio.file.Files.readAllBytes(theFile));
                                    }
                                    catch (java.nio.file.NoSuchFileException e) {
                                        return null;  // fail gracefully
                                    }
                                case CREATE:
                                    try {
                                        byte[] empty = new byte[0];
                                        java.nio.file.Files.write(theFile, empty,
                                            java.nio.file.StandardOpenOption.CREATE);
                                    }
                                    catch (java.lang.Exception e) {
                                        return null;  // fail gracefully
                                    }
                                    break;
                                case DELETE:
                                    java.nio.file.Files.deleteIfExists(theFile);
                                    break;
                            }
                        }
                    }
                }
            }
        }
        catch (java.io.IOException e) {
            System.out.println("AllNetContacts " + action + " ("
                + fname + "): IO exception " + e
                + " iterating over directory " + cpath
                + ", aborting");
        }
        return result;
    }

    private static void deleteFileIfAny(String contact, String fname) {
        fileAction(contact, fname, fileActions.DELETE);
    }

    private static void createEmptyFile(String contact, String fname) {
        fileAction(contact, fname, fileActions.CREATE);
    }

    private static boolean fileExists(String contact, String fname) {
        return (fileAction(contact, fname, fileActions.EXISTS) != null);
    }

    private static String fileContents(String contact, String fname) {
        return fileAction(contact, fname, fileActions.GET);
    }

    // delete the hidden file, if any
    public static void unhideContact(String contact) {
        deleteFileIfAny(contact, "hidden");
    }

    public static void hideContact(String contact) {
        createEmptyFile(contact, "hidden");
    }

    public static boolean isHiddenContact(String contact) {
        return fileExists(contact, "hidden");
    }

    // delete the exchange and hidden files, if any
    // but only if the exchange is really complete,
    // otherwise don't delete, and force the user to click the "cancel"
    // button (which deletes the entire contact) next time we restart
    public static void completeExchange(String contact) {
        if (fileExists(contact, "contact_pubkey")) {
            deleteFileIfAny(contact, "hidden");
            deleteFileIfAny(contact, "exchange");
        }
    }

    public static keyExchangeComplete contactComplete(String contactName) {
        if (!fileExists(contactName, "contact_pubkey")) {
            return keyExchangeComplete.INCOMPLETE_NO_KEY;
        }
        else if (fileExists(contactName, "exchange")) {
            return keyExchangeComplete.INCOMPLETE_WITH_KEY;
        }
        else {
            return keyExchangeComplete.COMPLETE;
        }
    }

    public static String contactExchangeFile(String contactName) {
        return fileContents(contactName, "exchange");
    }

    private static String[] splitExchangeFile(String contactName) {
        String contents = fileContents(contactName, "exchange");
        if (contents == null) {
            return null;
        }
        return contents.split("\n");
    }

    // return 0 if no exchange file, else 1 or (typically) 6 for hop count
    public static int exchangeHopCount(String contactName) {
        String[] contents = splitExchangeFile(contactName);
        if ((contents == null) || (contents.length < 1)) {
            return 0;
        }
        try {
            return Integer.parseInt(contents[0]);
        }
        catch (java.lang.NumberFormatException e) {
            return 0;
        }
    }

    // return null if no exchange file or no first secret
    public static String firstSecret(String contactName) {
        String[] contents = splitExchangeFile(contactName);
        if ((contents == null) || (contents.length < 2)) {
            return null;
        }
        return contents[1];
    }

    // return null if no exchange file or no second secret
    public static String secondSecret(String contactName) {
        String[] contents = splitExchangeFile(contactName);
        if ((contents == null) || (contents.length < 3)) {
            return null;
        }
        return contents[2];
    }

};
