// return a list of current contacts

package allnetui;

public class AllNetContacts {

    private static java.nio.file.Path getContactsDir(String dir) {
        String home = System.getenv ("HOME");
        String profile = System.getenv ("USERPROFILE");
        if (profile != null)
            home = profile;
        java.nio.file.Path nullResult = null;
        if (home == null) {
            System.out.println ("AllNetContacts: no home directory");
            return nullResult;
        }
        String search = home + "/.allnet/" + dir + "/";
//      System.out.println ("search directory is " + search);
        java.nio.file.Path path =
            java.nio.file.FileSystems.getDefault().getPath(search);
        if (! java.nio.file.Files.isDirectory(path)) {
            System.out.println ("AllNetContacts: " + search +
                                " is not a directory");
            return nullResult;
        }
        return path;
    }

    public static String [] get() {
        java.nio.file.Path path = getContactsDir("contacts");
        String [] noResult = new String [0];
        if (path == null)
            return noResult;
        java.util.LinkedList<String> rlist = new java.util.LinkedList<String>();
        try (java.nio.file.DirectoryStream<java.nio.file.Path> stream =
                 java.nio.file.Files.newDirectoryStream (path)) {
            for (java.nio.file.Path p: stream) {
//              System.out.println ("looking at path " + p);
                if (java.nio.file.Files.isDirectory(p)) {
                    java.nio.file.Path name =
                        java.nio.file.FileSystems.
                            getDefault().getPath(p + "/name");
//                  System.out.println ("looking at file " + name);
                    java.nio.charset.Charset charset =
                        java.nio.charset.Charset.forName("UTF-8");
                    java.io.BufferedReader in =
                        java.nio.file.Files.newBufferedReader(name, charset);
                    rlist.add (in.readLine());
//                  System.out.println (in.readLine());
                }
            }
        } catch (java.io.IOException e) {
            System.out.println ("AllNetContacts.java: IO exception " + e +
                                " iterating over directory " + path +
                                ", aborting");
            return noResult;
        }
        return rlist.toArray(noResult);
    }

    public static String [] getBroadcast() {
        java.nio.file.Path path = getContactsDir("other_bc_keys");
        String [] noResult = new String [0];
        if (path == null)
            return noResult;
        java.util.LinkedList<String> rlist = new java.util.LinkedList<String>();
        try (java.nio.file.DirectoryStream<java.nio.file.Path> stream =
                 java.nio.file.Files.newDirectoryStream (path)) {
            for (java.nio.file.Path p: stream) {
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
                        rlist.add (name);
                    }
                }
            }
        } catch (java.io.IOException e) {
            System.out.println ("IO exception " + e +
                                " iterating over directory " + path +
                                ", aborting");
            return noResult;
        }
        return rlist.toArray(noResult);
    }

    private static java.nio.file.Path chatTimeFile (String contact) {
        java.nio.file.Path cpath = getContactsDir("contacts");
        try (java.nio.file.DirectoryStream<java.nio.file.Path> stream =
                 java.nio.file.Files.newDirectoryStream (cpath)) {
            for (java.nio.file.Path p: stream) {
//              System.out.println ("looking at path " + p);
                if (java.nio.file.Files.isDirectory(p)) {
                    java.nio.file.Path name =
                        java.nio.file.FileSystems.
                            getDefault().getPath(p + "/name");
//                  System.out.println ("looking at file " + name);
                    java.nio.charset.Charset charset =
                        java.nio.charset.Charset.forName("UTF-8");
                    java.io.BufferedReader in =
                        java.nio.file.Files.newBufferedReader(name, charset);
                    String contactName = in.readLine();
//                  System.out.println (contactName);
                    if (contact.equals(contactName)) {
                        String fname = p.toString().replace("contacts",
                                                            "xchat") +
                                                            "/last_read";
                        System.out.println("looking at file " + fname);
                        java.nio.file.Path result =
                          java.nio.file.FileSystems.getDefault().getPath(fname);
                        return result;
                    }
                }
            }
        } catch (java.io.IOException e) {
            System.out.println ("IO exception " + e +
                                " iterating over directory " + cpath +
                                ", aborting");
        }
        return null;
    }

    public static int numNewMessages(String contact) {
        Message [] messages = ConversationData.getUnread(contact);
        if (messages == null)
            return 0;
        return messages.length;
    }

    public static int totalNewMessages() {
        String [] contacts = get();
        String [] bc = getBroadcast();
        int count = 0;
        for (String s: contacts)
            count += numNewMessages(s);
        for (String s: bc)
            count += numNewMessages(s);
        return count;
    }

    public static int contactsWithNewMessages() {
        String [] contacts = get();
        String [] bc = getBroadcast();
        int count = 0;
        for (String s: contacts)
            if (numNewMessages(s) > 0)
                count ++;
        for (String s: bc)
            if (numNewMessages(s) > 0)
                count ++;
        return count;
    }

    private static void updateChatTime(java.nio.file.Path path) {
        String lr = path.toString().replace("contacts", "xchat") + "/last_read";
System.out.println("updating chat time for " + lr);
        try {
            java.nio.file.Path lrp =
                java.nio.file.FileSystems.getDefault().getPath(lr);
            java.nio.file.Files.deleteIfExists(lrp);
            java.nio.file.Files.createFile(lrp);
        } catch (Exception e) {
            System.out.println ("updateChatTime: exception " + e +
                                " deleting/udpating " + lr);
        }
        System.out.println ("updated time for file " + lr);
    }

    public static void messagesHaveBeenRead(String contact) {
        java.nio.file.Path cpath = getContactsDir("contacts");
        try (java.nio.file.DirectoryStream<java.nio.file.Path> stream =
                 java.nio.file.Files.newDirectoryStream (cpath)) {
            for (java.nio.file.Path p: stream) {
                if (java.nio.file.Files.isDirectory(p)) {
                    java.nio.file.Path name =
                        java.nio.file.FileSystems.
                            getDefault().getPath(p + "/name");
                    java.nio.charset.Charset charset =
                        java.nio.charset.Charset.forName("UTF-8");
                    java.io.BufferedReader in =
                        java.nio.file.Files.newBufferedReader(name, charset);
                    String contactName = in.readLine();
                    if (contact.equals(contactName)) {
                        updateChatTime(p);
                        return;
                    }
                }
            }
        } catch (java.io.IOException e) {
            System.out.println ("IO exception " + e +
                                " iterating over directory " + cpath +
                                ", aborting");
        }
    }

    public static void newUnreadMessage(String contact) {
        // this does nothing, because the message is saved in the
        // file system, and we detect that anyway.
    }

};
