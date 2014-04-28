// return a list of current contacts

package allnetui;

public class AllNetContacts {

  public static String [] get() {
    String home = System.getenv ("HOME");
    String [] result = new String [0];
    if (home == null) {
      System.out.println ("AllNetContacts: no home directory");
      return result;
    }
    String search = home + "/.allnet/contacts/";
//    System.out.println ("search directory is " + search);
    java.nio.file.Path path =
      java.nio.file.FileSystems.getDefault().getPath(search);
    if (! java.nio.file.Files.isDirectory(path)) {
      System.out.println ("AllNetContacts: " + search + " is not a directory");
      return result;
    }
    java.util.LinkedList<String> rlist = new java.util.LinkedList<String>();
    try {
      for (java.nio.file.Path p: 
           java.nio.file.Files.newDirectoryStream (path)) {
//        System.out.println ("looking at path " + p);
        if (java.nio.file.Files.isDirectory(p)) {
          java.nio.file.Path name =
            java.nio.file.FileSystems.getDefault().getPath(p + "/name");
//          System.out.println ("looking at file " + name);
          java.nio.charset.Charset charset =
            java.nio.charset.Charset.forName("UTF-8");
          java.io.BufferedReader in =
            java.nio.file.Files.newBufferedReader(name, charset);
          rlist.add (in.readLine());
//          System.out.println (in.readLine());
        }
      }
    } catch (java.io.IOException e) {
      System.out.println ("IO exception " + e +
                          " iterating over directory " + search + ", aborting");
      return result;
    }
    return rlist.toArray(result);
  }

};
