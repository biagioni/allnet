package allnetui;

/**
 * test ConversationData
 * 
 * @author esb
 */
class CDTester {

  public static void main(String[] args) {
//    System.out.println (args.length + " args");
    for (String contact: args) {
//      System.out.println ("contact " + contact);
      Message[] ten = ConversationData.get(contact, 10);
      Message[] all = ConversationData.getAll(contact);
      for (int i = 0; i < ten.length; i++)
        System.out.println("message " + i + "/10 is :" + ten [i]);
      System.out.println();
      for (int i = 0; i < all.length; i += ((all.length + 10) / 10))
        System.out.println("message " + i + "/" + all.length +
                            " is :" + all [i]);
    }
  } 

}
