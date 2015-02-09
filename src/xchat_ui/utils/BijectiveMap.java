package utils;

import java.util.HashMap;

/**
 * To map A's to B's, and vice-versa.
 * 
 * Allows null as a key or value.
 * 
 * @author Henry
 */
public class BijectiveMap<A, B> {

    private HashMap<A, B> map;
    private HashMap<B, A> inverseMap;

    public BijectiveMap() {
        map = new HashMap<>();
        inverseMap = new HashMap<>();
    }

    public void put(A a, B b) {
        // get rid of any existing maps involving these args
        remove(a);
        removeValue(b);
        // and save the new mapping
        map.put(a, b);
        inverseMap.put(b, a);
    }

    public B getValueFor(A a) {
        return (map.get(a));
    }

    public A getKeyOf(B b) {
        return (inverseMap.get(b));
    }

    public void remove(A a) {
        if (map.containsKey(a)) {
            B b = map.get(a);
            map.remove(a);
            inverseMap.remove(b);
        }
    }

    public void removeValue(B b) {
        if (inverseMap.containsKey(b)) {
            A a = inverseMap.get(b);
            inverseMap.remove(b);
            map.remove(a);
        }
    }

    public boolean containsKey(A a) {
        return (map.containsKey(a));
    }

    public boolean containsValue(B b) {
        return (inverseMap.containsKey(b));
    }

    public boolean contains(A a, B b) {
        B b1 = map.get(a);
        return (b1 == b);
    }

    public static void main(String... args) {
        BijectiveMap<String, Integer> map = new BijectiveMap<>();
        String[] s = new String[]{null, "aaa", "bbb", "hello"};
        int[] ints = new int[]{0, 2, 4, 8};
        for (int i = 0; i < s.length; i++) {
            map.put(s[i], ints[i]);
        }
        System.out.println(map.contains(null, 0));
        System.out.println(map.contains(null, 1));
        System.out.println(map.contains("c", 2));
        for (int i = 0; i < s.length; i++) {
            System.out.println(s[i] + ": " + map.getValueFor(s[i]));
        }
        for (int i = 0; i < s.length; i++) {
            System.out.println(ints[i] + ": " + map.getKeyOf(ints[i]));
        }
        map.remove(null);
        for (int i = 0; i < s.length; i++) {
            System.out.println(s[i] + ": " + map.getValueFor(s[i]));
        }
        for (int i = 0; i < s.length; i++) {
            System.out.println(ints[i] + ": " + map.getKeyOf(ints[i]));
        }
        map.removeValue(4);
        for (int i = 0; i < s.length; i++) {
            System.out.println(s[i] + ": " + map.getValueFor(s[i]));
        }
        for (int i = 0; i < s.length; i++) {
            System.out.println(ints[i] + ": " + map.getKeyOf(ints[i]));
        }
        System.out.println(map.contains("a", 0));


    }
}
