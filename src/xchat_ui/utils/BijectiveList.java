package utils;

import java.util.ArrayList;
import java.util.Iterator;

/**
 * To map A's to B's, and vice-versa.
 * 
 * Null is not allowed as a key or value.
 * 
 * @author Henry
 */
public class BijectiveList<A, B> {

    private static class Pair<A, B> {

        A a;
        B b;

        Pair(A a, B b) {
            this.a = a;
            this.b = b;
        }
    }
    private ArrayList<Pair<A, B>> pairs;

    public BijectiveList() {
        pairs = new ArrayList<>();
    }

    public void put(A a, B b) {
        // get rid of any existing maps involving these args
        remove(a);
        removeValue(b);
        // and save the new mapping
        pairs.add(new Pair<>(a, b));
    }

    public B getValueFor(A a) {
        Pair<A, B> pair = findByKey(a);
        if (pair == null) {
            return (null);
        }
        else {
            return (pair.b);
        }
    }

    public A getKeyOf(B b) {
        Pair<A, B> pair = findByValue(b);
        if (pair == null) {
            return (null);
        }
        else {
            return (pair.a);
        }
    }

    public void remove(A a) {
        Pair<A, B> pair;
        Iterator<Pair<A, B>> it = pairs.iterator();
        while (it.hasNext()) {
            pair = it.next();
            if (pair.a.equals(a)) {
                it.remove();
                break;
            }
        }
    }

    public void removeValue(B b) {
        Pair<A, B> pair;
        Iterator<Pair<A, B>> it = pairs.iterator();
        while (it.hasNext()) {
            pair = it.next();
            if (pair.b.equals(b)) {
                it.remove();
                break;
            }
        }
    }

    public boolean containsKey(A a) {
        return (findByKey(a) != null);
    }

    public boolean containsValue(B b) {
        return (findByValue(b) != null);
    }

    public boolean contains(A a, B b) {
        Pair<A, B> pair = findByKey(a);
        if (pair == null) {
            return (false);
        }
        else {
            return (pair.b.equals(b));
        }
    }

    private Pair<A, B> findByKey(A a) {
        for (Pair<A, B> pair : pairs) {
            if (pair.a.equals(a)) {
                return (pair);
            }
        }
        return (null);
    }

    private Pair<A, B> findByValue(B b) {
        for (Pair<A, B> pair : pairs) {
            if (pair.b.equals(b)) {
                return (pair);
            }
        }
        return (null);
    }

    public static void main(String... args) {
        BijectiveList<String, Integer> map = new BijectiveList<>();
        String[] s = new String[]{"a", "aaa", "bbb", "hello"};
        int[] ints = new int[]{0, 2, 4, 8};
        for (int i = 0; i < s.length; i++) {
            map.put(s[i], ints[i]);
        }
        System.out.println(map.contains("a", 0));
        System.out.println(map.contains("a", 1));
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
