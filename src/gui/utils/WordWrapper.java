package utils;

import java.util.ArrayList;

/**
 * Class to do word wrapping and to correct text selected and copied from html.
 *
 * The name "WordWrapper" is meant in the sense of a class that does
 * word-wrapping, not as a wrapper around a word :-)
 *
 *
 * @author henry
 */
public class WordWrapper {

    // the original text
    private String original;
    // print errors
    private boolean verbose;
    // array of word-wrapped lines of text
    private String[] wrappedText;
    // indices into text where word-wrap has inserted linebreaks
    private ArrayList<Integer> wordBreaks;

    // complex constructor
    public WordWrapper(boolean verbose) {
        this.verbose = verbose;
    }

    public WordWrapper() {
        this(false);
    }

    // get the wrapped text as an array of lines
    public String[] getWrappedText() {
        return wrappedText;
    }

    // get a list of indices where extra line breaks were inserted
    public ArrayList<Integer> getWordBreaks() {
        return wordBreaks;
    }

    public void setVerbose(boolean verbose) {
        this.verbose = verbose;
    }

    public String getOriginal() {
        return original;
    }

    // does the word-wrap, places results in wrappedText and lineBreaks
    // prefixSpaces determines what happens when a line break is inserted
    // at a point with adjacent spaces: true places them on next line, false 
    // on the current line
    public void wordWrapText(String original, int maxChars, boolean prefixSpaces) {
        this.original = original;
        wordBreaks = new ArrayList<>();
        int idx = 0;
        // split into individual lines
        String[] temp = original.split("\n");
        ArrayList<String> list = new ArrayList<>();
        for (String line : temp) {
            if (line.length() <= maxChars) {
                list.add(line);
                idx += line.length();
                // +1 since a cr will be inserted after the line
                idx++;
            }
            else {
                ArrayList<String> splitLine = splitUpLine(line, maxChars, prefixSpaces);
                for (int i = 0; i < splitLine.size() - 1; i++) {
                    list.add(splitLine.get(i));
                    idx += splitLine.get(i).length();
                    wordBreaks.add(idx);
                    idx++;
                }
                list.add(splitLine.get(splitLine.size() - 1));
                idx += splitLine.get(splitLine.size() - 1).length();
                idx++;
            }
        }
        StringBuilder sb = new StringBuilder();
        for (String line : list) {
            sb.append(line);
            sb.append("\n");
        }
        String wordWrapped = sb.toString();
        wrappedText = wordWrapped.split("\n");
    }

    public String getCorrected(String selected, int startIdx) {
        // let's be safe here
        if ((selected == null) || selected.isEmpty()) {
            return ("");
        }
        StringBuilder temp = new StringBuilder();
        for (String w : wrappedText) {
            temp.append(w);
            temp.append("\n");
        }
        temp.deleteCharAt(temp.length() - 1);
        // wwText now mirrors what we would see if we did a selectAll on the bubble 
        String wwText = temp.toString();
        // now build the string: just omit the inserted word (line) breaks
        char nbsp = 0xa0;
        char space = 0x20;
        char cr = '\n';
        int wwIdx = startIdx;
        // "safe indexing"
        wwIdx = Math.max(wwIdx, 0);
        wwIdx = Math.min(wwIdx, wwText.length() - 1);
        int selIdx = 0;
        StringBuilder sb = new StringBuilder();
        boolean error = false;
        char sc, wwc;
        while (selIdx < selected.length()) {
            if (wwIdx >= wwText.length()) {
                error = true;
                break;
            }
            // walk through the selected text and reconstructed text
            sc = selected.charAt(selIdx);
            wwc = wwText.charAt(wwIdx);
            // all spaces in the displayed message will be nbsp's
            if ((sc == wwc) || ((sc == nbsp) && (wwc == space))) {
                sb.append(wwc);
                selIdx++;
                wwIdx++;
            }
            else if (((sc == nbsp) || (sc == space)) && (wwc == cr)
                && !wordBreaks.contains(wwIdx)) {
                // restore cr for space in selected string
                sb.append(cr);
                selIdx++;
                wwIdx++;
            }
            else if (((sc == nbsp) || (sc == space)) && wordBreaks.contains(wwIdx)) {
                // skip over inserted line (word) break
                selIdx++;
                wwIdx++;
            }
            else {
                error = true;
                // System.out.println((int)sc + "  " + (int) wwc);
                break;
            }
        }  // while
        if (error) {
            if (verbose) {
                System.out.println("error correcting selection: \"" + selected + "\"");
            }
            // just return uncorrected selection (filtered for nbsp's) if we fail for any reason
            return (selected.replaceAll(new String(new char[]{nbsp}),
                new String(new char[]{space})));
        }
        // return the constructed String
        return (sb.toString());
    }

    // chop a line up into pieces <= max length
    private ArrayList<String> splitUpLine(String oldLine, int maxChars, boolean prefixSpaces) {
        ArrayList<String> lines = new ArrayList<>();
        // String[] darkSpace = oldLine.split("\\s+");
        String[] darkSpace = smartSplit(oldLine, prefixSpaces);
        int i = 0;
        String nextWord;
        StringBuilder sb = new StringBuilder();
        while (i < darkSpace.length) {
            // line is full, then extract it
            if (sb.length() == maxChars) {
                lines.add(sb.toString());
                sb.delete(0, sb.length());
            }
            nextWord = darkSpace[i];
            // line is empty and next word fits, then add it and continue
            if ((sb.length() == 0) && (nextWord.length() <= maxChars)) {
                sb.append(darkSpace[i]);
                i++;
                continue;
            }
            // line is not empty and next word fits, then add it and continue
            else if ((sb.length() > 0)
                && (sb.length() + 1 + nextWord.length() <= maxChars)) {
                // sb.append(" ");
                sb.append(nextWord);
                i++;
                continue;
            }
            // next word fits on a line, but not into current line
            else if (nextWord.length() <= maxChars) {
                // save current line
                if (sb.length() > 0) {
                    lines.add(sb.toString());
                    sb.delete(0, sb.length());
                }
                sb.append(nextWord);
                i++;
                continue;
            }
            else {
                // next word does not fit on a line and must be broken up
                // save current line
                if (sb.length() > 0) {
                    lines.add(sb.toString());
                    sb.delete(0, sb.length());
                }
                lines.add(nextWord.substring(0, maxChars));
                darkSpace[i] = darkSpace[i].substring(maxChars);
                if (darkSpace[i].isEmpty()) {
                    i++;
                }
                continue;
            }
        }
        if (sb.length() != 0) {
            lines.add(sb.toString());
        }
        return (lines);
    }

    // method to use instead of the String.split() method
    // split the string using space as a delimiter, but place any extra spaces
    // as prefix/postfix to the words after/before
    public String[] smartSplit(String s, boolean preFixSpaces) {
        // first split into groups of spaces and non-spaces
        char space = ' ';
        ArrayList<String> groups = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        char nextChar;
        boolean isSpace, wasSpace = s.charAt(0) == space;
        for (int i = 0; i < s.length(); i++) {
            nextChar = s.charAt(i);
            isSpace = nextChar == space;
            if (isSpace == wasSpace) {
                current.append(nextChar);
            }
            else {
                groups.add(current.toString());
                current = new StringBuilder();
                current.append(nextChar);
                wasSpace = nextChar == space;
            }
        }
        groups.add(current.toString());
        if (groups.size() <= 1) {
            return (groups.toArray(new String[0]));
        }
        // now we make adjustments if the first or last group is spaces
        // if so, they pre/postpended to the adjacent (non-space) group
        String temp0, temp1;
        if (isSpaces(groups.get(0))) {
            temp0 = groups.remove(0);
            temp1 = groups.remove(0);
            groups.add(0, temp0 + temp1);
        }
        if (isSpaces(groups.get(groups.size() - 1))) {
            temp1 = groups.remove(groups.size() - 1);
            temp0 = groups.remove(groups.size() - 1);
            groups.add(groups.size(), temp0 + temp1);
        }
        // now use the groups of spaces as delimiters to make a list of words
        // but append or preppend the extra* spaces to the words
        // *we assume that a space will be inserted later as a delimiter when 
        // the text is reconstructed        
        ArrayList<String> words = new ArrayList<>();
        int startIdx;
        if (preFixSpaces) {
            startIdx = 1;
            words.add(groups.get(0));
        }
        else {
            startIdx = 0;
        }
        for (int i = startIdx; i < groups.size(); i += 2) {
            if (i + 1 < groups.size()) {
                words.add(groups.get(i) + groups.get(i + 1));
            }
            else {
                words.add(groups.get(i));
            }
        }
        return (words.toArray(new String[0]));
    }

    private boolean isSpaces(String s) {
        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) != ' ') {
                return (false);
            }
        }
        return (true);
    }

    public static void main(String... args) {
        // splits();
        String original = " The quick brown fox xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx  ";
        WordWrapper ww = new WordWrapper(true);
        ww.wordWrapText(original, 11, false);
        String[] lines = ww.getWrappedText();

        for (String line : lines) {
            System.out.println("\"" + line + "\"");
        }

        String selected = " The  quick  brown fox  xx";
        String corrected = ww.getCorrected(selected, 0);
        System.out.println(corrected);

    }

    private static void splits() {
        trySplit("veni vidi vici ", true);
        trySplit("veni vidi vici  ", true);
        trySplit(" veni vidi vici", true);
        trySplit("  veni vidi vici", true);
        trySplit("veni  vidi vici", true);
        trySplit("veni vidi  vici", true);
        trySplit("veni  vidi vici", false);
        trySplit("veni vidi  vici", false);
    }

    private static void trySplit(String s, boolean prefix) {
        WordWrapper ww = new WordWrapper(true);
        String[] parsed = ww.smartSplit(s, prefix);
        System.out.println("\"" + s + "\"");
        for (String p : parsed) {
            System.out.print("\"" + p + "\"  ");
        }
        System.out.println("\n");
    }

}
