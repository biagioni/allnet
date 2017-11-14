package utils;

import allnetui.SocketUtils;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import javax.swing.BoxLayout;
import javax.swing.JComponent;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JTextPane;

/**
 * Class to create a "message bubble" as a JTextPane.
 *
 * A border can be added externally.
 *
 * @author henry
 * @param <MESSAGE>
 */
public class MessageBubble<MESSAGE> extends JPanel implements ActionListener {

    private static final String COPY = "Copy";
    private static final String COPY_ALL = "Copy All";

    // width of the container the last time this MessageBubble was resized
    private int lastContainerWidth;

    // keep the message pane so we can change background later
    private JTextPane textPane;
    // keep ref to popup since text panes will need to reference it
    private JPopupMenu popup;
    // keep a reference to the message that the Bubble renders, if desired
    private MESSAGE message;
    //
    // needed for when we resize the bubble
    private String text;
    private boolean leftJustified;

    public MessageBubble(MESSAGE message, boolean leftJustified, Color color,
        String text, JComponent container) {
        super();
        this.message = message;
        this.leftJustified = leftJustified;
        this.text = text;
        setBackground(color);
        lastContainerWidth = container.getWidth();
        // int charsPerLine = findCharsPerLine(lastContainerWidth);
        textPane = makeTextPane(color, leftJustified, lastContainerWidth);
        setLayout(new BoxLayout(this, BoxLayout.X_AXIS));
        add(textPane);
        // make a context menu
        popup = new JPopupMenu();
        JMenuItem item = new JMenuItem(COPY);
        item.addActionListener(this);
        popup.add(item);
        item = new JMenuItem(COPY_ALL);
        item.addActionListener(this);
        popup.add(item);
        textPane.setComponentPopupMenu(popup);
    }

    private JTextPane makeTextPane(Color color, boolean leftJustified,
        int containerWidth) {
        JTextPane pane = null;
        int width = containerWidth;
        do {
            pane = makeTextPaneQuick(color, leftJustified, width);
            width = (9*width)/10;
        } while (pane.getPreferredSize().width > (2*containerWidth)/3);
        return(pane);
    }
        
    private JTextPane makeTextPaneQuick(Color color, boolean leftJustified,
        int containerWidth) {
        JTextPane pane = new JTextPane();
        pane.setContentType("text/html");
        pane.setEditable(false);
        pane.setBackground(color);
        // 5 pix per char is really small
        String[] lines = partitionText(text, containerWidth/5);
        String htmlPrefix;
        if (leftJustified) {
            htmlPrefix = "<STYLE type=\"text/css\"> BODY {text-align: left} </STYLE> <BODY>";
        }
        else {
            htmlPrefix = "<STYLE type=\"text/css\"> BODY {text-align: right} </STYLE> <BODY>";
        }
        StringBuilder sb = new StringBuilder(htmlPrefix);
        for (int i = 0; i < lines.length; i++) {
            sb.append(lines[i]);
            if (i < lines.length - 1) {
                sb.append("<br>");
            }
        }
        sb.append("</BODY>");
        pane.setText(sb.toString());
        // without this, panel grows to fill scrollpane
        Dimension size = pane.getPreferredScrollableViewportSize();
        pane.setPreferredSize(size);
        pane.setMaximumSize(size);
        return (pane);
    }

    //private int findCharsPerLine(int containerWidth) {
    //    return (Math.max(10, containerWidth / 10));
    //}
    private String[] partitionText(String text, int maxChars) {
        String[] lines = text.split("\n");
        ArrayList<String> list = new ArrayList<>();
        for (String line : lines) {
            if (line.length() <= maxChars) {
                list.add(line);
            }
            else {
                list.addAll(splitUpLine(line, maxChars));
            }
        }
        StringBuilder sb = new StringBuilder();
        for (String line : list) {
            sb.append(line);
            sb.append("\n");
        }
        String temp = SocketUtils.sanitizeForHtml(sb.toString());
        return (temp.split("\n"));
    }

    // chop a line up into pieces <= max length
    private ArrayList<String> splitUpLine(String oldLine, int maxChars) {
        ArrayList<String> lines = new ArrayList<>();
        String[] darkSpace = oldLine.split("\\s+");
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
                sb.append(" ");
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

    public void setBubbleBackground(Color bg) {
        super.setBackground(bg);
        textPane.setBackground(bg);
    }

    public MESSAGE getMessage() {
        return (message);
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        String cmd = e.getActionCommand();
        switch (cmd) {
            case COPY:
                this.textPane.copy();
                break;
            case COPY_ALL:
                this.textPane.selectAll();
                this.textPane.copy();
                break;
            default:
                throw new RuntimeException("bad menu cmd");
        }
    }

    public void resizeBubble(int width) {
        remove(textPane);
        textPane = makeTextPane(textPane.getBackground(), 
            leftJustified, width);
        textPane.setComponentPopupMenu(popup);
        add(textPane);        
    }

}
