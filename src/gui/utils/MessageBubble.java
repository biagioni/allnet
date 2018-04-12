package utils;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import javax.swing.BoxLayout;
import javax.swing.JComponent;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JTextPane;
import javax.swing.SwingUtilities;

/**
 * Class to create a "message bubble" as a JTextPane.
 *
 * A border can be added externally.
 *
 * @author henry
 * @param <MESSAGE>
 */
public class MessageBubble<MESSAGE> extends JPanel implements ActionListener, MouseListener {

    private static final String COPY = "Copy";
    private static final String COPY_ALL = "Copy All";

    // params for resizing bubbles
    private static int estimatedCharsPerLine = 0;
    private static int MAX_RESIZE_TRIES = 12;
    private static double wTargetHi = 0.72;
    private static double wTargetLo = 0.62;

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
    //
    // utility for word wrapping and selection correction
    private WordWrapper ww = new WordWrapper(true);

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
        textPane.addMouseListener(this);
    }

    public static void setEstimatedCharsPerLine(int estimatedCharsPerLine) {
        MessageBubble.estimatedCharsPerLine = estimatedCharsPerLine;
    }

    public void resizeBubble(int width) {
        remove(textPane);
        textPane = makeTextPane(textPane.getBackground(),
            leftJustified, width);
        textPane.setComponentPopupMenu(popup);
        textPane.addMouseListener(this);
        add(textPane);
    }

    private JTextPane makeTextPane(Color color, boolean leftJustified,
        int containerWidth) {
        JTextPane pane;
        int charsPerLine;
        if (estimatedCharsPerLine > 0) {
            charsPerLine = estimatedCharsPerLine;
        }
        else {
            // just use an estimated 5 pixels/char avg width, and 
            // set charsPerLine to fill entire width
            charsPerLine = containerWidth / 5;
        }
        // make a pane using the estimated or default chars per line 
        pane = makeTextPaneQuick(color, leftJustified, charsPerLine);
        int width = pane.getPreferredSize().width;
        // and now we semi-duplicate code, but it's simple and condensing it
        // would make the different condx impossible to follow </defensiveness>
        if (width > wTargetHi * containerWidth) {
            // it's too wide
            int tries = 0;
            do {
                charsPerLine = (9 * charsPerLine) / 10;
                pane = makeTextPaneQuick(color, leftJustified, charsPerLine);
                width = pane.getPreferredSize().width;
                tries++;
            }
            while ((tries < MAX_RESIZE_TRIES)
                && (width > wTargetHi * containerWidth));
            // System.out.println("hi  " + tries + "  " + charsPerLine);
            // set the estimated chars per line
            if ((tries < MAX_RESIZE_TRIES) && (tries > 1)) {
                estimatedCharsPerLine = charsPerLine;
            }            
        }
        else if ((width > wTargetHi * containerWidth) 
            && !ww.getWordBreaks().isEmpty()) {
            // not wide enough, and there were line breaks inserted, so retry
            int tries = 0;
            do {
                charsPerLine = (11 * charsPerLine) / 10;
                pane = makeTextPaneQuick(color, leftJustified, charsPerLine);
                width = pane.getPreferredSize().width;
                tries++;
            }
            while ((tries < MAX_RESIZE_TRIES)
                && (width < wTargetLo * containerWidth)
                && !ww.getWordBreaks().isEmpty());
            // System.out.println("lo  " + tries + "  " + charsPerLine);
            // set the estimated chars per line
            if ((tries < MAX_RESIZE_TRIES) && (tries > 1)
                && !ww.getWordBreaks().isEmpty()) {
                estimatedCharsPerLine = charsPerLine;
            }            
        }
        return (pane);
    }

    private JTextPane makeTextPaneQuick(Color color, boolean leftJustified,
        int charsPerLine) {
        JTextPane pane = new JTextPane();
        pane.setContentType("text/html");
        pane.setEditable(false);
        pane.setBackground(color);
        // 5 pix per char is really small
        ww.wordWrapText(text, charsPerLine, !leftJustified);
        String[] wordWrappedLines = ww.getWrappedText();
        String htmlPrefix;
        if (leftJustified) {
            htmlPrefix = "<STYLE type=\"text/css\"> BODY {text-align: left} </STYLE> <BODY>";
        }
        else {
            htmlPrefix = "<STYLE type=\"text/css\"> BODY {text-align: right} </STYLE> <BODY>";
        }
        StringBuilder sb = new StringBuilder(htmlPrefix);
        for (int i = 0; i < wordWrappedLines.length; i++) {
            sb.append(nbspMe(wordWrappedLines[i]));
            if (i < wordWrappedLines.length - 1) {
                sb.append("<br>");
            }
        }
        sb.append("</BODY>");
        // use &nbsp; here as <pre> does not seem to work
        pane.setText(sb.toString());
        // without this, panel grows to fill scrollpane
        Dimension size = pane.getPreferredScrollableViewportSize();
        pane.setPreferredSize(size);
        pane.setMaximumSize(size);
        return (pane);
    }

    private String nbspMe(String s) {
        String r = s.replaceAll(" ", "&nbsp;");
        return (r);
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
        String selected, corrected;
        int startIdx;
        String cmd = e.getActionCommand();
        switch (cmd) {
            case COPY_ALL:
                corrected = text;
                break;
            case COPY:
                selected = textPane.getSelectedText();
                // offset of 1 determined experimentally, apparently undocumented
                startIdx = textPane.getSelectionStart() - 1;
                corrected = ww.getCorrected(selected, startIdx);
                break;
            default:
                throw new RuntimeException("bad menu cmd");
        }
        StringSelection selection = new StringSelection(corrected);
        Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
        clipboard.setContents(selection, selection);
    }

    @Override
    public void mouseClicked(MouseEvent e) {
// System.out.println ("mouse clicked, event is " + e);
        if (SwingUtilities.isMiddleMouseButton(e)) {
            String selected = textPane.getSelectedText();
            // offset of 1 determined experimentally, apparently undocumented
            int startIdx = textPane.getSelectionStart() - 1;
            String corrected = ww.getCorrected(selected, startIdx);
// System.out.println ("mouse clicked, event is middle mouse button, selected " + corrected);
            StringSelection selection = new StringSelection(corrected);
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            clipboard.setContents(selection, selection);
        }
    }

    @Override
    public void mousePressed(MouseEvent e) {
    }

    @Override
    public void mouseReleased(MouseEvent e) {
    }

    @Override
    public void mouseEntered(MouseEvent e) {
    }

    @Override
    public void mouseExited(MouseEvent e) {
    }
}
