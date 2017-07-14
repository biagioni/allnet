package utils;

import java.awt.Color;
import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.border.Border;

/**
 *
 * @author Henry
 */
public class HtmlLabel extends JLabel {

    private static final long serialVersionUID = 1L;
    private static String html0 = "<html>";
    private static String html1 = "<html><body style='width: ";
    private static String html2 = "px'>";

    // constructor to wrap text using a fixed pixel width
    public HtmlLabel(String msg, int width) {
        super(html1 + width + html2 + msg);
    }

    // constructor to wrap text and insert line breaks
    public HtmlLabel(String... lines) {
        super();
        setText(lines);
    }

    public final void setText(String... lines) {
        // the html processing will trim off a leading space, substitute nbsp
        for (int i=0; i<lines.length; i++) {
            if (lines[i].startsWith(" ")) {
                lines[i] = "&nbsp;" + lines[i].substring(1);
            }
        }
        StringBuilder sb = new StringBuilder(html0+lines[0]);
        int i = 1;
        while (i<lines.length) {
            sb.append("<br>");
            sb.append(lines[i]);
            i++;
        }
        setText(sb.toString());
    }

    // undo the html processing
    public final String getPlainText() {
        String result = getText();
        result = result.replace("&nbsp;", " ");
        result = result.replace("<br>", "\n");
        result = result.replace("<html>", "");
        return result;
    }

    // undo the html processing
    public final String [] getPlainTextLines() {
        String text = getText();
        text = text.replace("&nbsp;", " ");
        text = text.replace("<html>", "");
        return text.split("<br>");
    }

    public void setLineBorder (Color c, int width, boolean round) {
        Border border = BorderFactory.createLineBorder(c, width, round);
        setBorder(border);
    }

}
