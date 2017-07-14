package utils;

import java.awt.*;
import java.awt.geom.Area;
import java.awt.geom.RoundRectangle2D;
import javax.swing.border.AbstractBorder;

/**
 *  Make a Border with rounded corners.
 * 
 */
public class RoundedBorder extends AbstractBorder {

    private static final long serialVersionUID = 1L;
    private Color color;
    private int borderWidth;
    private int borderRadius;
    private Insets insets = null;
    private BasicStroke stroke = null;
    private int strokePad;
    private RenderingHints hints;

    public RoundedBorder() {
        this(Color.BLACK, 1, 10, 10);
    }

    public RoundedBorder(Color color, int borderWidth, int borderRadius, int inset) {
        this.borderWidth = borderWidth;
        this.borderRadius = borderRadius;
        this.color = color;
        stroke = new BasicStroke(borderWidth);
        strokePad = borderWidth / 2;
        hints = new RenderingHints(
                RenderingHints.KEY_ANTIALIASING,
                RenderingHints.VALUE_ANTIALIAS_ON);
        int pad = inset + strokePad;
        insets = new Insets(pad, pad, pad, pad);
    }

    @Override
    public Insets getBorderInsets(Component c) {
        return insets;
    }

    @Override
    public Insets getBorderInsets(Component c, Insets insets) {
        return getBorderInsets(c);
    }

    @Override
    public void paintBorder(
            Component c,
            Graphics g,
            int x, int y,
            int width, int height) {

        Graphics2D g2 = (Graphics2D) g;
        Shape savedClip = g2.getClip();
        Area savedArea = new Area(savedClip);
        int bottom = height - borderWidth;
        RoundRectangle2D.Double roundRect = new RoundRectangle2D.Double(
                strokePad, strokePad, width - borderWidth, bottom, borderRadius, borderRadius);
        Area roundArea = new Area(roundRect);
        g2.setRenderingHints(hints);

        // Paint the BG color of the parent, everywhere outside the clip
        // of the text bubble
        Component parent = c.getParent();
        if (parent != null) {
            Color bg = parent.getBackground();
            Rectangle rect = new Rectangle(0, 0, width, height);
            Area outsideArea = new Area(rect);
            outsideArea.intersect(savedArea);
            outsideArea.subtract(roundArea);
            g2.setClip(outsideArea);
            g2.setColor(bg);
            g2.fillRect(0, 0, width, height);
            g2.setClip(savedClip);
        }
        g2.setColor(color);
        g2.setStroke(stroke);
        g2.draw(roundArea);
    }

    @Override
    public boolean isBorderOpaque() {
        return true;
    }

}
