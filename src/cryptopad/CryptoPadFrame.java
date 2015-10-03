/*
 * This JCryptoPad source code is hereby placed into the Public Domain by its Author maxpat78.
 */

package cryptopad;

import java.awt.Image;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.StringSelection;
import java.awt.datatransfer.Transferable;
import java.awt.event.WindowEvent;
import java.awt.event.WindowListener;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.net.URL;
import java.nio.charset.Charset;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.ImageIcon;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.undo.UndoManager;

/**
 *
 * @author maxpat78
 */
public class CryptoPadFrame
extends javax.swing.JFrame
implements DocumentListener, WindowListener {

    /**
     * Creates new form CryptoPadFrame
     * @throws java.lang.NoSuchFieldException
     * @throws java.lang.IllegalAccessException
     */
    public CryptoPadFrame() throws NoSuchFieldException, IllegalArgumentException, IllegalAccessException {
        // Un trucco per forzare la selezione di UTF-8 sulla TextArea
        System.setProperty("file.encoding","UTF-8");
        Field charset = Charset.class.getDeclaredField("defaultCharset");
        charset.setAccessible(true);
        charset.set(null,null);
        initComponents();
        appIcon = Toolkit.getDefaultToolkit()
                .getImage(URL.class.getResource("/icon.png"));
        clip = Toolkit.getDefaultToolkit().getSystemClipboard();
        undoMgr = new UndoManager();
        setIconImage(appIcon);
        addWindowListener(this);
        TextArea.getDocument().addDocumentListener(this);
        TextArea.getDocument().addUndoableEditListener(undoMgr);
        miFile_NewActionPerformed(null);
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        ScrollPane = new javax.swing.JScrollPane();
        TextArea = new javax.swing.JTextArea();
        mMenuBar = new javax.swing.JMenuBar();
        mFileMenu = new javax.swing.JMenu();
        miFile_New = new javax.swing.JMenuItem();
        miFile_Open = new javax.swing.JMenuItem();
        miFile_Save = new javax.swing.JMenuItem();
        miFile_SaveAs = new javax.swing.JMenuItem();
        jSeparator3 = new javax.swing.JPopupMenu.Separator();
        miFile_Exit = new javax.swing.JMenuItem();
        mEditMenu = new javax.swing.JMenu();
        miEdit_Undo = new javax.swing.JMenuItem();
        jSeparator4 = new javax.swing.JPopupMenu.Separator();
        miEdit_Cut = new javax.swing.JMenuItem();
        miEdit_Copy = new javax.swing.JMenuItem();
        miEdit_Paste = new javax.swing.JMenuItem();
        miEdit_Delete = new javax.swing.JMenuItem();
        jSeparator2 = new javax.swing.JPopupMenu.Separator();
        miEdit_SelectAll = new javax.swing.JMenuItem();
        mFormatMenu = new javax.swing.JMenu();
        miFormat_Wordwrap = new javax.swing.JCheckBoxMenuItem();
        miFormat_Font = new javax.swing.JMenuItem();
        mViewMenu = new javax.swing.JMenu();
        mHelpMenu = new javax.swing.JMenu();
        miHelp_Help = new javax.swing.JMenuItem();
        jSeparator1 = new javax.swing.JPopupMenu.Separator();
        miHelp_About = new javax.swing.JMenuItem();

        setDefaultCloseOperation(javax.swing.WindowConstants.DO_NOTHING_ON_CLOSE);

        TextArea.setColumns(20);
        TextArea.setLineWrap(true);
        TextArea.setRows(5);
        TextArea.setTabSize(4);
        TextArea.setWrapStyleWord(true);
        TextArea.addCaretListener(new javax.swing.event.CaretListener() {
            public void caretUpdate(javax.swing.event.CaretEvent evt) {
                TextAreaCaretUpdate(evt);
            }
        });
        ScrollPane.setViewportView(TextArea);

        mMenuBar.setBorder(null);

        mFileMenu.setMnemonic('F');
        mFileMenu.setText("File");

        miFile_New.setAccelerator(javax.swing.KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_N, java.awt.event.InputEvent.CTRL_MASK));
        miFile_New.setText("Nuovo");
        miFile_New.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                miFile_NewActionPerformed(evt);
            }
        });
        mFileMenu.add(miFile_New);

        miFile_Open.setAccelerator(javax.swing.KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_F12, java.awt.event.InputEvent.CTRL_MASK));
        miFile_Open.setText("Apri...");
        miFile_Open.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                miFile_OpenActionPerformed(evt);
            }
        });
        mFileMenu.add(miFile_Open);

        miFile_Save.setAccelerator(javax.swing.KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_S, java.awt.event.InputEvent.CTRL_MASK));
        miFile_Save.setText("Salva");
        miFile_Save.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                miFile_SaveActionPerformed(evt);
            }
        });
        mFileMenu.add(miFile_Save);

        miFile_SaveAs.setText("Salva con nome...");
        miFile_SaveAs.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                miFile_SaveAsActionPerformed(evt);
            }
        });
        mFileMenu.add(miFile_SaveAs);
        mFileMenu.add(jSeparator3);

        miFile_Exit.setText("Esci");
        miFile_Exit.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                miFile_ExitActionPerformed(evt);
            }
        });
        mFileMenu.add(miFile_Exit);

        mMenuBar.add(mFileMenu);

        mEditMenu.setMnemonic('M');
        mEditMenu.setText("Modifica");
        mEditMenu.addMenuListener(new javax.swing.event.MenuListener() {
            public void menuCanceled(javax.swing.event.MenuEvent evt) {
            }
            public void menuDeselected(javax.swing.event.MenuEvent evt) {
            }
            public void menuSelected(javax.swing.event.MenuEvent evt) {
                mEditMenuMenuSelected(evt);
            }
        });

        miEdit_Undo.setAccelerator(javax.swing.KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_Z, java.awt.event.InputEvent.CTRL_MASK));
        miEdit_Undo.setText("Annulla");
        miEdit_Undo.setEnabled(false);
        miEdit_Undo.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                miEdit_UndoActionPerformed(evt);
            }
        });
        mEditMenu.add(miEdit_Undo);
        mEditMenu.add(jSeparator4);

        miEdit_Cut.setAccelerator(javax.swing.KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_X, java.awt.event.InputEvent.CTRL_MASK));
        miEdit_Cut.setText("Taglia");
        miEdit_Cut.setEnabled(false);
        miEdit_Cut.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                miEdit_CutActionPerformed(evt);
            }
        });
        mEditMenu.add(miEdit_Cut);

        miEdit_Copy.setAccelerator(javax.swing.KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_C, java.awt.event.InputEvent.CTRL_MASK));
        miEdit_Copy.setText("Copia");
        miEdit_Copy.setEnabled(false);
        miEdit_Copy.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                miEdit_CopyActionPerformed(evt);
            }
        });
        mEditMenu.add(miEdit_Copy);

        miEdit_Paste.setAccelerator(javax.swing.KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_V, java.awt.event.InputEvent.CTRL_MASK));
        miEdit_Paste.setText("Incolla");
        miEdit_Paste.setEnabled(false);
        miEdit_Paste.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                miEdit_PasteActionPerformed(evt);
            }
        });
        mEditMenu.add(miEdit_Paste);

        miEdit_Delete.setAccelerator(javax.swing.KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_CLEAR, 0));
        miEdit_Delete.setText("Elimina");
        miEdit_Delete.setEnabled(false);
        miEdit_Delete.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                miEdit_DeleteActionPerformed(evt);
            }
        });
        mEditMenu.add(miEdit_Delete);
        mEditMenu.add(jSeparator2);

        miEdit_SelectAll.setAccelerator(javax.swing.KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_A, java.awt.event.InputEvent.CTRL_MASK));
        miEdit_SelectAll.setText("Seleziona tutto");
        miEdit_SelectAll.setEnabled(false);
        miEdit_SelectAll.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                miEdit_SelectAll(evt);
            }
        });
        mEditMenu.add(miEdit_SelectAll);

        mMenuBar.add(mEditMenu);

        mFormatMenu.setMnemonic('o');
        mFormatMenu.setText("Formato");

        miFormat_Wordwrap.setSelected(true);
        miFormat_Wordwrap.setText("A capo automatico");
        miFormat_Wordwrap.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                miFormat_WordwrapActionPerformed(evt);
            }
        });
        mFormatMenu.add(miFormat_Wordwrap);

        miFormat_Font.setText("Carattere...");
        miFormat_Font.setEnabled(false);
        miFormat_Font.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                miFormat_FontActionPerformed(evt);
            }
        });
        mFormatMenu.add(miFormat_Font);

        mMenuBar.add(mFormatMenu);

        mViewMenu.setMnemonic('V');
        mViewMenu.setText("Visualizza");
        mViewMenu.setEnabled(false);
        mMenuBar.add(mViewMenu);

        mHelpMenu.setMnemonic('?');
        mHelpMenu.setText("?");

        miHelp_Help.setText("Guida");
        miHelp_Help.setEnabled(false);
        mHelpMenu.add(miHelp_Help);
        mHelpMenu.add(jSeparator1);

        miHelp_About.setText("Informazioni su JCryptoPad");
        miHelp_About.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                miHelp_AboutActionPerformed(evt);
            }
        });
        mHelpMenu.add(miHelp_About);

        mMenuBar.add(mHelpMenu);

        setJMenuBar(mMenuBar);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(ScrollPane, javax.swing.GroupLayout.DEFAULT_SIZE, 649, Short.MAX_VALUE)
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(ScrollPane, javax.swing.GroupLayout.DEFAULT_SIZE, 414, Short.MAX_VALUE)
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private int Ask_For_Save() {
        String options[] = { "Salva", "Non salvare", "Annulla" };
        
        return JOptionPane.showOptionDialog(this,
                String.format("Salvare le modifiche a %s?",
                this.getTitle().replace(sTitle, "")),
                "JCryptoPad",
                JOptionPane.YES_NO_CANCEL_OPTION,
                JOptionPane.WARNING_MESSAGE,
                null,options,options[0]);
    }
    
    private void miFile_SaveActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_miFile_SaveActionPerformed
        if (curDocument == null) {
            miFile_SaveAsActionPerformed(evt);
            return;
        }
        
        try {
            try (OutputStream os = new FileOutputStream(curDocument);
                    DataOutputStream dos = new DataOutputStream(os)) {
                
                byte[] s = TextArea.getText()
                        .replaceAll("[^\r]\n", "\r\n") // Windows CR-LF convention
                        .getBytes("UTF-8");
                
                MiniZipAE mzip = new MiniZipAE();
                mzip.set_password(curPassword);
                mzip.set_comment(sDocument);
                mzip.append(curDocument.getName().replace(sEtxt, ".txt"), s);
                mzip.write(dos);
            }
            fileContentModified = false;
        } catch (IOException ex) {
        } catch (MiniZipException ex) {
            JOptionPane.showMessageDialog(this,
                    ex.getMessage(),
                    sTitle.substring(2),
                    JOptionPane.ERROR_MESSAGE);
        }
    }//GEN-LAST:event_miFile_SaveActionPerformed

    private void miFile_SaveAsActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_miFile_SaveAsActionPerformed
        CryptoPadPwdSaveDlg pwdChooser = new CryptoPadPwdSaveDlg(this, true);
        pwdChooser.setVisible(true);
        if (pwdChooser.getPassword().length == 0)
            return;
        
        fileChooser = new JFileChooser();
        FileNameExtensionFilter filter = new FileNameExtensionFilter(sDocument, "etxt");
        fileChooser.setFileFilter(filter);
        
        int returnVal = fileChooser.showSaveDialog(this);

        if (returnVal != JFileChooser.APPROVE_OPTION) {
            fileChooser = null;
            return;
        }

        curDocument = fileChooser.getSelectedFile();
        if (! curDocument.getName().endsWith(sEtxt)) {
            curDocument = new File(curDocument.getParent(), curDocument.getName()+sEtxt);
        }

        if (true == curDocument.exists()) {
            String options[] = { "Sì", "No" };
            int result = JOptionPane.showOptionDialog(this,
                    "Sovrascrivere il file esistente?",
                    "Conferma",
                    JOptionPane.YES_NO_OPTION,
                    JOptionPane.WARNING_MESSAGE,
                    null,options,options[1]);
            if ( result != JOptionPane.YES_OPTION ) {
                    fileChooser = null;
                    return;
            }
        }
        // Andrebbe modificata solo a salvataggio avvenuto?
        curPassword = pwdChooser.getPassword();
        miFile_SaveActionPerformed(evt);
        setTitle(fileChooser.getSelectedFile().getName()+sTitle);
    }//GEN-LAST:event_miFile_SaveAsActionPerformed

    private void miFile_OpenActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_miFile_OpenActionPerformed
        if(true == fileContentModified) {
            int result = Ask_For_Save();

            if (result == JOptionPane.CANCEL_OPTION)
                    return;

            if (result == JOptionPane.YES_OPTION) {
                miFile_SaveActionPerformed(evt);
                if (null == fileChooser)
                    return;
            }
        }

        fileChooser = new JFileChooser();
        FileNameExtensionFilter filter = new FileNameExtensionFilter(sDocument, "etxt");
        fileChooser.setFileFilter(filter);

        int returnVal = fileChooser.showOpenDialog(this);

        if (returnVal != JFileChooser.APPROVE_OPTION) {
            fileChooser = null;
            return;
        }

        curDocument = fileChooser.getSelectedFile();
        if (! curDocument.getName().endsWith(sEtxt)) {
            curDocument = new File(curDocument.getParent(), curDocument.getName()+sEtxt);
        }

        CryptoPadPwdOpenDlg pwd = new CryptoPadPwdOpenDlg(this, true);
        pwd.setVisible(true);
        
        if (0 == pwd.getPassword().length)
            return;

        try {
            try (InputStream is = new FileInputStream(curDocument);
                    DataInputStream dis = new DataInputStream(is)) {

                MiniZipAE mzip = new MiniZipAE();
                mzip.set_password(pwd.getPassword());
                mzip.read(dis);
                String s = new String(mzip.get());
                
                // Windows Style CR-LF
                s.replace("\r\n", "\n");
                
                TextArea.setText(s);
                setTitle(curDocument.getName().replace(sEtxt, "")+sTitle);
                fileContentModified = false;
                curPassword = pwd.getPassword();
            }
        } catch (FileNotFoundException ex) {
            JOptionPane.showMessageDialog(this,
                    "Errore nell'apertura del file "+curDocument,
                    "Errore",
                    JOptionPane.ERROR_MESSAGE);
        } catch (MiniZipException ex) {
            JOptionPane.showMessageDialog(this,
                    ex.getMessage(),
                    sTitle.substring(2),
                    JOptionPane.ERROR_MESSAGE);
        } catch (IOException ex) {
        }
    }//GEN-LAST:event_miFile_OpenActionPerformed

    private void miFile_ExitActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_miFile_ExitActionPerformed
        this.getToolkit().getSystemEventQueue()
                .postEvent(new WindowEvent(this, WindowEvent.WINDOW_CLOSING));
    }//GEN-LAST:event_miFile_ExitActionPerformed

    private void miFile_NewActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_miFile_NewActionPerformed
        if (fileContentModified) {
            int a = Ask_For_Save();

            if (a == JOptionPane.CANCEL_OPTION)
                    return;

            if (a == JOptionPane.YES_OPTION) {
                miFile_SaveActionPerformed(null);
                if (null == fileChooser)
                        return;
            }
        }
        TextArea.setText("");
        setTitle("Senza nome" +sTitle);
        fileContentModified = false;
        curDocument = null;
        curPassword = null;
    }//GEN-LAST:event_miFile_NewActionPerformed

    private void miHelp_AboutActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_miHelp_AboutActionPerformed
        JOptionPane.showMessageDialog(this,
                "Un semplice blocco note che supporta documenti UTF-8\ncompressi in formato ZIP cifrato con AES.",
                sTitle.substring(2),
                JOptionPane.INFORMATION_MESSAGE,
                new ImageIcon(appIcon));
    }//GEN-LAST:event_miHelp_AboutActionPerformed

    private void miFormat_WordwrapActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_miFormat_WordwrapActionPerformed
        TextArea.setLineWrap(! TextArea.getLineWrap());
    }//GEN-LAST:event_miFormat_WordwrapActionPerformed

    private void miEdit_CutActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_miEdit_CutActionPerformed
        try {
            StringSelection ss = new StringSelection(TextArea.getSelectedText());
            clip.setContents(ss, ss);
            TextArea.replaceRange( "",
                    TextArea.getSelectionStart(),
                    TextArea.getSelectionEnd() );
        } catch (Exception ex) {
            
        }
    }//GEN-LAST:event_miEdit_CutActionPerformed

    private void miEdit_CopyActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_miEdit_CopyActionPerformed
        try {
            StringSelection ss = new StringSelection(TextArea.getSelectedText());
            clip.setContents(ss, ss);
        } catch (Exception ex) {
        }
    }//GEN-LAST:event_miEdit_CopyActionPerformed

    private void miEdit_PasteActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_miEdit_PasteActionPerformed
        Transferable ss = clip.getContents(this);
        try {
            String s = (String) ss.getTransferData(DataFlavor.stringFlavor);
            TextArea.replaceRange( s,
                    TextArea.getSelectionStart(),
                    TextArea.getSelectionEnd() );
        } catch(Exception ex) {
        }
    }//GEN-LAST:event_miEdit_PasteActionPerformed

    private void miEdit_DeleteActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_miEdit_DeleteActionPerformed
        TextArea.replaceRange( "",
                TextArea.getSelectionStart(),
                TextArea.getSelectionEnd() );
    }//GEN-LAST:event_miEdit_DeleteActionPerformed

    private void miEdit_SelectAll(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_miEdit_SelectAll
        TextArea.selectAll();
    }//GEN-LAST:event_miEdit_SelectAll

    private void miFormat_FontActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_miFormat_FontActionPerformed
    }//GEN-LAST:event_miFormat_FontActionPerformed

    private void miEdit_UndoActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_miEdit_UndoActionPerformed
        if (undoMgr.canUndo())
            undoMgr.undo();
    }//GEN-LAST:event_miEdit_UndoActionPerformed

    private void TextAreaCaretUpdate(javax.swing.event.CaretEvent evt) {//GEN-FIRST:event_TextAreaCaretUpdate
        if (evt.getDot() == evt.getMark()) {
            // Cut-Copy-Delete
            mMenuBar.getMenu(1).getItem(2).setEnabled(false);
            mMenuBar.getMenu(1).getItem(3).setEnabled(false);
            mMenuBar.getMenu(1).getItem(5).setEnabled(false);
        }
        else {
            mMenuBar.getMenu(1).getItem(2).setEnabled(true);
            mMenuBar.getMenu(1).getItem(3).setEnabled(true);
            mMenuBar.getMenu(1).getItem(5).setEnabled(true);
        }
    }//GEN-LAST:event_TextAreaCaretUpdate

    private void mEditMenuMenuSelected(javax.swing.event.MenuEvent evt) {//GEN-FIRST:event_mEditMenuMenuSelected
        // Updates Undo Menu
        if (undoMgr.canUndo())
            mMenuBar.getMenu(1).getItem(0).setEnabled(true);
        else
            mMenuBar.getMenu(1).getItem(0).setEnabled(false);
        
        // Select All
        if (TextArea.getDocument().getLength() > 0)
            mMenuBar.getMenu(1).getItem(7).setEnabled(true);
        else
            mMenuBar.getMenu(1).getItem(7).setEnabled(false);
            
        // Paste
        if ( (clip.getContents(null) != null) &&
                clip.getContents(null)
                        .isDataFlavorSupported(DataFlavor.stringFlavor) )
            mMenuBar.getMenu(1).getItem(4).setEnabled(true);
        else
            mMenuBar.getMenu(1).getItem(4).setEnabled(false);
    }//GEN-LAST:event_mEditMenuMenuSelected

    // Variabili dichiarate manualmente
    private final String sTitle = " - JCryptoPad";
    private final String sDocument = "JCryptoPad Document";
    private final String sEtxt = ".etxt";
    private JFileChooser fileChooser;
    private File curDocument;
    private boolean fileContentModified;
    private char[] curPassword;
    private final Image appIcon;
    private final Clipboard clip;
    private final UndoManager undoMgr;
    
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JScrollPane ScrollPane;
    private javax.swing.JTextArea TextArea;
    private javax.swing.JPopupMenu.Separator jSeparator1;
    private javax.swing.JPopupMenu.Separator jSeparator2;
    private javax.swing.JPopupMenu.Separator jSeparator3;
    private javax.swing.JPopupMenu.Separator jSeparator4;
    private javax.swing.JMenu mEditMenu;
    private javax.swing.JMenu mFileMenu;
    private javax.swing.JMenu mFormatMenu;
    private javax.swing.JMenu mHelpMenu;
    private javax.swing.JMenuBar mMenuBar;
    private javax.swing.JMenu mViewMenu;
    private javax.swing.JMenuItem miEdit_Copy;
    private javax.swing.JMenuItem miEdit_Cut;
    private javax.swing.JMenuItem miEdit_Delete;
    private javax.swing.JMenuItem miEdit_Paste;
    private javax.swing.JMenuItem miEdit_SelectAll;
    private javax.swing.JMenuItem miEdit_Undo;
    private javax.swing.JMenuItem miFile_Exit;
    private javax.swing.JMenuItem miFile_New;
    private javax.swing.JMenuItem miFile_Open;
    private javax.swing.JMenuItem miFile_Save;
    private javax.swing.JMenuItem miFile_SaveAs;
    private javax.swing.JMenuItem miFormat_Font;
    private javax.swing.JCheckBoxMenuItem miFormat_Wordwrap;
    private javax.swing.JMenuItem miHelp_About;
    private javax.swing.JMenuItem miHelp_Help;
    // End of variables declaration//GEN-END:variables

    @Override
    public void insertUpdate(DocumentEvent e) {
        fileContentModified = true;
    }

    @Override
    public void removeUpdate(DocumentEvent e) {
        fileContentModified = true;
    }

    @Override
    public void changedUpdate(DocumentEvent e) {
        fileContentModified = true;
    }

    @Override
    public void windowOpened(WindowEvent e) {
    }

    @Override
    public void windowClosing(WindowEvent e) {
        if (fileContentModified) {
            int a = Ask_For_Save();

            if (a == JOptionPane.CANCEL_OPTION)
                return;

            if (a == JOptionPane.YES_OPTION) {
                miFile_SaveActionPerformed(null);
                if (null == fileChooser)
                    return;
            }
        }
        dispose();
    }

    @Override
    public void windowClosed(WindowEvent e) {
    }

    @Override
    public void windowIconified(WindowEvent e) {
    }

    @Override
    public void windowDeiconified(WindowEvent e) {
    }

    @Override
    public void windowActivated(WindowEvent e) {
    }

    @Override
    public void windowDeactivated(WindowEvent e) {
    }
}
