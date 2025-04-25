import javax.swing.*;
import java.awt.*;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

public class DataLeakageDetectorGUI extends JFrame {
    private JTextArea logTextArea;
    private JTextField dirField;
    private FileMonitor fileMonitor;

    public DataLeakageDetectorGUI() {
        setTitle("Data Leakage Detection System");
        setSize(600, 400);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);

        logTextArea = new JTextArea();
        logTextArea.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(logTextArea);
        add(scrollPane, BorderLayout.CENTER);

        JPanel panel = new JPanel();
        dirField = new JTextField(30);
        JButton monitorBtn = new JButton("Start Monitoring");

        panel.add(new JLabel("Directory:"));
        panel.add(dirField);
        panel.add(monitorBtn);
        add(panel, BorderLayout.NORTH);

        monitorBtn.addActionListener(e -> {
            String dirPath = dirField.getText().trim();
            if (dirPath.isEmpty()) {
                JOptionPane.showMessageDialog(this, "Please enter a directory path.");
                return;
            }

            try {
                KeyPair keyPair = RSAEncryptor.generateKeyPair();
                fileMonitor = new FileMonitor(dirPath, logTextArea, keyPair);
                fileMonitor.start();
            } catch (NoSuchAlgorithmException ex) {
                logTextArea.append("Key generation failed: " + ex.getMessage() + "\n");
            }
        });
    }
}
