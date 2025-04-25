import javax.swing.*;
import java.io.File;
import java.io.IOException;
import java.nio.file.*;
import java.security.KeyPair;

public class FileMonitor {
    private final String directoryPath;
    private final JTextArea logArea;
    private final KeyPair keyPair;
    private final SensitiveDataScanner scanner;

    public FileMonitor(String directoryPath, JTextArea logArea, KeyPair keyPair) {
        this.directoryPath = directoryPath;
        this.logArea = logArea;
        this.keyPair = keyPair;
        this.scanner = new SensitiveDataScanner();
    }

    public void start() {
        new Thread(() -> {
            logArea.setText("Monitoring: " + directoryPath + "\n");

            try (WatchService watchService = FileSystems.getDefault().newWatchService()) {
                Path path = Paths.get(directoryPath);
                path.register(watchService, StandardWatchEventKinds.ENTRY_CREATE, StandardWatchEventKinds.ENTRY_MODIFY);

                WatchKey key;
                while ((key = watchService.take()) != null) {
                    for (WatchEvent<?> event : key.pollEvents()) {
                        if (event.kind() == StandardWatchEventKinds.OVERFLOW) continue;

                        File changedFile = path.resolve((Path) event.context()).toFile();
                        if (!changedFile.isFile()) continue;

                        if (scanner.containsSensitiveData(changedFile)) {
                            logIncident("Sensitive data found in: " + changedFile.getAbsolutePath(), changedFile);
                        } else if (event.kind() == StandardWatchEventKinds.ENTRY_MODIFY) {
                            logIncident("File modified: " + changedFile.getAbsolutePath(), changedFile);
                        }
                    }
                    key.reset();
                }
            } catch (IOException | InterruptedException e) {
                logArea.append("Monitor error: " + e.getMessage() + "\n");
            }
        }).start();
    }

    private void logIncident(String message, File file) {
        logArea.append(message + "\n");

        try {
            String encrypted = RSAEncryptor.encryptFile(file, keyPair);
            logArea.append("Encrypted Content:\n" + encrypted + "\n");
        } catch (Exception e) {
            logArea.append("Encryption error: " + e.getMessage() + "\n");
        }

        JOptionPane.showMessageDialog(null, message, "Incident", JOptionPane.WARNING_MESSAGE);
    }
}
