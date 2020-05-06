import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class Main {
    public static void main(String[] args) throws IOException {
        directoryInformation("C:\\app\\apache-maven-3.6.3-bin");
    }

    private static void directoryInformation(String uri) throws IOException {
        Path path = Paths.get(uri);


        if (Files.exists(path)) {
            System.out.println("============= Target Directory =============");
            System.out.println("FileName : " + path.getFileName());
            System.out.println("FileSystem : " + path.getFileSystem());
            System.out.println("Parent : " + path.getParent());
            System.out.println("Root : " + path.getRoot());
            System.out.println("Absolute : " + path.isAbsolute());

            System.out.println("isDirectory : " + Files.isDirectory(path));
            System.out.println("isExecutable : " + Files.isExecutable(path));
            System.out.println("isHidden : " + Files.isHidden(path));
            System.out.println("isReadable : " + Files.isReadable(path));
            System.out.println("isSymbolicLink : " + Files.isSymbolicLink(path));

            if (Files.isDirectory(path)) {
                System.out.println("============= Sub-Directories =============");
                printFilesRecursively(path, "");
            }
        }
    }

    private static void printFilesRecursively(Path path, String dash) throws IOException {
        System.out.println(dash + path.getFileName().toString());

        if (Files.isDirectory(path)) {
            DirectoryStream<Path> directoryStream = Files.newDirectoryStream(path);
            for (Path subPath : directoryStream) {
                printFilesRecursively(subPath, dash + "-");
            }
        }
    }
}
