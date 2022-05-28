import java.io.FileInputStream;
import java.io.ObjectInputStream;

public class ToyServerFileMode {
    public static void main(String[] args) throws Exception {
        ObjectInputStream fis = new ObjectInputStream(new FileInputStream("/tmp/to_deserialize_file"));

        System.out.printf("got a long from the file: %d\n", fis.readLong());
        try {
            fis.readObject();
        } catch(Throwable e){}
        System.out.println("readObject(): done.");
        return;
    }
}