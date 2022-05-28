import java.io.*;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;

public class ToyServer implements Serializable {
    static final String serverName = "ToyServer";
    static final int serverVersion = 0x1337;

    public static void main(String[] args) throws Exception {
        bindAndDoStuff("0.0.0.0", 9090);
    }

    private static void bindAndDoStuff(String listenAddress, int listenPort) throws Exception {
        ObjectInputStream ois;
        ObjectOutputStream oos = null;
        InetAddress listenAddr;
        Socket s = null;

        listenAddr = InetAddress.getByName(listenAddress);

        ServerSocket serverSock = new ServerSocket(listenPort, 0, listenAddr);
        System.out.println("[+] ToyServer started, listening on " + serverSock.getInetAddress().getHostAddress() + ":" + serverSock.getLocalPort());

        while(true) {
            try {
                s = serverSock.accept();
                System.out.println("[+] Connection accepted from " + s.getInetAddress().getHostAddress() + ":" + s.getPort());

                oos = new ObjectOutputStream(s.getOutputStream());
                ois = new ObjectInputStream(s.getInputStream());

                oos.writeInt(serverVersion);
                oos.flush();
                System.out.printf("[>] writeInt(): 0x%x\n", serverVersion);

                System.out.printf("[<] readInt(): 0x%x\n", ois.readInt());

                oos.writeUTF(serverName);
                oos.flush();
                System.out.printf("[>] writeUTF(): %s\n", serverName);

                System.out.printf("[<] readUTF(): %s\n", ois.readUTF());


                oos.writeShort(0xabcd);
                oos.flush();
                System.out.printf("[>] writeShort(): 0x%x\n", 0xabcd);

                System.out.printf("[<] readShort(): 0x%x\n", ois.readShort());


		        oos.writeLong(-12345);
                oos.flush();
                System.out.printf("[>] writeLong(): %d\n", -12345);

                System.out.printf("[<] readLong(): %d\n", ois.readLong());


                oos.writeObject(new ToyServer());
                oos.flush();
                System.out.println("[>] writeObject()");

                System.out.println("[<] readObject()");
                try {
                	ois.readObject();
               	} catch (Throwable e) {}
                s.close();
                System.out.println("[!] connection closed.");
            } catch(Exception e) {
                System.out.println(e);
            }
        }
    }
}