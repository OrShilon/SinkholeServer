import java.net.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import java.io.*;

public class SinkholeServer {

    static final int DNS_PORT = 53;
    static final int DEFAULT_PORT = 5300;
    static final int MAX_MSG_SIZE_DNS = 1024;
    static DatagramSocket serverSocket;
    static HashSet<String> blockList;

    public static void main(String[] args){
        blockList = new HashSet<>();

        if (args.length > 1) {
            System.out.println("Usage: SinkholeServer [blacklist.txt]");
            System.exit(1);
        }
        if (args.length > 0) {
            importBlockList(args[0]);
        }

        run();
    }

    private static void run() {
        try {
            serverSocket = new DatagramSocket(DEFAULT_PORT);  // bind + listen
            byte[] receiveData = new byte[MAX_MSG_SIZE_DNS];
            DatagramPacket receivePacket = new DatagramPacket(receiveData, receiveData.length);
            serverSocket.receive(receivePacket);

            // Save Client Info
            InetAddress clientAddress = receivePacket.getAddress();
            int clientPort = receivePacket.getPort();
            byte[] dataCopy = Arrays.copyOf(receivePacket.getData(), receivePacket.getLength());
            String domainName = getDomainName(dataCopy, 12);

            // Check Block list
            if (isDomainBlocked(domainName)) {
                dataCopy = EditPacketNameError(dataCopy);
                DatagramPacket sendErrPacket = new DatagramPacket(dataCopy, dataCopy.length, clientAddress, clientPort);
                serverSocket.send(sendErrPacket);
                System.exit(2);
            }

            // Send packet to root server
            InetAddress RootServerAddress = InetAddress.getByName(getRandomRootServer());
            DatagramPacket sendPacket = new DatagramPacket(dataCopy, dataCopy.length, RootServerAddress, DNS_PORT);
            serverSocket.send(sendPacket);

            // Receive response
            serverSocket.receive(receivePacket);
            receiveData = Arrays.copyOf(receivePacket.getData(), receivePacket.getLength());

            int limitRounds = 16;
            while (queryConditions(receiveData) && limitRounds > 0) {

                // Get Server Address
                int answerIndex = GetAnswerIndex(receiveData);
                String serverName = getDomainName(receiveData, answerIndex);
                InetAddress serverAddress = InetAddress.getByName(serverName);

                // Send query to new server
                DatagramPacket newSendPacket = new DatagramPacket(sendPacket.getData(), sendPacket.getLength(), serverAddress, DNS_PORT);
                serverSocket.send(newSendPacket);

                // Receive response
                serverSocket.receive(receivePacket);
                receiveData = Arrays.copyOf(receivePacket.getData(), receivePacket.getLength());

                limitRounds--;
            }

            receiveData = EditPacketSuccess(receiveData);
            sendPacket = new DatagramPacket(receiveData, receiveData.length, clientAddress, clientPort);
            serverSocket.send(sendPacket);

        } catch (SocketException se) {
            System.err.println("Failed to open server socket.");
        } catch (IOException ioe) {
            System.err.println("IOException: Send/Receive packet error");
        }  finally {
            serverSocket.close();
        }
    }

    private static String getRandomRootServer() {
        int count = 13;
        String[] rootServers = new String[count];

        for (int i = 0; i < count; i++) {
            rootServers[i] = String.format("%c.root-servers.net", (char)('a' + i));
        }

        int randIndex = new Random().nextInt(rootServers.length);
        //return rootServers[randIndex];
        return rootServers[3];
    }

    private static String getDomainName(byte[] i_Data, int i_Index) {
        //byte[] data = Arrays.copyOf(i_Data, i_Data.length);
        StringBuilder domainName = new StringBuilder();

        while (i_Data[i_Index] != 0) {
            int len = i_Data[i_Index] & 0xff; // Unsigned short

            while ((len & 0xc0) == 0xc0) { // Check compression
                i_Index = i_Data[i_Index + 1];
                len = i_Data[i_Index] & 0xff; // Unsigned short
            }

            i_Index++;

            for (int i = 0; i < len; i++) {
                domainName.append((char) (int) i_Data[i_Index + i]);
            }

            domainName.append(".");
            i_Index += len;
        }

        return domainName.substring(0, domainName.length() - 1); // To ignore last dot
    }

    private static boolean queryConditions(byte[] i_Data) {
        int responseCode = i_Data[3];
        int numOfAnswers = (i_Data[6] << 8) | i_Data[7];
        int numOfAuthorities = (i_Data[8] << 8) | i_Data[9];

        return responseCode == 0 && numOfAnswers == 0 && numOfAuthorities > 0;
    }

    private static byte[] EditPacketNameError(byte[] i_Data) {
        i_Data[2] |= (byte)0x81;
        i_Data[3] |= (byte)0x83;

        System.err.println("Domain is in Block list");
        return i_Data;
    }

    private static byte[] EditPacketSuccess(byte[] i_Data) {
        i_Data[2] |= (byte)0x80;
        i_Data[2] &= (byte)0xfb;
        i_Data[3] |= (byte)0x80;

        return i_Data;
    }

    private static int GetAnswerIndex(byte[] i_Data) {
        int i = 12;
        while (i_Data[i] != 0) {
            i++;
        }
        i += 17; // Hand counted bytes to skip

        return i;
    }

    private static void importBlockList(String i_filePath) {
        try {
            blockList.addAll(Files.readAllLines(Paths.get(i_filePath)));
        }
        catch (Exception e) {
            System.err.println("File not found.");
        }
    }

    private static boolean isDomainBlocked(String i_DomainName) {
        return blockList.contains(i_DomainName);
    }
}
