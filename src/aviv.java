import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.net.*;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Random;

public class aviv {

    static boolean isBlockList = false;
    static final int UDP_DNS_SIZE = 512;
    static final int DNS_NAME_POSITION = 17;
    static HashSet<String> blockList;

    public static void main(String[] args) {

        //check if block list is required
        if (args.length == 1)
        {
            String blockListFile = args[0];
            blockList = createBlockList(blockListFile);
            isBlockList = true;
        }
        else if (args.length > 1) {
            System.err.println("Usage: SinkholeServer [opt]blocklist.txt");
            System.exit(-1);
        }

        startServer();
    }

    private static void startServer() {

        DatagramSocket serverSocket = null;
        try {
            serverSocket = new DatagramSocket(5300); // listen on port 5300
            DatagramPacket receiverPacket = new DatagramPacket(new byte[UDP_DNS_SIZE], UDP_DNS_SIZE);
            serverSocket.receive(receiverPacket);
            InetAddress clientAddress = receiverPacket.getAddress();
            int clientPort = receiverPacket.getPort();
            byte[] packetData = Arrays.copyOf(receiverPacket.getData(), receiverPacket.getLength());
            String nameFromDns = getNameFromPacket(receiverPacket, 12); // 12 - UDP header size
            if (isBlockList && blockList.contains(nameFromDns)) // block the request
            {
                prepareAndSendError(serverSocket, receiverPacket, packetData, clientAddress, clientPort);
            }
            else
            {
                InetAddress rootServerIP = getRandomRootServer();
                DatagramPacket dnsPacketToRoot = new DatagramPacket(packetData, packetData.length, rootServerIP, 53);
                serverSocket.send(dnsPacketToRoot);
                serverSocket.receive(receiverPacket);
                packetData = Arrays.copyOf(receiverPacket.getData(), receiverPacket.getLength()); // copy packet content without changing it
                int iterationLimit = 0;
                while (checkConditions(packetData) && iterationLimit < 16) {
                    // get next authoritative DNS Server
                    int indexToStart = 12; // UDP header
                    while (packetData[indexToStart] != 0) {
                        indexToStart += 1;
                    }
                    indexToStart += DNS_NAME_POSITION;
                    String serverName = getNameFromPacket(receiverPacket, indexToStart);
                    InetAddress serverAddress = InetAddress.getByName(serverName);
                    // send query to authoritative DNS Server
                    DatagramPacket packetToSend = new DatagramPacket(dnsPacketToRoot.getData(), dnsPacketToRoot.getLength(), serverAddress, 53);
                    serverSocket.send(packetToSend);
                    serverSocket.receive(receiverPacket);
                    packetData = Arrays.copyOf(receiverPacket.getData(), receiverPacket.getLength());
                    iterationLimit ++;
                }
                prepareAndSendPacket(serverSocket, receiverPacket, packetData, clientAddress, clientPort);
            }
        }
        catch (SocketException ex)
        {
            System.err.println("Unable to create UDP socket " + ex.getMessage());
        }
        catch (UnknownHostException ex)
        {
            System.err.println("Unable to get root server " + ex.getMessage());
        }
        catch (IOException ex)
        {
            System.err.println("Unable to receive packet " + ex.getMessage());
        }
        catch (StringIndexOutOfBoundsException ex)
        {
            System.err.println("Unable to reach requested domain, please try again " + ex.getMessage());
        }
        finally {
            try {
                serverSocket.close();
            }
            catch (Exception ex) {
                System.err.println("Unable to close socket " + ex.getMessage());
            }
        }
    }

    private static void prepareAndSendError(DatagramSocket socket, DatagramPacket packet, byte[] packetData, InetAddress clientAddress, int clientPort) throws IOException {
        // set required bytes for error response
        packetData[3] = (byte)(packetData[3] | (byte)0x3);
        byte RA = (byte)(packetData[3] | (byte)0x80); //check if starts with 10
        byte AA = (byte)(packetData[2] | (byte)0x80); //check if starts with 10
        packetData[3] = RA;
        packetData[2] = AA;
        sendFinalPacket(socket, packet, packetData, clientAddress, clientPort);
    }

    private static void prepareAndSendPacket(DatagramSocket socket, DatagramPacket packet, byte[] packetData, InetAddress clientAddress, int clientPort) throws IOException {
        // set required bytes for correct response
        byte RA = (byte)(packetData[3] | (byte)0x80); //check if starts with 10
        byte AA = (byte)(packetData[2] & (byte)0xfb);
        packetData[3] = RA;
        packetData[2] = AA;
        sendFinalPacket(socket, packet, packetData, clientAddress, clientPort);
    }

    private static void sendFinalPacket(DatagramSocket socket, DatagramPacket packet, byte[] packetData, InetAddress clientAddress, int clientPort) throws IOException {
        // send answer to the client
        packet.setData(packetData);
        packet.setAddress(clientAddress);
        packet.setPort(clientPort);
        socket.send(packet);
    }

    private static boolean checkConditions(byte[] packetDataToCheck) {
        boolean conditionsOK = false;
        boolean errorOK;
        boolean answerOK;
        boolean authorityOK;
        errorOK = (packetDataToCheck[3] == 0); // check NOERROR
        answerOK = (((packetDataToCheck[6] << 8) | (packetDataToCheck[7] & 0xff)) == 0); // check ANSWER
        authorityOK = (((packetDataToCheck[8] << 8) | (packetDataToCheck[9] & 0xff)) > 0); // check AUTHORITY
        conditionsOK = errorOK && answerOK && authorityOK;

        return  conditionsOK;
    }

    private static String getNameFromPacket(DatagramPacket packet, int indexToStart) {
        byte[] packetData = Arrays.copyOf(packet.getData(), packet.getLength()); // copy packet data without changing the original
        StringBuilder name = new StringBuilder();
        // start going over packet data to find the domain name
        while (packetData[indexToStart] != 0) {
            int len = packetData[indexToStart] & 0xff; //get unsigned int
            if ((len & 0xc0) == 0xc0) //check top two bits
            {
                indexToStart = packetData[indexToStart + 1];
                len = packetData[indexToStart];
            }
            indexToStart += 1;
            for (int i = 0; i < len; i ++) {
                name.append((char)(int) packetData[indexToStart + i]);
            }
            indexToStart += len;
            name.append(".");
        }

        String domainName = name.toString().substring(0, name.length() - 1);

        return domainName;
    }

    private static InetAddress getRandomRootServer() throws UnknownHostException {
        char[] letterArray = new char[] {'a' , 'b' , 'c', 'd' ,'e' , 'f' , 'g', 'h', 'i', 'j' , 'k' , 'l' ,'m'};
        Random rand = new Random();
        int randIndex = rand.nextInt(letterArray.length);
        InetAddress rootIP = InetAddress.getByName(letterArray[randIndex] + ".root-servers.net");
        return rootIP;
    }

    private static HashSet<String> createBlockList(String filePath)
    {
        HashSet<String> blockList = new HashSet<String>();
        // using try with resources to efficiently read the file
        try (BufferedReader br = new BufferedReader(new FileReader(filePath))) {
            String line = br.readLine();
            while (line != null)
            {
                blockList.add(line);
                line = br.readLine();
            }
        }
        catch (Exception ex) {
            System.err.println("Unable to read block list file");
        }

        return blockList;
    }
}