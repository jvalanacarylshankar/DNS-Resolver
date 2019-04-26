package ca.ubc.cs.cs317.dnslookup;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;

public class Response {
    private static int _offset;
    private static Response instance = new Response();
    private static ByteArrayInputStream _byteArrayInputStream;
    private static DataInputStream _dataInputStream;
    private static DatagramPacket _datagramPacket;
    public static boolean inAnswers = false;
    public static Boolean _AA;

    public static Response getInstance() { return instance; }

    /**
     * decodes the DNS response
     *
     * @param datagramResponsePacket  the datagram packet
     *
     */
    public static  List<ResourceRecord> decodeResponse(DatagramPacket datagramResponsePacket) throws IOException {
        // setup global variables
         _byteArrayInputStream = new ByteArrayInputStream(datagramResponsePacket.getData());
         _dataInputStream = new DataInputStream(_byteArrayInputStream);
         _datagramPacket = datagramResponsePacket;
         _offset = 0;
         _AA = false;
        List<ResourceRecord> recordsList = new ArrayList<>();

        // read the response id
        short iD = _dataInputStream.readShort();
        _offset += 2;

        if(iD != Query.getQueryID())
            throw new IOException("IDs do not match");

        byte header = _dataInputStream.readByte();
        _offset ++;
        // get the AA
        _AA = ((header >> 2) & 1) > 0;

        header = _dataInputStream.readByte();
        _offset ++;
        int RCODE = header & 15;

        if(RCODE == 3 || RCODE == 5) {
            throw new IOException("Error Code");
        }

        if(DNSLookupService.isVerboseTracing()) {
            System.out.println("Response ID: " + iD + " Authoritative = " + _AA);
        }

        int QDCOUNT = _dataInputStream.readShort();
        _offset += 2;
        int ANCOUNT = _dataInputStream.readShort();
        _offset += 2;
        int NSCOUNT = _dataInputStream.readShort();
        _offset += 2;
        int ARCOUNT = _dataInputStream.readShort();
        _offset += 2;

        for (int i = 0; i < QDCOUNT; i++) {
            // skipping over questions
            getName();
            _dataInputStream.readShort();
            _offset += 2;
            _dataInputStream.readShort();
            _offset += 2;
        }

        if(DNSLookupService.isVerboseTracing()) {
            System.out.println("  Answers (" + ANCOUNT + ")");
        }
        for (int i = 0; i < ANCOUNT; i++) {
            inAnswers = true;
            ResourceRecord temp = getResourceRecord();
            recordsList.add(temp);
            DNSLookupService.verbosePrintResourceRecord(temp, temp.getType().getCode());
        }

        inAnswers = false;

        if(DNSLookupService.isVerboseTracing()) {
            System.out.println("  Nameservers  (" + NSCOUNT + ")");
        }
        for (int i = 0; i < NSCOUNT; i++) {
            ResourceRecord temp = getResourceRecord();
            recordsList.add(temp);
            DNSLookupService.verbosePrintResourceRecord(temp, temp.getType().getCode());
        }

        if(DNSLookupService.isVerboseTracing()) {
            System.out.println("  Additional Information (" + ARCOUNT + ")");
        }
        for (int i = 0; i < ARCOUNT; i++) {
            ResourceRecord temp = getResourceRecord();
            recordsList.add(temp);
            DNSLookupService.verbosePrintResourceRecord(temp, temp.getType().getCode());
        }

        return recordsList;
    }

    /**
     * returns a name read from the DNS response
     *
     * @return String
     *
     */
    private static String getName() throws IOException{
        int ptr = _dataInputStream.readByte();
        _offset ++;
        StringBuilder name = new StringBuilder();

        while(ptr != 0) {
            if(ptr < 0) {//pointer
                _offset ++;
                int offsetTemp = _dataInputStream.readByte();

                // get back to beginning of input stream
                _byteArrayInputStream = new ByteArrayInputStream(_datagramPacket.getData());
                _dataInputStream = new DataInputStream(_byteArrayInputStream);

                // skip to offsetTemp
                _dataInputStream.skipBytes(offsetTemp);

                int currentOffset = _offset;
                // get name at offset
                name.append(getName());

                // reset the stream to previous place
                _byteArrayInputStream = new ByteArrayInputStream(_datagramPacket.getData());
                _dataInputStream = new DataInputStream(_byteArrayInputStream);
                 _dataInputStream.skipBytes(currentOffset);

                 _offset = currentOffset;
                return name.toString();
            }

            while(ptr > 0) {
                int temp = _dataInputStream.readByte();
                _offset ++;
                name.append((char) temp);
                ptr--;
            }

            name.append('.');
            ptr = _dataInputStream.readByte();
            _offset ++;

        }

        int nameLen = name.toString().length();
        return name.toString().substring(0, nameLen-1);
    }

    /**
     * returns a ResourceRecord read from the DNS response
     *
     * @return ResourceRecord
     *
     */
    private static ResourceRecord getResourceRecord() throws IOException{
        String name = getName();
        int stype = _dataInputStream.readShort();
        RecordType type = RecordType.getByCode(stype);
        _offset += 2;
        short classRR = _dataInputStream.readShort();
        _offset += 2;
        long TTL = _dataInputStream.readInt();
        _offset += 4;
        int dataLen = _dataInputStream.readShort();
        _offset += 2;

        if (type == RecordType.A || type == RecordType.AAAA) {
            byte[] bytes =  new byte[dataLen];
            _dataInputStream.read(bytes);
            _offset += dataLen;
            InetAddress addr = InetAddress.getByAddress(bytes);

            return new ResourceRecord(name, type, TTL, addr);
        }
        else { // type NS or type CNAME //
            String result = getName();
            return new ResourceRecord(name, type, TTL, result);
        }
    }
}
