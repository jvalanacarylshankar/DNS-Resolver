package ca.ubc.cs.cs317.dnslookup;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.*;

public class Query {
    private static short _iD;
    private static Query instance = new Query();
    public static Query getInstance() {
        return instance;
    }
    /**
     * returns the byte code for a DNSQuery using the given node as data.
     *
     * @param node  The node to create a query for
     *
     */
    public static byte[] createQuery(DNSNode node, Random random) {
        System.out.println();
        System.out.println();
        try {
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            DataOutputStream dataOutputStream = new DataOutputStream(byteArrayOutputStream);
            createQueryHeader(dataOutputStream, random);
            encodeNodeName(node, dataOutputStream);
            return byteArrayOutputStream.toByteArray();
        } catch (java.io.IOException e) {
            // ignore IO exception
        }

        return null;
    }

    /**
     * writes the node information to the given buffer.
     * Sets the QNAME, QTYPE, and QCLASS of the query.
     *
     *  @param node The node to get the hostname and type from
     *  @param dataOutputStream  The stream to write data to
     *
     */
    public static void encodeNodeName(DNSNode node, DataOutputStream dataOutputStream) throws IOException {
        // write QNAME
        String[] domainNameArray = node.getHostName().split("[.]");
        System.out.print(node.getHostName() + "  ");
        for (int i = 0; i < domainNameArray.length; i++) {
            String label = domainNameArray[i];
            // write label length (2-bits)
            dataOutputStream.writeByte(label.length());
            // write label
            dataOutputStream.write(label.getBytes("UTF-8"));
        }
        // write zero octet to mark end of domain name
        dataOutputStream.writeByte(0x00);
        // write QTYPE
        int qtype = node.getType().getCode();
        switch (qtype) {
            case 1:
                dataOutputStream.writeShort(0x0001);
                break;
            case 2:
                dataOutputStream.writeShort(0x0002);
                break;
            case 5:
                dataOutputStream.writeShort(0x0005);
                break;
            case 6:
                dataOutputStream.writeShort(0x0006);
                break;
            case 15:
                dataOutputStream.writeShort(0x000F);
                break;
            case 28:
                dataOutputStream.writeShort(0x001C);
                break;
            default:
                // type other
                dataOutputStream.writeShort(0x0000);
                break;
        }
        System.out.print(RecordType.getByCode(node.getType().getCode()) + " --> ");
        // write QCLASS
        dataOutputStream.writeShort(0x0001);
    }

    /**
     * creates the header for the DNS query
     *
     * @param dataOutputStream  The stream to write data to
     *
     */
    public static void createQueryHeader(DataOutputStream dataOutputStream, Random random) throws IOException {
        _iD = (short) random.nextInt(Short.MAX_VALUE + 1);
        System.out.print("Query ID     " + _iD + " ");
        // write 16-bit ID
        dataOutputStream.writeShort(_iD);
        // write QR, Opcode, AA, TC, RD, RA, Z, RCODE (all set to 0) (16 bits)
        dataOutputStream.writeShort(0x0000);
        // write QDCOUNT
        dataOutputStream.writeShort(0x0001);
        // write ANCOUNT
        dataOutputStream.writeShort( 0x0000);
        // write NSCOUNT
        dataOutputStream.writeShort(0x0000);
        // write ARCOUNT
        dataOutputStream.writeShort(0x0000);
    }

    /**
     * returns the ID of the last query made
     *
     */
    public static short getQueryID (){
        return _iD;
    }

}
