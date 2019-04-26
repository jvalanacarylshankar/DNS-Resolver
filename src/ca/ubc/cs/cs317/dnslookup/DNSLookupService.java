package ca.ubc.cs.cs317.dnslookup;

import javax.imageio.IIOException;
import java.io.*;
import java.net.*;
import java.util.*;

public class DNSLookupService {

    private static final int DEFAULT_DNS_PORT = 53;
    private static final int MAX_INDIRECTION_LEVEL = 10;

    private static InetAddress rootServer;
    private static boolean verboseTracing = false;
    private static DatagramSocket socket;

    public static DNSCache cache = DNSCache.getInstance();

    private static Random random = new Random();

    private static ResourceRecord _resA;
    private static ResourceRecord _resAAAA;
    private static ResourceRecord _resCN;
    public static DNSNode oGNode;
    private static boolean _resent = false;
    private static int _cNameTimes = 0;

    /**
     * Main function, called when program is first invoked.
     *
     * @param args list of arguments specified in the command line.
     */
    public static void main(String[] args) {

        if (args.length != 1) {
            System.err.println("Invalid call. Usage:");
            System.err.println("\tjava -jar DNSLookupService.jar rootServer");
            System.err.println("where rootServer is the IP address (in dotted form) of the root DNS server to start the search at.");
            System.exit(1);
        }

        try {
            rootServer = InetAddress.getByName(args[0]);
            System.out.println("Root DNS server is: " + rootServer.getHostAddress());
        } catch (UnknownHostException e) {
            System.err.println("Invalid root server (" + e.getMessage() + ").");
            System.exit(1);
        }

        try {
            socket = new DatagramSocket();
            socket.setSoTimeout(5000);
        } catch (SocketException ex) {
            ex.printStackTrace();
            System.exit(1);
        }

        Scanner in = new Scanner(System.in);
        Console console = System.console();
        do {
            // Use console if one is available, or standard input if not.
            String commandLine;
            if (console != null) {
                System.out.print("DNSLOOKUP> ");
                commandLine = console.readLine();
            } else
                try {
                    System.out.print("DNSLOOKUP> ");
                    commandLine = in.nextLine();
                } catch (NoSuchElementException ex) {
                    break;
                }
            // If reached end-of-file, leave
            if (commandLine == null) break;

            // Ignore leading/trailing spaces and anything beyond a comment character
            commandLine = commandLine.trim().split("#", 2)[0];

            // If no command shown, skip to next command
            if (commandLine.trim().isEmpty()) continue;

            String[] commandArgs = commandLine.split(" ");

            if (commandArgs[0].equalsIgnoreCase("quit") ||
                    commandArgs[0].equalsIgnoreCase("exit"))
                break;
            else if (commandArgs[0].equalsIgnoreCase("server")) {
                // SERVER: Change root nameserver
                if (commandArgs.length == 2) {
                    try {
                        rootServer = InetAddress.getByName(commandArgs[1]);
                        System.out.println("Root DNS server is now: " + rootServer.getHostAddress());
                    } catch (UnknownHostException e) {
                        System.out.println("Invalid root server (" + e.getMessage() + ").");
                        continue;
                    }
                } else {
                    System.out.println("Invalid call. Format:\n\tserver IP");
                    continue;
                }
            } else if (commandArgs[0].equalsIgnoreCase("trace")) {
                // TRACE: Turn trace setting on or off
                if (commandArgs.length == 2) {
                    if (commandArgs[1].equalsIgnoreCase("on"))
                        verboseTracing = true;
                    else if (commandArgs[1].equalsIgnoreCase("off"))
                        verboseTracing = false;
                    else {
                        System.err.println("Invalid call. Format:\n\ttrace on|off");
                        continue;
                    }
                    System.out.println("Verbose tracing is now: " + (verboseTracing ? "ON" : "OFF"));
                } else {
                    System.err.println("Invalid call. Format:\n\ttrace on|off");
                    continue;
                }
            } else if (commandArgs[0].equalsIgnoreCase("lookup") ||
                    commandArgs[0].equalsIgnoreCase("l")) {
                // LOOKUP: Find and print all results associated to a name.
                RecordType type;
                if (commandArgs.length == 2)
                    type = RecordType.A;
                else if (commandArgs.length == 3)
                    try {
                        type = RecordType.valueOf(commandArgs[2].toUpperCase());
                    } catch (IllegalArgumentException ex) {
                        System.err.println("Invalid query type. Must be one of:\n\tA, AAAA, NS, MX, CNAME");
                        continue;
                    }
                else {
                    System.err.println("Invalid call. Format:\n\tlookup hostName [type]");
                    continue;
                }
                findAndPrintResults(commandArgs[1], type);
            } else if (commandArgs[0].equalsIgnoreCase("dump")) {
                // DUMP: Print all results still cached
                cache.forEachNode(DNSLookupService::printResults);
            } else {
                System.err.println("Invalid command. Valid commands are:");
                System.err.println("\tlookup fqdn [type]");
                System.err.println("\ttrace on|off");
                System.err.println("\tserver IP");
                System.err.println("\tdump");
                System.err.println("\tquit");
                continue;
            }

        } while (true);

        socket.close();
        System.out.println("Goodbye!");
    }

    /**
     * Finds all results for a host name and type and prints them on the standard output.
     *
     * @param hostName Fully qualified domain name of the host being searched.
     * @param type     Record type for search.
     */
    private static void findAndPrintResults(String hostName, RecordType type) {

        DNSNode node = new DNSNode(hostName, type);
        oGNode = node;
        printResults(node, getResults(node, 0));
    }

    /**
     * Finds all the result for a specific node.
     *
     * @param node             Host and record type to be used for search.
     * @param indirectionLevel Control to limit the number of recursive calls due to CNAME redirection.
     *                         The initial call should be made with 0 (zero), while recursive calls for
     *                         regarding CNAME results should increment this value by 1. Once this value
     *                         reaches MAX_INDIRECTION_LEVEL, the function prints an error message and
     *                         returns an empty set.
     * @return A set of resource records corresponding to the specific query requested.
     */
    private static Set<ResourceRecord> getResults(DNSNode node, int indirectionLevel) {
        /*if (oGNode == null) {
            oGNode = node;
        }*/
        if (indirectionLevel > MAX_INDIRECTION_LEVEL) {
            System.err.println("Maximum number of indirection levels reached.");
            return Collections.emptySet();
        }

        // check if cache has the results. If not, initiate query.
        if (cache.getCachedResults(node).isEmpty()) {
            // initiate the search with given node and IP address of default root name server
            retrieveResultsFromServer(node, rootServer);
        }

        return cache.getCachedResults(node);
    }

    /**
     * Retrieves DNS results from a specified DNS server. Queries are sent in iterative mode,
     * and the query is repeated with a new server if the provided one is non-authoritative.
     * Results are stored in the cache.
     *
     * @param node   Host name and record type to be used for the query.
     * @param server Address of the server to be used for the query.
     */
    private static void retrieveResultsFromServer(DNSNode node, InetAddress server) {
        // set up global variables
        _resCN = null;
        _resAAAA = null;
        _resA = null;
        // encode the DNS query
        byte[] dnsQuery = Query.createQuery(node, random);
        if (dnsQuery == null) {
            // probably should remake the query! An error occurred.
        }

        System.out.print(server.getHostAddress() + "\n");
        DatagramPacket datagramQueryPacket = new DatagramPacket(dnsQuery, dnsQuery.length, server, DEFAULT_DNS_PORT);

        // send the DNS query
        try {
            socket.send(datagramQueryPacket);
        } catch (java.io.IOException e) {
            // resend packet if there was an error sending it before
            retrieveResultsFromServer(node, server);
        }

        // receive the response
        byte[] byteResponse = new byte[1024];
        DatagramPacket datagramResponsePacket = new DatagramPacket(byteResponse, byteResponse.length);
        try {
            socket.receive(datagramResponsePacket);
            // parse the response
            List<ResourceRecord> recordsList = Response.decodeResponse(datagramResponsePacket);

            // save resource records to the cache
            for (int i = 0; i < recordsList.size(); i++) {
                ResourceRecord r = recordsList.get(i);
                if (r.getType() == RecordType.A) {
                    _resA = r;
                } else if (r.getType() == RecordType.AAAA) {
                    _resAAAA = r;
                } else if (r.getType() == RecordType.CNAME || r.getType() == RecordType.NS) {
                    _resCN = r;
                }
                cache.addResult(r);
            }

            // save a resource record that may not match the original host name queried. (eg. if a CNAME search is required)
            for (int i = 0; i < recordsList.size(); i++) {
                ResourceRecord rr = recordsList.get(i);
                if (Response._AA && !rr.getHostName().equals(oGNode.getHostName())) {
                    if (cache.getCachedResults(oGNode).isEmpty() &&
                            (rr.getType() == RecordType.A || rr.getType() == RecordType.AAAA)) {
                        cache.addResult(new ResourceRecord(oGNode.getHostName(), rr.getType() , rr.getTTL(), rr.getInetResult()));
                    }
                }
            }
            // do recursion with the new ip address
            InetAddress newIP;
            if (_resA != null) {
                // return if last response was authoritative and type A
                if (Response._AA) {
                    _resA = null;
                    return;
                }
                newIP = _resA.getInetResult();
                _resA = null;
                retrieveResultsFromServer(node, newIP);
            } else if (_resAAAA != null) {
                // return if last response was authoritative and type AA
                if (Response._AA) {
                    _resA = null;
                    return;
                }
                // otherwise query with the type AAAA IP address in the response
                newIP = _resAAAA.getInetResult();
                _resAAAA = null;
                retrieveResultsFromServer(node, newIP);
            } else if (_resCN != null) {
                // do another query if the response was CNAME or NS
                DNSNode dnsNode = new DNSNode(_resCN.getTextResult(), RecordType.A);
                _resCN = null;
                _cNameTimes++;
                getResults(dnsNode, _cNameTimes);
            }
        } catch (java.net.SocketTimeoutException s) {
            // resend query once if there was a timeout problem receiving the response
            if (!_resent) {
                retrieveResultsFromServer(node, server);
                _resent = true;
            }
        } catch (java.io.IOException e) {
            // do nothing if there was another error
        }
    }

    public static void verbosePrintResourceRecord(ResourceRecord record, int rtype) {
        if (verboseTracing)
            System.out.format("       %-30s %-10d %-4s %s\n", record.getHostName(),
                    record.getTTL(),
                    record.getType() == RecordType.OTHER ? rtype : record.getType(),
                    record.getTextResult());
    }

    /**
     * Prints the result of a DNS query.
     *
     * @param node    Host name and record type used for the query.
     * @param results Set of results to be printed for the node.
     */
    private static void printResults(DNSNode node, Set<ResourceRecord> results) {
        if (results.isEmpty())
            System.out.printf("%-30s %-5s %-8d %s\n", node.getHostName(),
                    node.getType(), -1, "0.0.0.0");
        for (ResourceRecord record : results) {
            System.out.printf("%-30s %-5s %-8d %s\n", node.getHostName(),
                    node.getType(), record.getTTL(), record.getTextResult());
        }
    }

    /**
     * returns verboseTracing
     *
     * @return boolean
     */
    public static boolean isVerboseTracing() {
        return verboseTracing;
    }
}