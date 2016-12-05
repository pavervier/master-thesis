/**
 * Final-year project, University of Liège
 * Automated analysis and detection of spamming botnets.
 * 
 * @author  Pierre-Antoine Vervier
 * @version May, 2010
 * 
 * This class implements the capture of network PDUs from a PacketCapture (PCAP)
 * file.
 * 
 */

package be.ulg.vervier.SmtpDump.NetworkDataCapture;

import jpcap.JpcapCaptor;

public class PCAPFileReader extends PacketCaptor {
    
    /** CONSTRUCTORS */
    
    /** Default constructor. */
    public PCAPFileReader() { super(); }
    
    /** Create a new PCAP file reader with the given PCAP file name. */
    public PCAPFileReader(String fileName) { super(fileName); }
    
    /** METHODS */
    
    /** Open the file to read PDUs from. */
    public void open() throws PacketCaptorException {
        if (is_resource_open) close();
        if (resource_identifier == null || resource_identifier.isEmpty())
            throw new PacketCaptorException("Unable to capture packet from file "
                                           + resource_identifier);
        try {
            captor = JpcapCaptor.openFile(resource_identifier);
        } catch (java.io.IOException ioe) {
            throw new PacketCaptorException("Unable to open file " +
                                           resource_identifier);
        }
        is_resource_open = true;
    }
    
    /** Set the name of the input file to read from. */
    public void setFileName(String fileName) {
        setResourceIdentifier(fileName);
    }
    
    /** Retrieve the name of the input file to read from. */
    public String getFileName() {
        return getResourceIdentifier();
    }
    
}
