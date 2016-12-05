/**
 * Final-year project, University of Liège
 * Automated analysis and detection of spamming botnets.
 * 
 * @author  Pierre-Antoine Vervier
 * @version May, 2010
 * 
 * This class represents a SMTP session. It is simply a collection of SMTP
 * statements and responses recorded on a single TCP session, i.e. from one
 * client to a server.
 * 
 */

package be.ulg.vervier.SmtpDump.SMTPSessionManagement;

import java.util.Collection;
import java.util.List;
import java.util.ArrayList;
import java.net.InetAddress;
import be.ulg.vervier.SmtpDump.TCPSessionManagement.TCPSession;

public class SMTPSession {
    
    /** INSTANCE VARIABLES */
    
    /** The list of SMTP commands/IMF messages issued by the client */
    private ArrayList<SessionStatement> commands;
    /** The list of SMTP responses sent by the server */
    private ArrayList<SessionStatement> responses;
    /** The underlying TCP session */
    private TCPSession tcp_session;
    /** The list of SMTP transactions within the current SMTP session. A
     * SMTP transaction begins with the client sending the MAIL command and ends
     * with the client sending the termination sequence <CRLF>.<CRLF> or the
     * RSET command. */
    private ArrayList<Transaction> transactions;
    /** The current SMTP transaction */
    private Transaction cur_trans;
    
    /** This class defines a SMTP transaction. A SMTP transaction begins with
     * the client sending the MAIL command and ends with the client sending the
     * termination sequence <CRLF>.<CRLF> or the RSET command. */
    class Transaction {
        
        /** INSTANCE VARIABLES */
        
        /** The index of the first SMTP command in the transaction */
        private int f_cmd;
        /** The index of the first SMTP response in the transaction */
        private int f_res;
        /** The index of the last SMTP command in the transaction */
        private int l_cmd;
        /** The index of the last SMTP response in the transaction */
        private int l_res;
        
        /** CONSTRUCTORS */
        
        /** Default constructor. */
        Transaction() { this(-1, -1, -1, -1); }
        
        /** Create a new SMTP transaction with the given starting SMTP command
         * and response and the given ending SMTP command and response. */
        Transaction(int f_cmd, int f_res, int l_cmd, int l_res) {
            this.f_cmd = f_cmd;
            this.f_res = f_res;
            this.l_cmd = l_cmd;
            this.l_res = l_res;
        }
        
        /** METHODS */
        
        /** Retrieve the index of the first SMTP command in the transaction. */
        int firstCmd() { return f_cmd; }
        
        /** Retrieve the index of the first SMTP command in the transaction. */
        void firstCmd(int index) { f_cmd = index; }
        
        /** Retrieve the index of the first SMTP command in the transaction. */
        int firstRes() { return f_res; }
        
        /** Retrieve the index of the first SMTP command in the transaction. */
        void firstRes(int index) { f_res = index; }
        
        /** Retrieve the index of the last SMTP response in the transaction. */
        int lastCmd() { return l_cmd; }
        
        /** Retrieve the index of the last SMTP response in the transaction. */
        void lastCmd(int index) { l_cmd = index; }
        
        /** Retrieve the index of the last SMTP response in the transaction. */
        int lastRes() { return l_res; }
        
        /** Retrieve the index of the last SMTP response in the transaction. */
        void lastRes(int index) { l_res = index; }
        
        /** Return true if the given command index belongs to the SMTP
         * transaction, false otherwise. */
        boolean isCmdInTransaction(int index) {
            return index >= 0 && index >= f_cmd && index <= l_cmd;
        }
        
        /** Return true if the given response index belongs to the SMTP
         * transaction, false otherwise. */
        boolean isResInTransaction(int index) {
            return index >= 0 && index >= f_res && index <= l_res;
        }
        
        /** Return true if the SMTP transaction has been closed normally as far
         * as the client is concerned, i.e. the client has sent the termination
         * sequence <CRLF>.<CRLF> or the RSET command, false otherwise. */
        boolean isCmdClosed() {
            return f_cmd >= 0 && l_cmd >= 0;
        }
        
        /** Return true if the SMTP transaction has been closed normally as far
         * as the server is concerned, i.e. the server has answered the client's
         * termination sequence <CRLF>.<CRLF> or RSET command, false
         * otherwise. */
        boolean isResClosed() {
            return f_res >= 0 && l_res >= 0;
        }
        
        /** Return true if the SMTP transaction has been closed normally,
         * i.e. the client has sent the termination sequence <CRLF>.<CRLF> or
         * the RSET command and the server has acknowleged it, false
         * otherwise. */
        boolean isClosed() {
            return isCmdClosed() && isResClosed();
        }
        
        /** Return the String representation of the SMTP transaction. */
        public String toString() {
            return "[CMD = " + f_cmd + ", " + l_cmd +
                   "; RES = " + f_res + ", " + l_res + "]";
        }
        
    }
    
    /** CONSTRUCTORS */
    
    /** Default constructor. */
    public SMTPSession(TCPSession under_tcp_session)
            throws InvalidSMTPSessionIdentifierException {
        if (under_tcp_session == null ||
            (under_tcp_session != null && under_tcp_session.isEmpty()))
            throw new InvalidSMTPSessionIdentifierException();
        tcp_session = under_tcp_session;
        commands = new ArrayList<SessionStatement>();
        responses = new ArrayList<SessionStatement>();
        transactions = new ArrayList<Transaction>();
        cur_trans = null;
    }
    
    /** METHODS */
    
    /** Retrieve the commands/messages issed by the SMTP client. */
    public List<SessionStatement> getCommands() { return commands; }
    
    /** Retrieve the responses sent by the SMTP server. */
    public List<SessionStatement> getResponses() { return responses; }
    
    /** Retrieve the number of commands/messages issued by the SMTP client. */
    public int getCmdCount() { return commands.size(); }
    
    /** Retrieve the number of responses sent by the SMTP server. */
    public int getResCount() { return responses.size(); }
    
    /** Retrieve the number of SMTP packets extracted from the underlying TCP
     * connection. */
    public int size() { return commands.size() + responses.size(); }
    
    /** Retrieve the number of SMTP packets coming from the client SMTP. */
    public int getClientPacketCount() { return getCmdCount(); }
    
    /** Retrieve the number of SMTP packets coming from the server SMTP. */
    public int getServerPacketCount() { return getResCount(); }
    
    /** Return true if the the SMTP session is empty, i.e. there is no SMTP
     * command and response. */
    public boolean isEmpty() { return commands.isEmpty() && responses.isEmpty(); }
    
    /** Retrieve the SMTP server IP address. */
    public InetAddress getServerIP() { return tcp_session.getDestinationIP(); }
    
    /** Retrieve the SMTP client IP address. */
    public InetAddress getClientIP() { return tcp_session.getSourceIP(); }
    
    /** Retrieve the SMTP server port number. */
    public int getServerPort() { return tcp_session.getDestinationPort(); }
    
    /** Retrieve the SMTP client port number. */
    public int getClientPort() { return tcp_session.getSourcePort(); }
    
    /** Return true if the underlying TCP connection was opened correclty by the
     * client, false otherwise. */
    public boolean hasTcpSyn() { return tcp_session.hasSyn(); }
    
    /** Return true if the underlying TCP connection was closed correclty by the
     * client, false otherwise. */
    public boolean hasTcpFin() { return tcp_session.hasFin(); }
    
    /** Return true if the underlying TCP connection was reset by the client,
     * false otherwise. */
    public boolean hasTcpRst() { return tcp_session.hasRst(); }
    
    /** Retrieve the number of TCP packets which SMTP data has been extracted
     * from. */
    public int getTCPPacketCount() { return tcp_session.size(); }
    
    /** Retrieve the underlying TCP session. */
    public TCPSession getTCPSession() { return tcp_session; }
    
    /** Retrieve the number of SMTP transaction within the SMTP session. A SMTP
     * transaction begins with the client sending the MAIL command and ends with
     * the client sending the termination sequence <CRLF>.<CRLF> or the RSET
     * command. */
    public int getTransactionCount() { return transactions.size(); }
    
    /** Retrieve the transaction number of the given SMTP command index, -1
     * if the command index doesn't belong to any transaction. */
    public int getCmdTransaction(int cmd_index) {
        for (int i = 0; i < transactions.size(); i++)
            if (transactions.get(i).isCmdInTransaction(cmd_index))
                return i;
        return -1;
    }
    
    /** Retrieve the transaction number of the given SMTP response index, -1
     * if the response index doesn't belong to any transaction. */
    public int getResTransaction(int res_index) {
        for (int i = 0; i < transactions.size(); i++)
            if (transactions.get(i).isResInTransaction(res_index))
                return i;
        return -1;
    }
    
    /** Return true if the given transaction numbers matche, i.e. they are
     * equal, false otherwise. Comparing a transaction number -1 always return
     * true. */
    public boolean isMatchingTransaction(int trans1, int trans2) {
        return trans1 == trans2;
    }
    
    /** Compute the hashcode of the current SMTP session. */
    public int hashCode() {
        return getServerIP().hashCode() + getClientIP().hashCode() +
               getServerPort() + getClientPort();
    }
    
    /** Add the given command to the SMTP session. */
    void addCommand(SMTPCommand command)
            throws InvalidSessionStatementException {
        // a SMTP transaction begins with the client sending the MAIL command
        // and ends with the client sending the termination sequence
        // <CRLF>.<CRLF> in a IMF packet or the RSET command
        if (command != null && !command.isEmpty()) {
            switch (command.cmdType()) {
                // start a transaction
                case MAIL:
                    cur_trans = new Transaction();
                    cur_trans.firstCmd(commands.size());
                    break;
                // end a transaction
                case RSET:
                    if (cur_trans != null)
                        cur_trans.lastCmd(commands.size());
                    break;
                // break a transaction
                case HELO:
                case QUIT:
                case EXTN:
                    cur_trans = null;
                    break;
                // no effect on transaction
                case RCPT: break;
                case DATA: break;
                case NOOP: break;
                case VRFY: break;
                case EXPN: break;
                case HELP: break;
                default: break;
            }
            commands.add(command);
        } else {
            throw new InvalidSessionStatementException();
        }
    }
    
    /** Add the given command to the SMTP session. */
    void addMessage(IMFMessage message)
            throws InvalidSessionStatementException {
        // a SMTP transaction begins with the client sending the MAIL command
        // and ends with the client sending the termination sequence
        // <CRLF>.<CRLF> in a IMF packet or the RSET command
        if (message != null && !message.isEmpty()) {
            if (cur_trans != null)
                cur_trans.lastCmd(commands.size());
            commands.add(message);
        } else {
            throw new InvalidSessionStatementException();
        }
    }
    
    /** Add a response to the SMTP session. */
    void addResponse(SMTPResponse response)
            throws InvalidSessionStatementException {
        if (response != null) {
            if (cur_trans != null) {
                if (cur_trans.firstRes() < 0)
                    cur_trans.firstRes(responses.size());
                if (cur_trans.isCmdClosed() && !cur_trans.isResClosed()) {
                    cur_trans.lastRes(responses.size());
                    transactions.add(cur_trans);
                    //System.out.println(cur_trans);
                    cur_trans = null;
                }
            }
            responses.add(response);
        }
        else throw new InvalidSessionStatementException();
    }
    
    /** Return the String representation of the SMTP session. */
    public String toString() {
        StringBuilder sb = new StringBuilder(300);
        sb.append("(C)");
        sb.append(getClientIP());
        sb.append(":");
        sb.append(getClientPort());
        sb.append(" --> (S)");
        sb.append(getServerIP());
        sb.append(":");
        sb.append(getServerPort());
        sb.append(" [");
        sb.append(getCmdCount());
        sb.append(" cmds, ");
        sb.append(getResCount());
        sb.append(" resps, ");
        sb.append(getTransactionCount());
        sb.append(" trans]");
        return sb.toString();
    }
    
}
