import java.io.*;
import java.util.*;
import java.text.*;
import java.util.regex.*;

import java.net.*;
import java.lang.*;


public class Module_tcpconnect
{
    private final String SUCC_CODE        = "0";
    private final String ERR_CODE         = "1";
    private final Integer MIN_PORT_NUMBER = 1;
    private final Integer MAX_PORT_NUMBER = 65535;
    private final Integer REACH_TIMEOUT   = 3000;
    private final Integer SOCKET_TIMEOUT  = 500;
    private final String JAVA_EOL         = getLineSeparator();

    private String getLineSeparator()
    {
        String os_name = System.getProperty("os.name");
        if (os_name.startsWith("Windows"))
            return "\r\n";
        else
            return "\n";
    }

    private byte[] hex2bin(String data) throws Exception
    {
        if ((data.length() % 2) == 1)
            throw new Exception("hex2bin(): data cannot have an odd number of digits");
        
        byte[] data_bytes = new byte[data.length() / 2];
        for (int i = 0; i < data.length(); i += 2)
        {
            String hs = data.substring(i, i + 2);
            try
            {
                int val = Integer.parseInt(hs, 16);
                data_bytes[i/2] = (byte)val;
            }
            catch(Exception e)
            {
                throw new Exception("hex2bin() failed to convert hex:'" + hs + "' to byte");
            }
        }
        return data_bytes;
    }

    private String bin2hex(byte[] ba) throws Exception
    {
        try
        {
            StringBuilder sb = new StringBuilder(ba.length * 2);
            for (byte b: ba)
                sb.append(String.format("%02x", b));
            return sb.toString();
        }
        catch(Exception e)
        {
            throw new Exception("bin2hex() failed");
        }
    }

    private String hex2str(String data) throws Exception
    {
        byte[] data_bytes = hex2bin(data);
        String data_string = new String(data_bytes);
        return data_string;
    }

    private String normalizePath(String currPath)
    {
        currPath = currPath.replace("\"", "");
        currPath = currPath.replace("'", "");
        currPath = currPath.replace("\\", "/");
        return currPath;
    }

    private String[] parseArgs(String args)
    {
        String regex = "\"[^\"]+\"|'[^']+'|\\S+";
        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(args);
        List<String> arguments = new ArrayList<String>();

        while (matcher.find())
            arguments.add(matcher.group(0));

        String[] arguments_arr = new String[arguments.size()];
        arguments_arr = arguments.toArray(arguments_arr);
        return arguments_arr;
    }

    private String changeCWD(String cwd) throws Exception
    {
        File target_dir = new File(cwd).getAbsoluteFile();

        if (target_dir.exists() == false)
            throw new Exception("Directory: '" + cwd + "': does not exist");

        if (target_dir.canRead() == false)
            throw new Exception("Can't move to path: '" + cwd + "': permission denied");

        if (target_dir.isDirectory() == false)
            throw new Exception("Path: '" + cwd + "': is not a directory");

        System.setProperty("user.dir", target_dir.getCanonicalPath());

        return normalizePath(target_dir.getCanonicalPath());
    }

    private boolean isNumeric(String strNum)
    {
        if (strNum == null)
            return false;
        
        try
        {
            Integer i = Integer.parseInt(strNum);
        }
        catch (NumberFormatException nfe)
        {
            return false;
        }
        return true;
    }

    private Boolean validIP (String ip)
    {
        try
        {
            if (ip == null || ip.isEmpty())
                return false;

            String[] parts = ip.split("\\.");
            if (parts.length != 4)
                return false;

            for (String s : parts)
            {
                int i = Integer.parseInt(s);
                if ((i < 0) || (i > 255))
                    return false;
            }

            if (ip.endsWith("."))
                return false;

            return true;
        }
        catch (NumberFormatException nfe)
        {
            return false;
        }
    }

    private String connect2Port(String addr, String port) throws Exception
    {
        String status = "";
        String banner = "";
        Socket socket = null;

        if (isNumeric(port) == false)
            throw new Exception("Invalid port '" + port + "': not a number");

        Integer port_val = Integer.parseInt(port);
        if (port_val < MIN_PORT_NUMBER || port_val > MAX_PORT_NUMBER)
            throw new Exception("Invalid port: '" + port + "'");
        
        try
        {
            InetAddress address = InetAddress.getByName(addr);

            if (address.isReachable(REACH_TIMEOUT) == false)
                throw new NoRouteToHostException();

            socket = new Socket(address, port_val);
            status = "open";

            socket.setSoTimeout(SOCKET_TIMEOUT);
            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            String line = reader.readLine();
            if (line != null)
                banner = line;
        }
        catch (UnknownHostException ex)
        {
            throw new Exception("Can't resolve: " + addr);
        }
        catch (SocketTimeoutException ex)
        {
            status = "open";
        }
        catch (ConnectException ex)
        {
            status = "closed";
        }
        catch (NoRouteToHostException ex)
        {
            throw new Exception("Host: " + addr + " is unreachable");
        }
        finally
        {
            try
            {
                if (socket != null && !socket.isClosed())
                    socket.close();
            }
            catch (Exception e)
            {
                throw new Exception("Can't close socket");
            }
        }

        return addr + ":" + port + " (" + status + ") " + banner + JAVA_EOL;
    }

    private String[] doTcpConnect(String addr, String port)
    {
        String result = "";

        try
        {
            result = connect2Port(addr, port);
        }
        catch (Exception ex)
        {
            return new String[]{ERR_CODE, ex.getMessage() + JAVA_EOL};
        }

        return new String[]{SUCC_CODE, result};
    }

    public String[] execute(String[] args)
    {
        if (args.length != 2)
        {
            String result = "Invalid arguments provided. Specify an address and port" + JAVA_EOL;
            return new String[]{ERR_CODE, result};
        }

        return doTcpConnect(args[0], args[1]);
    }

    public String[] go(String module_cwd, String module_args)
    {
        try
        {
            String new_cwd = changeCWD(hex2str(module_cwd));
            String[] args = parseArgs(hex2str(module_args));
            return execute(args);
        }
        catch(Exception ex)
        {
            return new String[]{ERR_CODE, ex.getMessage() + JAVA_EOL};
        } 
    }

    public static void main(String[] args)
    {
        Module_tcpconnect m = new Module_tcpconnect();
        String[] results = m.execute(args);
        System.out.println(results[1]);
        return;
    }
}