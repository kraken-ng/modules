using System;
using System.IO;
using System.Text;
using System.Security;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Runtime.InteropServices;
using System.Security.Principal;

using System.Net;
using System.Net.NetworkInformation;


public class MyConnection
{
    public string proto;
    public string local_addr;
    public int    local_port;
    public string remote_addr;
    public int    remote_port;
    public string state;

    public const string SEPARATOR = "\t";


    public MyConnection(string proto, string local_addr, int local_port, 
                     string remote_addr, int remote_port, string state)
    {
        this.proto       = proto;
        this.local_addr  = local_addr;
        this.local_port  = local_port;
        this.remote_addr = remote_addr;
        this.remote_port = remote_port;
        this.state       = state;
    }

    public override string ToString()
    {
        string output = "";
        output += this.proto;
        output += SEPARATOR;
        output += this.local_addr  + ":" + this.local_port.ToString();
        output += SEPARATOR;
        if (this.proto == "udp")
            output += "*:*";
        else
            output += this.remote_addr + ":" + this.remote_port.ToString();
        output += SEPARATOR;
        if (this.state == "")
            output += "?";
        else
            output += this.state;
        return output;
    }
}

public class Module_netstat
{
    public const string SUCC_CODE       = "0";
    public const string ERR_CODE        = "1";
    public const string NON_TOKEN_VALUE = "0";

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool RevertToSelf();

    private void ImpersonateWithToken(string token)
    {
        int token_int = Int32.Parse(token);
        IntPtr targetToken = new IntPtr(token_int);

        string current_username = "";
        using (WindowsIdentity wid = WindowsIdentity.GetCurrent())
        {
            current_username = wid.Name;
        }

        if (!ImpersonateLoggedOnUser(targetToken))
        {
            int errorCode = Marshal.GetLastWin32Error();
            throw new Exception("ImpersonateLoggedOnUser failed with the following error: " + errorCode);
        }

        string impersonate_username = "";
        using (WindowsIdentity wid = WindowsIdentity.GetCurrent())
        {
            impersonate_username = wid.Name;
        }

        if (current_username == impersonate_username)
            throw new Exception("ImpersonateLoggedOnUser worked, but thread running as user " + current_username);
    }

    private string hex2Str(string hex)
    {
        byte[] raw = new byte[hex.Length / 2];
        for (int i = 0; i < raw.Length; i++)
        {
            raw[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        }
        return Encoding.ASCII.GetString(raw);
    }

    private string normalizePath(string currPath)
    {
        currPath = currPath.Replace("\"", "");
        currPath = currPath.Replace("'", "");
        currPath = currPath.Replace(@"\", "/");
        return currPath;
    }

    private string changeCWD(string cwd)
    {
        try
        {
            Directory.SetCurrentDirectory(cwd);
            return normalizePath(Directory.GetCurrentDirectory());
        }
        catch (Exception ex)
        {
            if (ex is IOException)
                throw new Exception("Path '" + cwd + "' is not a directory");
            else if (ex is DirectoryNotFoundException)
                throw new Exception("Directory '" + cwd + "' does not exist");
            else if (ex is SecurityException)
                throw new Exception("Directory '" + cwd + "' permission denied");
            else if (ex is PathTooLongException)
                throw new Exception("Path '" + cwd + "' exceed the maximum length defined by the system");
            else
                throw new Exception("Move to path '" + cwd + "' failed");
        }
    }

    private string[] parseArguments(string args)
    {
        List<string> arguments_parsed = new List<string>();
        string pattern = @"""[^""]+""|'[^']+'|\S+";
        foreach (Match m in Regex.Matches(args, pattern))
        {
            arguments_parsed.Add(m.Value);
        }
        return arguments_parsed.ToArray();
    }

    private string FormatAddress(IPAddress address)
    {
        switch (address.AddressFamily)
        {
            case System.Net.Sockets.AddressFamily.InterNetwork:
                return address.ToString();
            case System.Net.Sockets.AddressFamily.InterNetworkV6:
                return "[" + address.ToString() + "]";
            default:
                return address.ToString();
        }
    }

    private void ActiveTcpListeners(List<MyConnection> myconnections)
    {
        IPGlobalProperties properties = IPGlobalProperties.GetIPGlobalProperties();
        IPEndPoint[] endPoints =  properties.GetActiveTcpListeners();
        foreach (IPEndPoint e in endPoints)
        {
            MyConnection myconnection = new MyConnection(
                "tcp",
                FormatAddress(e.Address),
                e.Port,
                Dns.GetHostName(),
                0,
                "Listen"
            );
            myconnections.Add(myconnection);
        }
    }

    private void ActiveTcpConnections(List<MyConnection> myconnections)
    {
        IPGlobalProperties properties = IPGlobalProperties.GetIPGlobalProperties();
        TcpConnectionInformation[] connections = properties.GetActiveTcpConnections();
        foreach (TcpConnectionInformation c in connections)
        {            
            MyConnection myconnection = new MyConnection(
                "tcp",
                FormatAddress(c.LocalEndPoint.Address),
                c.LocalEndPoint.Port,
                FormatAddress(c.RemoteEndPoint.Address),
                c.RemoteEndPoint.Port,
                c.State.ToString()
            );
            myconnections.Add(myconnection);
        }
    }

    private void ActiveUdpListeners(List<MyConnection> myconnections)
    {
        IPGlobalProperties properties = IPGlobalProperties.GetIPGlobalProperties();
        IPEndPoint[] endPoints =  properties.GetActiveUdpListeners();
        foreach (IPEndPoint e in endPoints)
        {
            MyConnection myconnection = new MyConnection(
                "udp",
                FormatAddress(e.Address),
                e.Port,
                FormatAddress(e.Address),
                e.Port,
                "-"
            );
            myconnections.Add(myconnection);
        }
    }

    private string[] doListConnections()
    {
        string result = "";

        try
        {
            result = "Protocol\tLocal address\tRemote address\tState" + Environment.NewLine;
        
            List<MyConnection> myconnections = new List<MyConnection>();
            ActiveTcpListeners(myconnections);
            ActiveTcpConnections(myconnections);
            ActiveUdpListeners(myconnections);

            foreach(MyConnection myconnection in myconnections)
                result += myconnection + Environment.NewLine;
        }
        catch(Exception ex)
        {
            result += ex.ToString() + Environment.NewLine;
            return new string[]{ERR_CODE, result};
        }

        return new string[]{SUCC_CODE, result};
    }

    public string[] execute(string[] args)
    {
        string result = "";		
        List<string> nargs = new List<string>(args);

        if (nargs.Count != 1)
        {
            result = "Invalid arguments provided. Use netstat -[l|a|r]" + Environment.NewLine;
            return new string[]{ERR_CODE, result};
        }

        string option = nargs[0];
        switch (option)
        {
            case "-l":
                return doListConnections();
            case "-a":
                return new string[]{ERR_CODE, "Not implemented yet" + Environment.NewLine};
            case "-r":
                return new string[]{ERR_CODE, "Not implemented yet" + Environment.NewLine};
            default:
                return new string[]{ERR_CODE, "Invalid argument '" + option + "'. Use netstat -[l|a|r]" + Environment.NewLine};
        }
    }

    public string[] go(string cwd, string args, string token)
    {
        string[] results = new string[]{SUCC_CODE, ""};
        string pwd = Directory.GetCurrentDirectory();

        try
        {
            if (token != NON_TOKEN_VALUE)
                ImpersonateWithToken(token);

            string new_cwd = changeCWD(cwd);
            string[] arguments_parsed = parseArguments(hex2Str(args));
            
            results = execute(arguments_parsed);
        }
        catch (Exception ex)
        {
            results[0] = ERR_CODE;
            results[1] = ex.ToString();
        }
        finally
        {
            changeCWD(pwd);
            if (token != NON_TOKEN_VALUE)
                RevertToSelf();
        }
        return results;
    }

    public static void go_dm(string cwd, string args, string token)
    {
        Module_netstat m = new Module_netstat();
        String[] results = m.go(cwd, args, token);
        Console.WriteLine(results[0]);
        Console.WriteLine(results[1]);
        return;
    }

    public static void Main(string[] args)
    {
        Module_netstat m = new Module_netstat();
        String[] results = m.execute(args);
        Console.WriteLine(results[0]);
        Console.WriteLine(results[1]);
        return;
    }
}