using System;
using System.IO;
using System.Text;
using System.Security;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Runtime.InteropServices;
using System.Security.Principal;

using System.Net;
using System.Net.Sockets;


public class Module_tcpconnect
{
    public const string SUCC_CODE       = "0";
    public const string ERR_CODE        = "1";
    public const string NON_TOKEN_VALUE = "0";
    public const int MIN_PORT_NUMBER    = 1;
    public const int MAX_PORT_NUMBER    = 65535;
    public const double SOCKET_TIMEOUT  = 0.5;

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

    private bool isNumeric(string s)
    {
        int n;
        return int.TryParse(s, out n);
    }

    private bool IsPortOpen(IPAddress ipaddr, int port, TimeSpan timeout)
    {
        try
        {
            using(TcpClient client = new TcpClient())
            {
                IAsyncResult result = client.BeginConnect(ipaddr, port, null, null);
                bool success = result.AsyncWaitHandle.WaitOne(timeout);
                client.EndConnect(result);
                return success;
            }
        }
        catch
        {
            return false;
        }
    }

    private string[] doTcpConnect(string addr, string port)
    {
        string result = "";
        try
        {
            if (isNumeric(port) == false)
                return new string[]{ERR_CODE, "Invalid port '" + port + "': not a number" + Environment.NewLine};

            int port_val = Int32.Parse(port);
            if (port_val < MIN_PORT_NUMBER || port_val > MAX_PORT_NUMBER)
                return new string[]{ERR_CODE, "Invalid port: '" + port + "'" + Environment.NewLine};

            IPAddress[] ipaddrs;
            try
            {
                ipaddrs = Dns.GetHostAddresses(addr);
            }
            catch(Exception ex)
            {
                return new string[]{ERR_CODE, "Can not GetHostAddresses from '" + addr + "' : " + ex.Message + Environment.NewLine};
            }

            List<string> data = new List<string>();
            foreach(IPAddress ipaddr in ipaddrs)
            {
                string line = "";
                TimeSpan timeout = TimeSpan.FromSeconds(SOCKET_TIMEOUT);
                if (IsPortOpen(ipaddr, port_val, timeout))
                    line = FormatAddress(ipaddr) + ":" + port + " (open)";
                else
                    line = FormatAddress(ipaddr) + ":" + port + " (closed)";
                
                if (data.Contains(line) == false)
                    data.Add(line);
            }

            foreach(string d in data)
                result += d + Environment.NewLine;
            result = result.TrimEnd('\n');
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
        List<string> nargs = new List<string>(args);

        if (nargs.Count != 2)
            return new string[]{ERR_CODE, "Invalid arguments provided. Specify an address and port" + Environment.NewLine};

        return doTcpConnect(nargs[0], nargs[1]);
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

    public static void Main(string[] args)
    {
        Module_tcpconnect m = new Module_tcpconnect();
        String[] results = m.execute(args);
        Console.WriteLine(results[0]);
        Console.WriteLine(results[1]);
        return;
    }
}