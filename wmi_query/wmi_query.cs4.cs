using System;
using System.IO;
using System.Text;
using System.Security;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Runtime.InteropServices;
using System.Security.Principal;

using System.Management;


public class Module_wmi_query
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

    private List<string> getHeadersFromQuery(ManagementObjectCollection queryCollection)
    {
        List<string> header = new List<string>();
        foreach (ManagementObject mObj in queryCollection)
        {
            if (mObj.Properties.Count == 0)
                continue;
            
            foreach (PropertyData pData in mObj.Properties)
                header.Add(pData.Name);

            break;
        }
        
        if (header.Count == 0)
            throw new Exception("Query dont return any results");
        
        return header;
    }

    private string joinList(List<string> list, string separator)
    {
        StringBuilder sb = new StringBuilder();

        for (int i = 0; i < list.Count; i++)
        {
            sb.Append(list[i]);

            if (i < list.Count - 1)
            {
                sb.Append(separator);
            }
        }

        return sb.ToString();
    }

    private string[] doWmiQuery(string wmiQuery, List<string> wmiFields)
    {
        string result = "";

        try
        {
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(wmiQuery);
            ManagementObjectCollection queryCollection = searcher.Get();

            List<string> all_headers = getHeadersFromQuery(queryCollection);
            List<string> header     = new List<string>();
            
            if (wmiFields.Count > 0)
            {
                foreach(string wmiField in wmiFields)
                {
                    if (all_headers.Contains(wmiField) == false)
                    {
                        throw new Exception("Field '" + wmiField + "' not exists in response");
                    }
                    else
                    {
                        header.Add(wmiField);
                    }
                }
            }
            else
            {
                header = all_headers;
            }
            
            result += joinList(header, "\t") + Environment.NewLine;

            foreach (ManagementObject mObj in queryCollection)
            {
                List<string> rows = new List<string>();
                foreach (string headerCol in header)
                {
                    if (mObj[headerCol] != null)
                        rows.Add(mObj[headerCol].ToString());
                    else
                        rows.Add("-");
                }
                result += joinList(rows, "\t") + Environment.NewLine;
            }
        }
        catch (Exception ex)
        {
            result = "Query: '" + wmiQuery + "' failed. Reason: " + ex.Message + Environment.NewLine;
            return new string[] { ERR_CODE, result };
        }

        return new string[] { SUCC_CODE, result };
    }

    public string[] execute(string[] args)
    {
        string result = "";
        List<string> nargs = new List<string>(args);

        if (nargs.Count < 1)
        {
            result = "Invalid arguments provided. Specify a query to be performed" + nargs.Count + Environment.NewLine;
            return new string[]{ERR_CODE, result};
        }

        string wmiQuery        = nargs[0].Replace("'", "");
        List<string> wmiFields = new List<string>();

        if (nargs.Count > 1)
        {
            wmiFields = nargs.GetRange(1, (nargs.Count - 1));
        }

        return doWmiQuery(wmiQuery, wmiFields);
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
        Module_wmi_query m = new Module_wmi_query();
        String[] results = m.go(cwd, args, token);
        Console.WriteLine(results[0]);
        Console.WriteLine(results[1]);
        return;
    }

    public static void Main(string[] args)
    {
        Module_wmi_query m = new Module_wmi_query();
        String[] results = m.execute(args);
        Console.WriteLine(results[0]);
        Console.WriteLine(results[1]);
        return;
    }
}
