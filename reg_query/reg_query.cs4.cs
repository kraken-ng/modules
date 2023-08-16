using System;
using System.IO;
using System.Text;
using System.Security;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Runtime.InteropServices;
using System.Security.Principal;

using Microsoft.Win32;


public class Module_reg_query
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

    public enum ROOT_KEY : uint
    {
        HKEY_CLASSES_ROOT      = 0x80000000,
        HKEY_CURRENT_USER      = 0x80000001,
        HKEY_LOCAL_MACHINE     = 0x80000002,
        HKEY_USERS             = 0x80000003,
        HKEY_PERFORMANCE_DATA  = 0x80000004,
        HKEY_CURRENT_CONFIG    = 0x80000005,
        HKEY_DYN_DATA          = 0x80000006
    }

    private string[] doRegQuery(string rootKeyStr, string subKeyStr, string[] valuesStr)
    {
        string result = "";

        try
        {
            ROOT_KEY rootKey;
            switch (rootKeyStr.ToUpper())
            {
                case "HKCR":
                case "HKEY_CLASSES_ROOT":
                    rootKey = ROOT_KEY.HKEY_CLASSES_ROOT;
                    break;
                case "HKCU":
                case "HKEY_CURRENT_USER":
                    rootKey = ROOT_KEY.HKEY_CURRENT_USER;
                    break;
                case "HKLM":
                case "HKEY_LOCAL_MACHINE":
                    rootKey = ROOT_KEY.HKEY_LOCAL_MACHINE;
                    break;
                case "HKU":
                case "HKEY_USERS":
                    rootKey = ROOT_KEY.HKEY_USERS;
                    break;
                case "HKEY_PERFORMANCE_DATA":
                    rootKey = ROOT_KEY.HKEY_PERFORMANCE_DATA;
                    break;
                case "HKEY_CURRENT_CONFIG":
                    rootKey = ROOT_KEY.HKEY_CURRENT_CONFIG;
                    break;
                case "HKEY_DYN_DATA":
                    rootKey = ROOT_KEY.HKEY_DYN_DATA;
                    break;
                default:
                    throw new Exception("Invalid root key: '" + rootKeyStr + "'");
            }

            RegistryKey regKey = RegistryKey.OpenBaseKey((RegistryHive)rootKey, RegistryView.Default);
            using (regKey)
            {
                RegistryKey regSubKey = regKey.OpenSubKey(subKeyStr);
                if (regSubKey == null)
                    throw new Exception("Invalid sub key: '" + subKeyStr + "' not found");
                
                if (valuesStr.Length == 0)
                {
                    result += "Type\tName" + Environment.NewLine;

                    string[] subKeyNames = regSubKey.GetSubKeyNames();
                    foreach(string subKeyName in subKeyNames)
                    {
                        result += "SubKey" + "\t" + subKeyName + Environment.NewLine;
                    }

                    string[] subValuesNames = regSubKey.GetValueNames();
                    foreach(string subValuesName in subValuesNames)
                    {
                        result += "Value" + "\t" + subValuesName + Environment.NewLine;
                    }
                }
                else
                {
                    foreach(string valueStr in valuesStr)
                    {
                        object regValue = regSubKey.GetValue(valueStr);
                        if (regValue == null)
                        {
                            result += "[!] Invalid value: '" + valueStr + "' not found or denied";
                            continue;
                        }
                        
                        result += regValue.ToString() + Environment.NewLine;
                    }
                }
            }
        }
        catch (Exception ex)
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

        if (nargs.Count < 2)
        {
            result = "Invalid arguments provided. Specify a root key and registry key to be queried" + Environment.NewLine;
            return new string[]{ERR_CODE, result};
        }

        string rootKeyStr   = "";
        string subKeyStr    = "";
        List<string> values = new List<string>();
        
        if (nargs.Count > 2)
        {
            rootKeyStr = nargs[0];
            subKeyStr  = nargs[1];
            values     = nargs.GetRange(2, (nargs.Count - 2));
        }
        else
        {
            rootKeyStr = nargs[0];
            subKeyStr  = nargs[1];
        }

        return doRegQuery(rootKeyStr, subKeyStr, values.ToArray());
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
        Module_reg_query m = new Module_reg_query();
        String[] results = m.go(cwd, args, token);
        Console.WriteLine(results[0]);
        Console.WriteLine(results[1]);
        return;
    }

    public static void Main(string[] args)
    {
        Module_reg_query m = new Module_reg_query();
        String[] results = m.execute(args);
        Console.WriteLine(results[0]);
        Console.WriteLine(results[1]);
        return;
    }
}