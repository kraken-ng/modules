using System;
using System.IO;
using System.Text;
using System.Security;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Runtime.InteropServices;
using System.Security.Principal;


public class Module_mv
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

    private bool fileOrDirectoryExists(string filepath)
    {
        return (Directory.Exists(filepath) || File.Exists(filepath));
    }

    private string[] doMove(string[] sources, string dest)
    {
        string result = "";

        try
        {
            dest = normalizePath(dest);

            if ((sources.Length > 1) && (Directory.Exists(dest) == false))
                throw new Exception("mv: target '" + dest + "' is not a directory");

            foreach (string fsource in sources)
            {
                string source = normalizePath(fsource);
                if (fileOrDirectoryExists(source) == false)
                {
                    result += "mv: cannot stat '" + source + "': No such file or directory" + Environment.NewLine;
                    continue;
                }

                try
                {
                    if ((File.Exists(source) == true) && (Directory.Exists(dest) == true))
                    {
                        string new_dest = dest + Path.DirectorySeparatorChar + Path.GetFileName(source);
                        File.Move(source, new_dest);
                    }
                    else if ((Directory.Exists(source) == true) && (Directory.Exists(dest) == true))
                    {
                        string new_dest = dest + Path.DirectorySeparatorChar + Path.GetFileName(source);
                        Directory.Move(source, new_dest);
                    }
                    else if ((Directory.Exists(source) == true) && (Directory.Exists(dest) == false))
                    {
                        Directory.Move(source, dest);
                    }
                    else
                    {
                        File.Move(source, dest);
                    }
                }
                catch(Exception ex)
                {
                    result += "mv: cannot move '" + source + "' to '" + dest + "': " + ex.ToString() + Environment.NewLine;
                    continue;
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
		
        if (nargs.Count < 2)
        {
            result = "Invalid arguments provided. Specify a source file or directory to be moved to a destination" + Environment.NewLine;
            return new string[]{ERR_CODE, result};
        }

        string[] sources = nargs.GetRange(0, (nargs.Count - 1)).ToArray();
        string dest = nargs[(nargs.Count - 1)];

        return doMove(sources, dest);
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
        Module_mv m = new Module_mv();
        String[] results = m.execute(args);
        Console.WriteLine(results[0]);
        Console.WriteLine(results[1]);
        return;
    }
}