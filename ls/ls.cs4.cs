using System;
using System.IO;
using System.Text;
using System.Security;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Runtime.InteropServices;
using System.Security.Principal;


public class Module_ls
{
    public const string SUCC_CODE          = "0";
    public const string ERR_CODE           = "1";
    public const string NON_TOKEN_VALUE    = "0";
    private const string DATE_FORMAT       = "dd/MM/yyyy HH:mm:ss";
    private const string DIRECTORY_SIZE    = "4096 B";
    private const string CURRENT_DIRECTORY = ".";

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

    private string getFilePermissions(string file)
    {
        string permissions = "";

        if (File.Exists(file))
            permissions += "-";
        else if (Directory.Exists(file))
            permissions += "d";
        else
            permissions += "?";

        try
        {
            using (var fs = new FileStream(file, FileMode.Open, FileAccess.Read))
            {
                permissions += "r";
            }
        }
        catch(Exception)
        {
            permissions += "-";
        }

        try
        {
            using (var fs = new FileStream(file, FileMode.Open, FileAccess.ReadWrite))
            {
                permissions += "w";
            }
        }
        catch(Exception)
        {
            permissions += "-";
        }
        return permissions;
    }

    private string getFileOwner(string file)
    {
        try
        {
            return File.GetAccessControl(file).GetOwner(typeof(NTAccount)).ToString();
        }
        catch(Exception)
        {
            return "?";
        }
    }

    private string FormatSize(Int64 bytes)
    {
        string[] suffixes =  { "B", "KB", "MB", "GB", "TB", "PB" };
        int counter = 0;  
        decimal number = (decimal)bytes;  
        while (Math.Round(number / 1024) >= 1)  
        {  
            number = number / 1024;  
            counter++;  
        }  
        return string.Format("{0:n1} {1}", number, suffixes[counter]);
    }

    private string getFileLength(string file)
    {
        try
        {
            if (Directory.Exists(file))
            {
                return DIRECTORY_SIZE;
            }
            else
            {
                FileInfo fi = new FileInfo(file);
                return FormatSize(fi.Length);
            }
        }
        catch(Exception)
        {
            return "?";
        }
    }

    private string getFileLastModified(string file)
    {
        try
        {
            DateTime lastmodified = File.GetLastWriteTime(file);
            return lastmodified.ToString(DATE_FORMAT);
        }
        catch (Exception)
        {
            return "??/??/???? ??:??:??";
        }
    }

    private string doList(string file, bool recursive)
    {
        string result = "";
        List<string> files = new List<string>();
        
        if ((File.Exists(file) == false) && (Directory.Exists(file) == false))
            return "ls: can't access '" + file + "': file or directory does not exist or permission denied" + Environment.NewLine;

        FileAttributes attr = File.GetAttributes(file);
        if ((attr & FileAttributes.Directory) == FileAttributes.Directory)
        {
            string [] subFiles = Directory.GetFiles(file);
            foreach(string subFileName in subFiles)
                if (file == CURRENT_DIRECTORY)
                    files.Add(Path.GetFileName(subFileName));
                else
                    files.Add(file + Path.DirectorySeparatorChar + Path.GetFileName(subFileName));
            
            string [] subDirectories = Directory.GetDirectories(file);
            foreach(string subDirName in subDirectories)
                if (file == CURRENT_DIRECTORY)
                    files.Add(Path.GetFileName(subDirName));
                else
                    files.Add(file + Path.DirectorySeparatorChar + Path.GetFileName(subDirName));
        }
        else
        {
            files.Add(file);
        }

        files.Sort();

        foreach (string f in files)
        {
            string file_permissions = getFilePermissions(f);
            string file_owner = getFileOwner(f);
            string file_length = getFileLength(f);
            string file_last_modified = getFileLastModified(f);
            string file_name = normalizePath(f.Replace(@"/\", "/"));

            result += file_permissions + "\t" + file_owner + "\t" + file_length + "\t" + file_last_modified + "\t" + file_name + Environment.NewLine;

            if (Directory.Exists(f) && recursive)
                result += doList(f, recursive);
        }
        return result;
    }

    public string[] execute(string[] args)
    {
        string result = "";
        bool recursive = false;
        List<string> nargs = new List<string>(args);
        List<string> files = new List<string>();
		
        if (nargs.Count > 0)
        {
            if (nargs[0].Equals("-R"))
            {
                recursive = true;
                files = nargs.GetRange(1, (nargs.Count - 1));
            }
            else
            {
                files = nargs.GetRange(0, nargs.Count);
            }
        }

        if (files.Count == 0)
        {
            files = new List<string>(){ CURRENT_DIRECTORY };
        }

        foreach (string file in files)
        {
            string normalized_path = normalizePath(file);
            result += doList(normalized_path, recursive);
        }

        return new string[]{SUCC_CODE, result};
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
        Module_ls m = new Module_ls();
        String[] results = m.execute(args);
        Console.WriteLine(results[0]);
        Console.WriteLine(results[1]);
        return;
    }
}