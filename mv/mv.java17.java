import java.io.*;
import java.util.*;
import java.text.*;
import java.util.regex.*;


public class Module_mv
{
    private String cwd = System.getProperty("user.dir");
    private final String SUCC_CODE = "0";
    private final String ERR_CODE  = "1";
    private final String JAVA_EOL  = getLineSeparator();

    private String getLineSeparator()
    {
        String os_name = System.getProperty("os.name");
        if (os_name.startsWith("Windows"))
            return "\r\n";
        else
            return "\n";
    }

    private byte[] hex2bin(String data) throws Exception
    {
        if ((data.length() % 2) == 1)
            throw new Exception("hex2bin(): data cannot have an odd number of digits");
        
        byte[] data_bytes = new byte[data.length() / 2];
        for (int i = 0; i < data.length(); i += 2)
        {
            String hs = data.substring(i, i + 2);
            try
            {
                int val = Integer.parseInt(hs, 16);
                data_bytes[i/2] = (byte)val;
            }
            catch(Exception e)
            {
                throw new Exception("hex2bin() failed to convert hex:'" + hs + "' to byte");
            }
        }
        return data_bytes;
    }

    private String bin2hex(byte[] ba) throws Exception
    {
        try
        {
            StringBuilder sb = new StringBuilder(ba.length * 2);
            for (byte b: ba)
                sb.append(String.format("%02x", b));
            return sb.toString();
        }
        catch(Exception e)
        {
            throw new Exception("bin2hex() failed");
        }
    }

    private String hex2str(String data) throws Exception
    {
        byte[] data_bytes = hex2bin(data);
        String data_string = new String(data_bytes);
        return data_string;
    }

    private String sanitizePath(String currPath)
    {
        currPath = currPath.replace("\"", "");
        currPath = currPath.replace("'", "");
        currPath = currPath.replace("\\", "/");
        return currPath;
    }

    private String normalizePath(String currPath) throws IOException
    {
        currPath = sanitizePath(currPath);

        File filepath = new File(currPath);
        if (filepath.isAbsolute())
        {
            return filepath.getCanonicalPath();
        }
        else
        {
            File new_filepath = new File(this.cwd + File.separator + currPath);
            return new_filepath.getCanonicalPath();
        }
    }

    private String[] parseArgs(String args)
    {
        String regex = "\"[^\"]+\"|'[^']+'|\\S+";
        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(args);
        List<String> arguments = new ArrayList<String>();

        while (matcher.find())
            arguments.add(matcher.group(0));

        String[] arguments_arr = new String[arguments.size()];
        arguments_arr = arguments.toArray(arguments_arr);
        return arguments_arr;
    }

    private String changeCWD(String cwd) throws Exception
    {
        File target_dir = new File(cwd).getAbsoluteFile();

        if (target_dir.exists() == false)
            throw new Exception("Directory: '" + cwd + "': does not exist");

        if (target_dir.canRead() == false)
            throw new Exception("Can't move to path: '" + cwd + "': permission denied");

        if (target_dir.isDirectory() == false)
            throw new Exception("Path: '" + cwd + "': is not a directory");

        System.setProperty("user.dir", target_dir.getCanonicalPath());

        return sanitizePath(target_dir.getCanonicalPath());
    }

    private String[] doMove(String[] sources, String dest)
    {
        String result = "";
        try
        {
            dest = normalizePath(dest);
            File dest_file = new File(dest).getAbsoluteFile();
            if ((sources.length > 1) && (dest_file.isDirectory() == false))
                throw new Exception("mv: target '" + dest + "' is not a directory");
            
            for (String source : sources)
            {
                source = normalizePath(source);
                File source_file = new File(source);
                if (source_file.exists() == false)
                {
                    result += "mv: cannot stat '" + source + "': No such file or directory" + JAVA_EOL;
                    continue;
                }

                if ((dest_file.exists() == true) && (dest_file.isDirectory() == true))
                {
                    File new_dest_file = new File(dest + File.separator + source_file.getName());
                    if(source_file.renameTo(new_dest_file) == false)
                    {
                        result += "mv: cannot move '" + source + "' to '" + dest + "': Failed" + JAVA_EOL;
                        continue;
                    }

                    source_file.delete();
                }
                else
                {
                    if(source_file.renameTo(dest_file) == false)
                    {
                        result += "mv: cannot move '" + source + "' to '" + dest + "': Failed" + JAVA_EOL;
                        continue;
                    }

                    source_file.delete();
                }
            }
        }
        catch(Exception ex)
        {
            return new String[]{ERR_CODE, ex.getMessage() + JAVA_EOL};
        }
        return new String[]{SUCC_CODE, result};
    }

    public String[] execute(String[] args)
    {        
        if (args.length < 2)
            return new String[]{ERR_CODE, "Invalid arguments provided. Specify a source file or directory to be moved to a destination" + JAVA_EOL};
        
        String[] sources = Arrays.copyOfRange(args, 0, (args.length - 1));
        String dest      = args[(args.length - 1)];

        return doMove(sources, dest);
    }

    public String[] go(String module_cwd, String module_args)
    {
        try
        {
            this.cwd = changeCWD(hex2str(module_cwd));
            String[] args = parseArgs(hex2str(module_args));
            return execute(args);
        }
        catch(Exception ex)
        {
            return new String[]{ERR_CODE, ex.getMessage() + JAVA_EOL};
        }
    }

    public static void main(String[] args)
    {
        Module_mv m = new Module_mv();
        String[] results = m.execute(args);
        System.out.println(results[1]);
        return;
    }
}