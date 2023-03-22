import java.io.*;
import java.util.*;
import java.text.*;
import java.util.regex.*;


public class Module_execute
{
    private String cwd = System.getProperty("user.dir");
    private final String SUCC_CODE              = "0";
    private final String ERR_CODE               = "1";
    private final String DEFAULT_EMPTY_EXECUTOR = "-";
    private final String DEFAULT_WIN_EXECUTOR   = "cmd.exe";
    private final String JAVA_EOL               = getLineSeparator();

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

    private String getOS()
    {
        String OS = System.getProperty("os.name").toLowerCase();
        if (OS.contains("win"))
            return "Windows";
        if (OS.contains("nix") || OS.contains("nux") || OS.contains("aix"))
            return "Unix";
        return OS;
    }

    private String[] executeWithProcessBuilder(List<String> command)
    {
        String result = "";
        String return_code = SUCC_CODE;

        try
        {                 
            ProcessBuilder processBuilder = new ProcessBuilder();
            processBuilder.command(command);
            processBuilder.redirectErrorStream(true);
            Process process = processBuilder.start();

            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line = "";
            String stdout = "";
            while ((line = reader.readLine()) != null)
                stdout += line + JAVA_EOL;
            
            line = "";
            String stderr = "";
            reader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
            while ((line = reader.readLine()) != null)
                stderr += line + JAVA_EOL;

            int return_value = process.waitFor();
            if (return_value != 0)
                return_code = ERR_CODE;

            if (stdout.length() > 0 && stderr.length() == 0)
                result = stdout;
            else if (stderr.length() > 0 && stdout.length() == 0)
                result = stderr;
            else if (stdout.length() > 0 && stderr.length() > 0)
                result = stdout + JAVA_EOL + stderr;
        }
        catch(Exception ex)
        {
            return new String[]{ERR_CODE, "execute: Failed '" + ex.getMessage() + "'" + JAVA_EOL};
        }

        return new String[]{return_code, result};
    }

    private String[] doExecute(String executor, String[] arguments)
    {
        try 
        {
            List<String> commands = new ArrayList<String>();
            String current_os = getOS();

            if (current_os.equals("Windows"))
            {
                if (executor.equals(DEFAULT_EMPTY_EXECUTOR))
                {
                    commands.add(DEFAULT_WIN_EXECUTOR);
                    commands.add("/c");
                    for (String arg : arguments)
                        commands.add(arg);
                }
                else
                {
                    commands.add(executor);
                    for (String arg : arguments)
                        commands.add(arg);
                }
            }
            else if (current_os.equals("Unix"))
            {
                if (executor.equals(DEFAULT_EMPTY_EXECUTOR))
                {
                    for (String arg : arguments)
                        commands.add(arg);
                }
                else
                {
                    commands.add(executor);
                    for (String arg : arguments)
                        commands.add(arg);
                }
            }
            else
            {
                return new String[]{ERR_CODE, "Insupported platform: '" + current_os + "'" + JAVA_EOL};
            }
            return executeWithProcessBuilder(commands);
        }
        catch(Exception ex)
        {
            return new String[]{ERR_CODE, "execute: " + ex.getMessage() + JAVA_EOL};
        }
    }

    public String[] execute(String[] args)
    {
        String[] commands = new String[]{};
        
        if (args.length < 1)
            return new String[]{ERR_CODE, "Invalid arguments provided. Specify one or multiple commands" + JAVA_EOL};

        if (args.length > 1)
            commands = Arrays.copyOfRange(args, 1, args.length);

        return doExecute(args[0], commands);
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
        Module_execute m = new Module_execute();
        String[] results = m.execute(args);
        System.out.println(results[1]);
        return;
    }
}