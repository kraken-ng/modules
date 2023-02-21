#<?php


class Module_ls
{
    private $SUCC_CODE        = 0;
    private $ERR_CODE         = 1;

    private $FIELD_SEPARATOR  = ",";
    private $VALUE_SEPARATOR  = "=";

    private $RESPONSE_STATUS  = "status";
    private $RESPONSE_MESSAGE = "message";

    private $CURRENT_DIR      = ".";
    private $PREVIOUS_DIR     = "..";
    private $DATE_FORMAT      = "Y/m/d H:i:s";

    private $return_code;

    public function __construct($cwd)
    {
        $this->return_code = $this->SUCC_CODE;
        $cwd = $this->normalizePath($cwd);
        chdir($cwd);
    }

    private function normalizePath($currPath)
    {
        $currPath = str_replace("\"", "", $currPath);
        $currPath = str_replace("'", "", $currPath);
        $currPath = str_replace("\\", "/", $currPath);
        return $currPath;
    }

    private function parseArgs($args)
    {
        preg_match_all('/"[^"]+"|\'[^\']+\'|\S+/', $args, $matches);
        return $matches[0];
    }

    private function generateResponse($result)
    {
        $response  = "";
        $response .= $this->RESPONSE_STATUS . $this->VALUE_SEPARATOR . $this->return_code;
        $response .= $this->FIELD_SEPARATOR;
        $response .= $this->RESPONSE_MESSAGE . $this->VALUE_SEPARATOR . bin2hex($result);
        return bin2hex($response);
    }

    private function endsWith($haystack, $needle)
    {
        $length = strlen($needle);
        if(!$length)
            return true;
        return substr($haystack, -$length) === $needle;
    }

    private function get_file_permissions($filepath)
    {
        $perms = @fileperms($filepath);

        switch ($perms & 0xF000)
        {
            case 0xC000: // Socket
                $info = 's';
                break;
            case 0xA000: // Symbolic link
                $info = 'l';
                break;
            case 0x8000: // Readable
                $info = '-';
                break;
            case 0x6000: // Special block
                $info = 'b';
                break;
            case 0x4000: // Directory
                $info = 'd';
                break;
            case 0x2000: // Special character
                $info = 'c';
                break;
            case 0x1000: // FIFO pipe
                $info = 'p';
                break;
            default: // Unknown
                $info = 'u';
        }
        
        // Owner
        $info .= (($perms & 0x0100) ? 'r' : '-');
        $info .= (($perms & 0x0080) ? 'w' : '-');
        $info .= (($perms & 0x0040) ?
                    (($perms & 0x0800) ? 's' : 'x' ) :
                    (($perms & 0x0800) ? 'S' : '-'));
        
        // Group
        $info .= (($perms & 0x0020) ? 'r' : '-');
        $info .= (($perms & 0x0010) ? 'w' : '-');
        $info .= (($perms & 0x0008) ?
                    (($perms & 0x0400) ? 's' : 'x' ) :
                    (($perms & 0x0400) ? 'S' : '-'));
        
        // Others
        $info .= (($perms & 0x0004) ? 'r' : '-');
        $info .= (($perms & 0x0002) ? 'w' : '-');
        $info .= (($perms & 0x0001) ?
                    (($perms & 0x0200) ? 't' : 'x' ) :
                    (($perms & 0x0200) ? 'T' : '-'));
        return $info;
    }

    private function get_file_num_links($filepath)
    {
        $stats = @stat($filepath);
        if ($stats === false)
            return "?";
        return $stats["nlink"];
    }

    private function get_file_owner($filepath)
    {
        $phpuname_fields = explode(" ", php_uname());
        if ($phpuname_fields[0] === "Windows")
            return "?";
        
        $user = @posix_getpwuid(@fileowner($filepath));
        if ($user === false)
            return @fileowner($filepath);
        return $user["name"];
    }

    private function get_file_group($filepath)
    {
        $phpuname_fields = explode(" ", php_uname());
        if ($phpuname_fields[0] === "Windows")
            return "?";
        
        $group = @posix_getgrgid(@filegroup($filepath));
        if ($group === false)
            return @filegroup($filepath);
        return $group["name"];
    }

    private function get_file_size($filepath)
    {
        $file_size = @filesize($filepath);
        if ($file_size === false)
            return "?";
        return $file_size;
    }

    private function get_file_last_modified($filepath)
    {
        $filemtime = @filemtime($filepath);
        if ($filemtime === false)
            return "?";
        return @date($this->DATE_FORMAT, $filemtime);
    }

    private function get_file_path($filepath, $absolute)
    {
        if ($absolute)
        {
            return $filepath;
        }
        else
        {
            $parts = explode(DIRECTORY_SEPARATOR, $filepath);
            return end($parts);
        }
    }

    private function doList($filepath, $recursive)
    {
        $output = "";
        $files = array();

        try 
        {
            $filepath = $this->normalizePath($filepath);

            if (@file_exists($filepath) === false)
                throw new Exception("ls: can't access '$filepath': file or directory does not exist");

            if (@is_readable($filepath) === false)
                throw new Exception("ls: can't open directory '$filepath': Permission denied");
            
            if (@is_dir($filepath))
            {
                $fdir = @opendir($filepath);
                while (false !== ($entry = @readdir($fdir)))
                    array_push($files, $filepath . DIRECTORY_SEPARATOR  . $entry);
                @closedir($fdir);

            }
            else
            {
                array_push($files, $filepath);
            }

            sort($files);

            foreach ($files as &$file)
            {
                try 
                {
                    $perms = $this->get_file_permissions($file);
                    $num = $this->get_file_num_links($file);
                    $owner = $this->get_file_owner($file);
                    $group = $this->get_file_group($file);
                    $size = $this->get_file_size($file);
                    $last_mod = $this->get_file_last_modified($file);
                    $name = $this->get_file_path($file, $recursive);

                    $output .= "$perms\t$num\t$owner\t$group\t$size\t$last_mod\t$name" . PHP_EOL;

                    if ($this->endsWith($file, DIRECTORY_SEPARATOR . $this->CURRENT_DIR) || $this->endsWith($file, DIRECTORY_SEPARATOR . $this->PREVIOUS_DIR))
                        continue;

                    if ($recursive && @is_dir($file))
                        $output .= $this->doList($file, $recursive);
                }
                catch (Exception $e)
                {
                    continue;
                }
            }
        }
        catch (Exception $e)
        {
            $output .= $e->getMessage() . PHP_EOL;
        }

        return $output;
    }


    public function execute($args)
    {
        $result = "";
        $recursive = false;
        $files = array();

        $parsed_args = $this->parseArgs(hex2bin($args));

        if (sizeof($parsed_args) > 0)
        {
            if ($parsed_args[0] === "-R")
            {
                $recursive = true;
                $files = array_slice($parsed_args, 1);
            }
            else
            {
                $files = array_slice($parsed_args, 0);
            }
        }

        if (sizeof($files) === 0)
        {
            $files[] = $this->CURRENT_DIR;
        }

        foreach ($files as $file)
        {    
            $result .= $this->doList($file, $recursive);
        }

        return $this->generateResponse($result);
    }
}


$cwd = '#{CWD}';
$args = '#{ARGS}';
$module = new Module_ls($cwd);
print($module->execute($args));