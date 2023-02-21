#<?php


class Module_find
{
    private $SUCC_CODE        = 0;
    private $ERR_CODE         = 1;

    private $FIELD_SEPARATOR  = ",";
    private $VALUE_SEPARATOR  = "=";

    private $RESPONSE_STATUS  = "status";
    private $RESPONSE_MESSAGE = "message";

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

    private function matchWithPattern($filename, $pattern)
    {
        $m = @preg_match("/$pattern/", $filename);
        if ($m === false)
            throw new Exception("find: '$pattern': invalid pattern");
        return ($m === 1) ? true : false;
    }

    private function startsWith($haystack, $needle)
    {
        $length = strlen($needle);
        return substr($haystack, 0, $length) === $needle;
    }

    private function endsWith($haystack, $needle)
    {
        $length = strlen( $needle );
        if(!$length)
            return true;
        return substr($haystack, -$length) === $needle;
    }

    private function cleanQuotes($str)
    {
        if ($this->startsWith($str, "'") && $this->endsWith($str, "'"))
            return substr($str, 1, -1);
        return $str;
    }

    private function doFind($path, $pattern, $recursive)
    {
        $output = "";
        
        try 
        {
            $path = $this->normalizePath($path);
            $pattern = $this->cleanQuotes($pattern);

            if (@file_exists($path) === false)
                throw new Exception("find: '$path': No such file or directory");

            if (@is_readable($path) === false)
                throw new Exception("find: '$path': Permission denied");
            
            if ($this->matchWithPattern($path, $pattern))
                $output .= $path . PHP_EOL;

            if (@is_dir($path))
            {
                $fdir = @opendir($path);
                while (false !== ($entry = @readdir($fdir)))
                {
                    if ($entry === "." || $entry === "..")
                        continue;

                    $complete_filepath = $path . DIRECTORY_SEPARATOR  . $entry;
                    if ($this->matchWithPattern($entry, $pattern))
                        $output .= $complete_filepath . PHP_EOL;
                    
                    if (@is_dir($complete_filepath) && $recursive)
                        $output .= $this->doFind($complete_filepath, $pattern, $recursive);
                }
                @closedir($fdir);
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
        $pattern = "";
        $paths = array();

        $parsed_args = $this->parseArgs(hex2bin($args));

        if (sizeof($parsed_args) < 2)
        {
            $result = "Invalid arguments provided. Specify a pattern and one or multiple to search";
            $this->return_code = $this->ERR_CODE;
        }
        else
        {
            if (($parsed_args[0] === "-R") && (sizeof($parsed_args) === 2))
            {
                $result = "Invalid arguments provided. Specify a multiple to search";
                $this->return_code = $this->ERR_CODE;
            }
            elseif (($parsed_args[0] === "-R") && (sizeof($parsed_args) > 2))
            {
                $recursive = true;
                $pattern = $parsed_args[1];
                $paths = array_slice($parsed_args, 2);
            }
            else
            {
                $pattern = $parsed_args[0];
                $paths = array_slice($parsed_args, 1);
            }
        }

        foreach ($paths as $path)
        {    
            $result .= $this->doFind($path, $pattern, $recursive);
        }

        return $this->generateResponse($result);
    }
}


$cwd = '#{CWD}';
$args = '#{ARGS}';
$module = new Module_find($cwd);
print($module->execute($args));