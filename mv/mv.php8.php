#<?php


class Module_mv
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

    private function doMove($sources, $dest)
    {
        $result = "";

        try
        {
            $dest = $this->normalizePath($dest);

            if ((sizeof($sources) > 1) && (@is_dir($dest) === false))
            {
                throw new Exception("mv: target '$dest' is not a directory", 1);
            }

            foreach ($sources as $source)
            {
                $source = $this->normalizePath($source);
                if (@file_exists($source) === false)
                {
                    $result .= "mv: cannot stat '$source': No such file or directory" . PHP_EOL;
                    continue;
                }

                if ((@file_exists($dest) === true) && (@is_dir($dest) === true))
                {
                    $dest_expand = $dest . DIRECTORY_SEPARATOR . basename($source);
                    if (@rename($source, $dest_expand) === false)
                    {
                        $result .= "mv: cannot move '$source' to '$dest_expand': Failed" . PHP_EOL;
                        continue;
                    }
                }
                else
                {
                    if (@rename($source, $dest) === false)
                    {
                        $result .= "mv: cannot move '$source' to '$dest': Failed" . PHP_EOL;
                        continue;
                    }
                }
            }
        }
        catch (Exception $e)
        {
            $result .= $e->getMessage() . PHP_EOL;
            $this->return_code = $this->ERR_CODE;
        }

        return $result;
    }

    public function execute($args)
    {
        $result = "";

        $parsed_args = $this->parseArgs(hex2bin($args));

        if (sizeof($parsed_args) < 2)
        {
            $result = "Invalid arguments provided. Specify a source file or directory to be moved to a destination" . PHP_EOL;
            $this->return_code = $this->ERR_CODE;
        }
        else
        {
            $sources = array_slice($parsed_args, 0, -1);
            $dest    = end($parsed_args);
            $result .= $this->doMove($sources, $dest);
        }
        return $this->generateResponse($result);
    }
}


$cwd = '#{CWD}';
$args = '#{ARGS}';
$module = new Module_mv($cwd);
print($module->execute($args));
