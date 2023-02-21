#<?php


class Module_cd
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

    private function doChangeDirectory($directory)
    {
        $output = "";

        try
        {
            $directory = $this->normalizePath($directory);

            if (@file_exists($directory) === false)
            {
                throw new Exception("cd: '$directory': File or directory does not exist");
            }

            if (@is_dir($directory) === false)
            {
                throw new Exception("cd: '$directory': Not a directory");
            }

            if (@is_readable($directory) === false)
            {
                throw new Exception("cd: '$directory': Permission denied");
            }

            if (@chdir($directory) === false) {
                throw new Exception("cd: '$directory': Failed");
            }

            $output = $this->normalizePath(getcwd());
        }
        catch (Exception $e)
        {
            $output .= $e->getMessage() . PHP_EOL;
            $this->return_code = $this->ERR_CODE;
        }

        return $output;
    }

    public function execute($args)
    {
        $result = "";
        $parsed_args = $this->parseArgs(hex2bin($args));

        if (sizeof($parsed_args) != 1)
        {
            $result = "Invalid arguments provided. Only one directory is allowed to be moved" . PHP_EOL;
            $this->return_code = $this->ERR_CODE;
        }
        else
        {
            $result .= $this->doChangeDirectory($parsed_args[0]);
        }

        return $this->generateResponse($result);
    }
}


$cwd = '#{CWD}';
$args = '#{ARGS}';
$module = new Module_cd($cwd);
print($module->execute($args));