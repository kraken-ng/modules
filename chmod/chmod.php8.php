#<?php


class Module_chmod
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

    private function doModify($perms, $files)
    {
        $result = "";

        if (preg_match("/^0[0-7][0-7][0-7]$/", $perms) !== 1)
            throw new Exception("Invalid perms. An octal value preceded by 0 is required");

        foreach ($files as $file)
        {
            try
            {
                $file = $this->normalizePath($file);

                if (@file_exists($file) === false)
                    throw new Exception("chmod: can't perform stat on '$file': File or directory does not exist");

                if (@chmod($file, octdec($perms)) === false)
                    throw new Exception("chmod: changing permissions of '$file': Operation not allowed");

            }
            catch (Exception $e)
            {
                $result .= $e->getMessage() . PHP_EOL;
            }
        }

        return $result;
    }

    public function execute($args)
    {
        $result = "";

        try
        {
            $parsed_args = $this->parseArgs(hex2bin($args));

            if (sizeof($parsed_args) < 2)
                throw new Exception("Invalid arguments provided. Specify one or multiple files to modify");

            $perms = $parsed_args[0];
            $files = array_slice($parsed_args, 1);
            $result = $this->doModify($perms, $files);
  
        }
        catch (Exception $e)
        {
            $result = $e->getMessage() . PHP_EOL;
            $this->return_code = $this->ERR_CODE;
        }

        return $this->generateResponse($result);
    }
}

$cwd = '#{CWD}';
$args = '#{ARGS}';
$module = new Module_chmod($cwd);
print($module->execute($args));