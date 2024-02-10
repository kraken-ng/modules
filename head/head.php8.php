#<?php


class Module_head
{
    private $SUCC_CODE        = 0;
    private $ERR_CODE         = 1;

    private $FIELD_SEPARATOR  = ",";
    private $VALUE_SEPARATOR  = "=";

    private $RESPONSE_STATUS  = "status";
    private $RESPONSE_MESSAGE = "message";

    private $DEFAULT_LINES    = 10;

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

    private function doHead($numLines, $file)
    {
        $result = "";

        if (!@file_exists($file))
            return "head: $file: No such file or directory" . PHP_EOL;

        if (!@is_readable($file))
            return "head: $file: Permission denied" . PHP_EOL;

        if (@is_dir($file))
            return "head: $file: Is a directory" . PHP_EOL;

        if (!$this->isTextFile($file))
            return "head: '$file': Is not ASCII file" . PHP_EOL;

        $handle = @fopen($file, "r");
        if ($handle === false)
            return "head: '$file': Can't read it" . PHP_EOL;

        $lineNum = 1;
        while (($line = fgets($handle)) !== false && $lineNum <= $numLines)
        {
            $result .= $line;
            $lineNum++;
        }
        fclose($handle);

        return $result;
    }

    public function execute($args)
    {
        try
        {
            $result = "";
            $parsed_args = $this->parseArgs(hex2bin($args));
            
            if (sizeof($parsed_args) < 1)
                throw new Exception("Invalid arguments provided. Specify a file/s to be readed");

            if (($parsed_args[0] === "-n") && (sizeof($parsed_args) < 3))
                throw new Exception("Invalid arguments provided. You should specify number of lines and file/s to be readed");

            $num_lines = $this->DEFAULT_LINES;
            $files = array();
            $multiple = false;
            if ($parsed_args[0] === "-n")
            {
                if (!@is_numeric($parsed_args[1]))
                    throw new Exception("invalid num of lines '".$parsed_args[1]."': not a number");

                $num_lines = @intval($parsed_args[1]);
                $files = array_slice($parsed_args, 2);
            }
            else
            {
                $files = $parsed_args;
            }

            if (sizeof($files) > 1)
                $multiple = true;
            
            foreach ($files as $file)
            {
                if ($multiple)
                    $result .= "==>$file<==" . PHP_EOL;
                
                $result .= $this->doHead($num_lines, $file) . PHP_EOL;
            }

            return $this->generateResponse($result);
        }
        catch (Exception $e)
        {
            $this->return_code = $this->ERR_CODE;
            return $this->generateResponse($e->getMessage() . PHP_EOL);
        }

    }
}

$cwd = '#{CWD}';
$args = '#{ARGS}';
$module = new Module_head($cwd);
print($module->execute($args));
