#<?php


class Module_ps
{
    private $SUCC_CODE        = 0;
    private $ERR_CODE         = 1;

    private $FIELD_SEPARATOR  = ",";
    private $VALUE_SEPARATOR  = "=";

    private $RESPONSE_STATUS  = "status";
    private $RESPONSE_MESSAGE = "message";

    private $MIN_PID          = 1;
    private $MAX_PID          = 32768;
    private $DATE_FORMAT      = 'd/m/Y-H:i:s';

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

    private function scanDirectory($directory)
    {
        return array_diff(@scandir($directory), array('.', '..'));
    }

    private function isValidPID($pid)
    {
        return ($this->MIN_PID <= intval($pid)) && (intval($pid) <= $this->MAX_PID);
    }

    private function uid2Name($id)
    {
        $user = @posix_getpwuid($id);
        return $user["name"];
    }

    private function jiffies2Seconds($timeval)
    {
        return intval(intval($timeval)/100);
    }

    private function timeElapsed($secs)
    {
        if ($secs === 0)
            return "0s";

        $bit = array(
            'y' => $secs / 31556926 % 12,
            'w' => $secs / 604800 % 52,
            'd' => $secs / 86400 % 7,
            'h' => $secs / 3600 % 24,
            'm' => $secs / 60 % 60,
            's' => $secs % 60
            );
           
        foreach($bit as $k => $v)
            if($v > 0)$ret[] = $v . $k;
           
        return join(' ', $ret);
    }

    private function getValueFromColumn($line, $separator, $column)
    {
        $fields = explode($separator, trim($line));
        if (sizeof($fields) <= $column)
            return null;
        
        return trim($fields[$column]);
    }

    private function processPIDStatusFile($pid)
    {
        $pinfo = array();
        if (@file_exists("/proc/$pid/status") === false)
            return $pinfo;
        
        if (@is_readable("/proc/$pid/status") === false)
            return $pinfo;
        
        $status_content = @file_get_contents("/proc/$pid/status");
        $lines = explode("\n",$status_content);

        foreach ($lines as $line)
        {
            if (strpos($line, "Pid:") === 0)
            {
                $data = $this->getValueFromColumn($line, "\t", 1);
                if ($data !== null)
                    $pinfo["pid"] = $data;
            }
            elseif (strpos($line, "PPid:") === 0)
            {
                $data = $this->getValueFromColumn($line, "\t", 1);
                if ($data !== null)
                    $pinfo["ppid"] = $data;
            }
            elseif (strpos($line, "Uid:") === 0)
            {
                $data = $this->getValueFromColumn($line, "\t", 1);
                if ($data !== null)
                    $pinfo["user"] = $this->uid2Name($data);
            }
            elseif (strpos($line, "VmSize:") === 0)
            {
                $data = $this->getValueFromColumn($line, "\t", 1);
                if ($data !== null)
                    $pinfo["vmsize"] = $data;
            }
            elseif (strpos($line, "VmRSS:") === 0)
            {
                $data = $this->getValueFromColumn($line, "\t", 1);
                if ($data !== null)
                    $pinfo["vmrss"] = $data;
            }
        }
        return $pinfo;
    }

    private function getProcUptime()
    {
        if (@file_exists("/proc/uptime") === false)
            return false;
    
        if (@is_readable("/proc/uptime") === false)
            return false;
        
        $uptime_content = @file_get_contents("/proc/uptime");
        $fields = explode(" ", $uptime_content);

        if (sizeof($fields) < 1)
            return false;

        return intval(trim($fields[0]));
    }

    private function getPidTimes($pid)
    {
        $start_time = false;

        if (@file_exists("/proc/$pid/stat") === false)
            return $start_time;
        
        if (@is_readable("/proc/$pid/stat") === false)
            return $start_time;
        
        $stat_content = @file_get_contents("/proc/$pid/stat");
        $fields = explode(" ",$stat_content);

        if (sizeof($fields) <= 21)
            return $start_time;

        $proc_start_time = $this->jiffies2Seconds($fields[21]);
        $uptime = $this->getProcUptime();
        $timenow = time();
        $result = ($timenow - ($uptime - $proc_start_time));

        $start_time = @date($this->DATE_FORMAT, $result);
        $elapsed_time = $this->timeElapsed($timenow - $result);

        return array(
            "start_time" => $start_time,
            "elapsed_time" => $elapsed_time
        );
    }

    private function getPidBinary($pid)
    {
        if (in_array("exe", $this->scanDirectory("/proc/$pid")) === false)
            return false;

        if(@is_link("/proc/$pid/exe") === false)
            return false;

        if (@is_readable("/proc/$pid/exe") === false)
            return false;

        return @readlink("/proc/$pid/exe");
    }

    private function readBinaryFile($filepath)
    {
        $fd = @fopen($filepath, "rb");
        if ($fd === false)
            return false;

        $data = '';
        while (!@feof($fd))
        {
            $b = @fread($fd, 1);
            if ($b === "\0")
                $data .= " ";
            else
                $data .= $b;
        }
        @fclose($fd);
        return trim($data);
    }

    private function getPidBinaryArgs($pid)
    {
        if(@file_exists("/proc/$pid/cmdline") === false)
            return false;

        if (@is_readable("/proc/$pid/cmdline") === false)
            return false;

        return $this->readBinaryFile("/proc/$pid/cmdline");
    }

    private function getPidLoginUid($pid)
    {
        if (@file_exists("/proc/$pid/loginuid") === false)
            return false;
        
        if (@is_readable("/proc/$pid/loginuid") === false)
            return false;
        
        $uid = @file_get_contents("/proc/$pid/loginuid");
        $username = $this->uid2Name($uid);
        return $username;
    }

    private function getPidTty($pid)
    {
        if(@is_link("/proc/$pid/fd/0") === false)
            return false;

        if (@is_readable("/proc/$pid/fd/0") === false)
            return false;

        $tty = @readlink("/proc/$pid/fd/0");
        if (strpos($tty, "/dev/pts/") !== 0)
            return false;

        return $tty;
    }

    private function parseProcessInfo($pinfo)
    {
        $output = "";

        if (array_key_exists("user", $pinfo) !== false)
            $output .= $pinfo["user"] . "\t";
        else
            $output .= "?" . "\t";

        if (array_key_exists("pid", $pinfo) !== false)
            $output .= $pinfo["pid"] . "\t";
        else
            $output .= "?" . "\t";

        if (array_key_exists("ppid", $pinfo) !== false)
            $output .= $pinfo["ppid"] . "\t";
        else
            $output .= "?" . "\t";

        if (array_key_exists("vmsize", $pinfo) !== false)
            $output .= $pinfo["vmsize"] . "\t";
        else
            $output .= "?" . "\t";

        if (array_key_exists("vmrss", $pinfo) !== false)
            $output .= $pinfo["vmrss"] . "\t";
        else
            $output .= "?" . "\t";

        if (array_key_exists("tty", $pinfo) !== false)
            $output .= $pinfo["tty"] . "\t";
        else
            $output .= "?" . "\t";

        if (array_key_exists("start", $pinfo) !== false)
            $output .= $pinfo["start"] . "\t";
        else
            $output .= "?" . "\t";

        if (array_key_exists("elapsed", $pinfo) !== false)
            $output .= $pinfo["elapsed"] . "\t";
        else
            $output .= "?" . "\t";

        if (array_key_exists("binary_args", $pinfo) !== false)
            $output .= ($pinfo["binary_args"] != "") ? $pinfo["binary_args"] : "?";
        else
            $output .= "?";
        
        return $output;
    }

    private function doListProcesses()
    {
        $result = "USER\tPID\tPPID\tVSZ\tRSS\tTTY\tSTART\tELAPSED\tCOMMAND" . PHP_EOL;
        try
        {
            $files = $this->scanDirectory("/proc");
            sort($files);
            foreach ($files as $file)
            {
                if ($this->isValidPID($file) === false)
                    continue;

                if (@is_dir("/proc/$file") === false)
                    continue;
                
                $pid = $file;

                $pinfo = $this->processPIDStatusFile($pid);
                if (sizeof($pinfo) === 0)
                    continue;

                $pid_binary = $this->getPidBinary($pid);
                if ($pid_binary !== false)
                    $pinfo["binary"] = $pid_binary;

                $pid_binary_args = $this->getPidBinaryArgs($pid);
                if ($pid_binary_args !== false)
                    $pinfo["binary_args"] = $pid_binary_args;

                if (array_key_exists('user', $pinfo) === false)
                {
                    $pid_user = $this->getPidLoginUid($pid);
                    if ($pid_user !== false)
                        $pinfo["user"] = $pid_user;
                }

                $pid_tty = $this->getPidTty($pid);
                if ($pid_tty !== false)
                    $pinfo["tty"] = $pid_tty;
                
                $pid_times = $this->getPidTimes($pid);
                if ($pid_times !== false)
                {
                    $pinfo["start"] = $pid_times["start_time"];
                    $pinfo["elapsed"] = $pid_times["elapsed_time"];
                }
                
                $result .= $this->parseProcessInfo($pinfo) . PHP_EOL;
            }

        }
        catch (Exception $e)
        {
            $result .= $e->getMessage() . PHP_EOL;
        }

        return $result;
    }

    public function execute($args)
    {
        $result = "";

        try
        {
            $parsed_args = $this->parseArgs(hex2bin($args));
            $result = $this->doListProcesses();
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
$module = new Module_ps($cwd);
print($module->execute($args));