<?php

class test {
    /**
     * 测试苹果消息推送服务
     */
    public function testPushEventService()
    {
//        var_dump($deviceNumber = '3F80A943-43A4-4B2F-938F-B0B3548A62DE');exit;
//        var_dump($this->account['default']['token']);exit;
        // 1 + 2 + 36 + 2 (payload 长度)
        $message = 'AAAg1qNyhaWfLC9Bz0iOmuyCzEVJsUyFUhwSvh85u9ThWQEDdXsiYXBzIjp7ImFsZXJ0Ijp7InRpdGxlIjoiZmFuZy5saXUiLCJib2R5IjoiMjAyMC0wOC0wOSAyMToyMToyNy17XCJjb252ZXJzYXRpb25fdHlwZVwiIn0sInNvdW5kIjoiZGVmYXVsdCIsImJhZGdlIjoxLCJ1c2VyaW5mbyI6IntcImNvbnZlcnNhdGlvbl90eXBlXCI6XCJDMkNcIixcInR5cGVcIjozLFwicGF5bG9hZFwiOntcImNvbnRlbnRcIjp7XCJub3RpY2VcIjp7XCJ0eXBlXCI6MSxcInRpdGxlXCI6XCJcXHU3MjNiXFx1NGZlMVYxLjNcXHU0ZTBhXFx1N2ViZlwiLFwiYWJzdHJhY3RcIjpcIlxcdTcyM2JcXHU0ZmUxVjEuM1xcdTRlMGFcXHU3ZWJmXFx1NTU2NlwiLFwiY29udGVudFwiOlwiPHA+XFx1NzIzYlxcdTRmZTFWMS4zXFx1NGUwYVxcdTdlYmZcXHU1NTY2XFx1ZmYwY1xcdTZiMjJcXHU4ZmNlXFx1NTkyN1xcdTViYjZcXHU0ZjUzXFx1OWE4Y35+fn5+PFxcXC9wPlwiLFwiZGV0YWlsX3VybFwiOlwiaHR0cDpcXFwvXFxcL3dlYi1hcGktMS55YW94aW4uY29cXFwvaFxcXC9hcHAtaDVcXFwvI1xcXC9wYWdlc1xcXC9wdXNoTXNnXFxcL3B1c2hNc2c/bm90aWNlX2lkPTc1XCJ9fSxcIm1lc3NhZ2VfdHlwZVwiOjIwMCxcInNlbmRfdGltZVwiOlwiMTU5MjAzNDAxNDAwMFwiLFwibmlja25hbWVcIjpcIlxcdTcyM2JcXHU0ZmUxXFx1NWMwZlxcdTUyYTlcXHU2MjRiXCIsXCJhdmF0YXJcIjpcImh0dHA6XFxcL1xcXC95YW94aW4tcmVzLm9zcy1jbi1zaGVuemhlbi5hbGl5dW5jcy5jb21cXFwvdXNlclxcXC9hdmF0YXJcXFwvZGRcXFwvNzRcXFwvMjNcXFwvZGQ3NDIzYjcxOWI5YmZkNjVkNDhiMzU1ZGEyYzIxYjUuanBnXCJ9LFwiZnJvbVwiOlwiMDc4ODg4Njk1XCIsXCJ0b1wiOlwiODQzNjQ2NjIyXCIsXCJpZFwiOlwiNWVlNDgzMGQ4MjE4ZVwifSJ9fQ==';
        $message = base64_decode($message);
        var_dump($message);
        var_dump("data len: " . strlen($message));
        ob_flush();
        $socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
        socket_connect($socket, '127.0.0.1', 8443);
        for($i=1; $i<200; $i++) {
            $this->fwrite_stream($socket, $message);
           // break;
        }

        $this->read_stream($socket);
        exit('test');
    }

    function fwrite_stream($fp, $string) {
        for ($written = 0; $written < strlen($string); $written += $fwrite) {
            $str = substr($string, $written);
            $fwrite = socket_send($fp, $str, strlen($str), MSG_DONTROUTE);
            if ($fwrite === false) {
                return $written;
            }
        }
        return $written;
    }

    function read_stream($fp)
    {
        do {
            $str  = socket_read($fp, 1024);
            var_dump($str);
        } while(strlen($str)>0);

    }
}

(new \test())->testPushEventService();