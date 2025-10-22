The `slowhttptest` tool is a standard package on Kali Linux. Here is a guide on how to install, run, and configure it.

## 🛠️ Installation on Kali Linux

You can install `slowhttptest` using the standard Advanced Packaging Tool (`apt`):

1.  **Update your package lists:**
    ```bash
    sudo apt update
    ```
2.  **Install the tool:**
    ```bash
    sudo apt install slowhttptest
    ```

-----

## 🚀 How to Run and Configure (`slowhttptest` Usage)

The tool works by simulating different types of low-bandwidth Denial of Service (DoS) attacks. You must specify a target URL (`-u`) and a test mode (`-H`, `-B`, `-R`, or `-X`).

### 1\. Basic Command Structure

```bash
slowhttptest [options ...] -u <URL> -l <duration> -c <connections>
```

### 2\. Attack Modes (Test Type)

You must choose one of the following modes:

| Option | Mode | Description |
| :--- | :--- | :--- |
| **-H** | Slow Headers (Slowloris) | Sends unfinished **HTTP headers** to keep the connection open. |
| **-B** | Slow Body (R-U-Dead-Yet) | Sends unfinished **HTTP message bodies** (typically in a POST request). |
| **-R** | Range Attack (Apache Killer) | Sends many overlapping **Range Request headers**, forcing the server to consume significant CPU and memory. |
| **-X** | Slow Read | Sends a complete request but **reads the response slowly**, using TCP window size manipulation. |

-----

### 3\. Key Configuration Options

The core functionality is configured using the following parameters:

| Option | Parameter | Default | Description |
| :--- | :--- | :--- | :--- |
| **-u** | `URL` | `http://localhost/` | The **absolute URL** of the target server. |
| **-l** | `seconds` | `240` | The target **test duration** in seconds. |
| **-c** | `connections` | `50` | The target **number of connections** to open. |
| **-r** | `rate` | `50` | **Connection rate** per second (how fast new connections are opened). |
| **-i** | `seconds` | `10` | **Interval** between follow-up data chunks (for `-H` and `-B` modes). |
| **-x** | `bytes` | `32` | Max length of each randomized name/value pair of follow-up data (for `-H` and `-B` modes). |
| **-t** | `verb` | `GET` or `POST` | HTTP **verb** to use in the request (`GET`, `POST`, `HEAD`, etc.). |
| **-p** | `seconds` | `5` | **Timeout** to wait for an HTTP response on the probe connection. |
| **-g** | (flag) | `off` | **Generate statistics** (`.html` and `.csv` files) when the test finishes. |
| **-o** | `file_prefix` | (none) | Save statistics output with the specified file prefix (requires `-g`). |

### 4\. Example Commands

#### Slowloris Attack (Slow Headers)

This command starts a 240-second Slowloris attack using 500 connections against `https://target.com/`.

```bash
slowhttptest -H -c 500 -r 100 -l 240 -i 10 -x 24 -u https://target.com/ -g -o slowloris_test
```

  * `-H`: Slow Headers mode.
  * `-c 500`: Target 500 connections.
  * `-r 100`: Connection rate of 100 per second.
  * `-l 240`: Test duration of 240 seconds.
  * `-i 10`: Send follow-up data every 10 seconds.
  * `-g -o slowloris_test`: Generate `slowloris_test.html` and `slowloris_test.csv` reports.

#### Slow Read Attack

This command tests for a Slow Read vulnerability by establishing 8000 connections and reading very slowly.

```bash
slowhttptest -X -c 8000 -r 200 -l 300 -w 10 -y 20 -n 5 -z 32 -k 3 -u http://target.com/big_file.html
```

  * `-X`: Slow Read mode.
  * `-w 10 -y 20`: TCP advertised window size is a random value between 10 and 20 bytes.
  * `-n 5`: Interval between read operations is 5 seconds.
  * `-z 32`: Read 32 bytes from the receive buffer at a time.
  * `-k 3`: Requests the resource 3 times per socket (pipeline factor).


This command initiates a specialized Denial of Service (DoS) attack simulation known as a **Slow Read Attack** against the target URL. The goal is to tie up a large number of the web server's resources by deliberately consuming data very slowly, thereby preventing new, legitimate connections from being served.

Here is a breakdown of what happens when you run this command, based on the parameters used:

***

## ⚙️ Command Breakdown

| Parameter | Value | Description |
| :--- | :--- | :--- |
| **`-X`** | (flag) | **Mode**: Initiates the **Slow Read** attack mode. |
| **`-u`** | `http://target.com/big_file.html` | **Target**: The absolute URL of the resource to attack. It's targeting a file that is presumed to be large to keep the connection busy. |
| **`-c 8000`** | 8,000 | **Connections**: The tool attempts to establish **8,000 concurrent TCP connections** with the target server. |
| **`-r 200`** | 200/sec | **Rate**: Connections are initiated at a rate of **200 per second**. |
| **`-l 300`** | 300 seconds | **Duration**: The total test duration will run for **300 seconds** (5 minutes), unless all connections are closed earlier. |
| **`-w 10 -y 20`** | 10 to 20 bytes | **Window Size**: The TCP advertised window size for the connection will be a random value picked from the range of **10 to 20 bytes**. A small advertised window signals the server to send data slowly. |
| **`-n 5`** | 5 seconds | **Read Interval**: The tool will wait **5 seconds** between consecutive read operations on each socket. This deliberately slows down the consumption of the server's response data. |
| **`-z 32`** | 32 bytes | **Read Length**: Each individual `read()` operation will attempt to pull only **32 bytes** of data from the receive buffer, further drawing out the process. |
| **`-k 3`** | 3 times | **Pipeline Factor**: The client will send **three copies of the same request** back-to-back over a single persistent connection (`Connection: Keep-Alive` header is used). This maximizes the amount of data the server must generate and the potential length of the slow read attack on that connection. |

***

## 🔄 Sequence of Events

1.  **Initialization and Connection Storm**
    * The tool immediately begins opening connections to `http://target.com/` at a sustained rate of 200 connections per second.
    * This continues until 8,000 active connections are either established, fail, or the test duration is hit.

2.  **Request and Slow Download**
    * Once a connection is established, the client sends the HTTP `GET` request for `big_file.html` a total of three times (`-k 3`) to maximize the response payload.
    * Crucially, the client sets a **small TCP advertised window size** (between 10 and 20 bytes) to throttle the rate at which the server can send data.
    * The server attempts to stream the (presumably large) response, but is limited by the small window size.

3.  **Draining the Buffer**
    * The client repeatedly waits **5 seconds** (`-n 5`).
    * After each interval, it performs a read operation to consume only **32 bytes** (`-z 32`) of the buffered response data, freeing up only that amount of space in the TCP window.
    * The connection remains open and in a slow transmission state for the full 300 seconds of the test duration, keeping the server's worker processes or threads tied up.

4.  **Monitoring and Termination**
    * The tool uses an internal, independent "probe" connection (default behavior, since no `-e` option was provided) to periodically check if the target server is still responding quickly to normal requests.
    * The test runs for 300 seconds unless the user manually cancels it, an unexpected error occurs, or the target server successfully closes all 8,000 connections.
