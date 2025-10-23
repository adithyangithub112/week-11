### **Report on Slowloris Attack Using `slowhttptest`**

### **Command Breakdown and Execution**

1. **Extracting the Archive**:**bash**
    
    `$ tar -xzvf slowhttptest-x.x.tar.gz`
    
    This command extracts the contents of the `slowhttptest-x.x.tar.gz` archive, which contains the source code and necessary files for the `slowhttptest` tool.
    
2. **Navigating to the Directory**:**bash**
    
    `$ cd slowhttptest-x.x`
    
    This command changes the current directory to the extracted `slowhttptest-x.x` directory, where the source code is located.
    
3. **Configuring the Build**:**bash**
    
    `$ ./configure --prefix=PREFIX`
    
    This command runs the configuration script to prepare the build environment. The `--prefix=PREFIX` option specifies the installation directory prefix.
    
4. **Compiling the Source Code**:**bash**
    
    `$ make`
    
    This command compiles the source code into executable binaries.
    
5. **Installing the Compiled Binaries**:**bash**
    
    `$ sudo make install`
    
    This command installs the compiled binaries to the specified prefix directory, making `slowhttptest` available system-wide.
    
6. **Running the Slowloris Attack**:**bash**
    
    `$ slowhttptest -H -c 500 -r 100 -l 240 -i 10 -x 24 -u http://testphp.vulnweb.com -g -o slowloris_test`
    
    This command executes a Slowloris attack on the specified target URL (`http://testphp.vulnweb.com`). The options used are:
    
    - `H`: Enables HTTP/1.1 mode.
    - `c 500`: Sets the number of concurrent connections to 500.
    - `r 100`: Sets the number of requests per connection to 100.
    - `l 240`: Sets the socket timeout to 240 seconds.
    - `i 10`: Sets the interval between header sends to 10 seconds.
    - `x 24`: Sets the number of extra headers to send to 24.
    - `u http://testphp.vulnweb.com`: Specifies the target URL.
    - `g`: Enables the use of GET requests.
    - `o slowloris_test`: Specifies the output file for the test results.

### **Impact on the Website**

A Slowloris attack, as executed with the above command, can have significant impacts on the targeted website:

1. **Resource Exhaustion**: The attack opens a large number of connections to the web server and keeps them alive by slowly sending HTTP headers. This exhausts the server's resources, including memory and CPU, as it tries to handle all the open connections 1,2.
2. **Denial of Service**: As the server's connection pool fills up with these slow, incomplete requests, it becomes unable to accept new legitimate connections. This results in a denial of service for genuine users, who may experience slowdowns, timeouts, or complete unavailability of the website 1,3.
3. **Persistence**: Slowloris attacks can be maintained for extended periods, as long as the attacker continues to send periodic header updates. This persistence can lead to prolonged downtime or degraded performance of the targeted website 3.
4. **Difficulty in Detection**: These attacks are challenging to detect because they mimic normal traffic patterns but at a much slower pace. This makes it hard for traditional security measures to identify and mitigate the attack effectively 2.
5. **Impact on Users**: Users of the targeted website may experience increased latency, frequent timeouts, and an overall degraded user experience. In severe cases, they may be completely unable to access the website, leading to potential loss of business or user trust 1.
